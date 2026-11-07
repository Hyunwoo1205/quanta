"""Meaningful evidence parsing and fixed isolation boundary checks, no Docker."""
from pathlib import Path
import copy
import importlib.util
import json
import io
import subprocess
import sys
import tarfile
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

MODULE = Path(__file__).resolve().parents[1] / "scripts/verify_atomistic_a03.py"
spec = importlib.util.spec_from_file_location("verify_atomistic_a03", MODULE)
a03 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a03)


def cube(tmp_path, samples="1 2 -0.5 1.5", dims="2 0.5 0 0\n2 0 0.5 0\n1 0 0 0.5"):
    path = tmp_path / "density.cube"
    path.write_text("density\nno clipping\n1 0 0 0\n"+dims+"\n2 2 0 0 0\n"+samples+"\n")
    return path


def test_density_signed_samples_and_volume_are_not_normalized(tmp_path):
    result = a03.parse_cube(cube(tmp_path))
    assert result["electron_integral"] == pytest.approx(0.5)
    assert result["negative_integral"] == pytest.approx(-0.0625)
    assert result["negative_samples"] == 1
    assert result["electron_count_error_from_2"] == pytest.approx(-1.5)
    assert result["clipped_smoothed_or_renormalized"] is False
    assert result["convergence_status"] == "not_tested"


@pytest.mark.parametrize("samples", ["1 2 3", "1 2 3 4 5", "1 2 3 nan"])
def test_density_rejects_incomplete_excess_or_nonfinite_data(tmp_path, samples):
    with pytest.raises(ValueError):
        a03.parse_cube(cube(tmp_path, samples))


def test_source_report_does_not_claim_build_attestation():
    r = a03.parse_version("CP2K version 2026.2\nCP2K| source code revision git:67b5da8\n", "67b5da876dd6a76b8b021d5a04d1c81ba79a4c50")
    assert r["reported_revision"] == "67b5da8"
    assert r["release_source_prefix_matches"] is True
    assert r["source_identity_attested"] is False


def test_actual_cp2k_output_energy_without_colon_and_unknown_revision():
    text = " CP2K| version string: CP2K version 2026.2\n CP2K| source code revision number: unknown\n ENERGY| Total FORCE_EVAL ( QS ) energy [hartree]             -2.884463653290686\n *** SCF run converged in 9 steps ***\n PROGRAM ENDED AT timestamp\n"
    observed = a03.parse_output(text)
    assert observed["energy_hartree"] == -2.884463653290686
    assert observed["source_claims_from_output"]["reported_revision"] == "unknown"
    assert observed["source_claims_from_output"]["release_source_prefix_matches"] is False
    assert observed["scf_converged"] and observed["program_ended"]


def test_cp2k_fixed13_fields_accept_adjacent_negative_exponent_values(tmp_path):
    # Literal records taken from actual CP2K2026.2 full-density output.
    field = " 0.21598E-008-0.21598E-008 0.21598E-008-0.21598E-008"
    observed = a03.parse_cube(cube(tmp_path, field))
    assert observed["samples"] == 4 and observed["negative_samples"] == 2
    assert observed["electron_integral"] == pytest.approx(0.0, abs=1e-25)
    assert observed["minimum_electrons_per_bohr3"] == -2.1598e-9
    assert observed["field_significant_digits"] == 5


def image_fixture(platform, manifest_id=False):
    lock = json.loads((a03.LOCK_DIR / "engine-lock.json").read_text())
    selected = a03.image_selection(lock, platform)
    config, manifest_size = a03.read_locked_image(selected)
    observed = {
        "Architecture": config["architecture"],
        "Os": config["os"],
        "Id": selected["config_digest"],
        "RepoDigests": [selected["immutable_reference"].removeprefix("docker.io/")],
        "Size": 4_555_398_423,
        "RootFS": {"Type": config["rootfs"]["type"], "Layers": config["rootfs"]["diff_ids"][:]},
        "Config": copy.deepcopy(config["config"]),
    }
    if manifest_id:
        observed["Id"] = selected["digest"]
        observed["Descriptor"] = {
            "digest": selected["digest"], "mediaType": a03.OCI_IMAGE_MANIFEST, "size": manifest_size,
        }
    return observed, selected, config, manifest_size


@pytest.mark.parametrize("platform", ["linux/arm64", "linux/amd64"])
@pytest.mark.parametrize("manifest_id,method", [
    (False, "daemon_config_id"),
    (True, "daemon_platform_manifest_descriptor_to_locked_config"),
])
def test_both_daemon_identity_paths_use_exact_a02_locks(platform, manifest_id, method):
    observed, selected, config, manifest_size = image_fixture(platform, manifest_id)
    evidence = a03.assert_image_identity(observed, selected, config, manifest_size)
    assert evidence["proof_method"] == method
    assert evidence["daemon_image_id"] == observed["Id"]
    assert evidence["locked_config_digest"] == selected["config_digest"]
    assert evidence["locked_raw_manifest_and_config_verified"] is True
    assert evidence["local_raw_config_bytes_read"] is False
    assert evidence["ordered_rootfs_diff_ids_match"] is True
    assert a03.image_observation(observed, selected)["Size"] == 4_555_398_423


def test_wrong_platform_and_wrong_config_are_rejected():
    observed, selected, config, manifest_size = image_fixture("linux/amd64")
    observed["Architecture"] = "arm64"
    with pytest.raises(ValueError, match="architecture"):
        a03.assert_image_identity(observed, selected, config, manifest_size)
    observed["Architecture"] = "amd64"; observed["Id"] = "sha256:"+"0"*64
    with pytest.raises(ValueError, match="config digest"):
        a03.assert_image_identity(observed, selected, config, manifest_size)


@pytest.mark.parametrize("field,value", [
    ("digest", "sha256:" + "0"*64),
    ("mediaType", "application/vnd.oci.image.index.v1+json"),
    ("size", 4_555_398_423),
])
def test_manifest_identity_requires_exact_descriptor(field, value):
    observed, selected, config, manifest_size = image_fixture("linux/arm64", True)
    observed["Descriptor"][field] = value
    with pytest.raises(ValueError, match="manifest descriptor"):
        a03.assert_image_identity(observed, selected, config, manifest_size)


def test_manifest_id_without_descriptor_and_descriptor_with_wrong_id_are_rejected():
    observed, selected, config, manifest_size = image_fixture("linux/arm64", True)
    descriptor = observed.pop("Descriptor")
    with pytest.raises(ValueError, match="config digest"):
        a03.assert_image_identity(observed, selected, config, manifest_size)
    observed["Descriptor"] = descriptor
    observed["Id"] = selected["config_digest"]
    with pytest.raises(ValueError, match="manifest descriptor"):
        a03.assert_image_identity(observed, selected, config, manifest_size)


@pytest.mark.parametrize("manifest_id", [False, True])
def test_both_identity_paths_require_repo_layers_and_runtime_config(manifest_id):
    observed, selected, config, manifest_size = image_fixture("linux/arm64", manifest_id)
    invalid = copy.deepcopy(observed)
    invalid["RepoDigests"] = ["another/repo@" + selected["digest"]]
    with pytest.raises(ValueError, match="repository digest"):
        a03.assert_image_identity(invalid, selected, config, manifest_size)
    invalid = copy.deepcopy(observed)
    invalid["RootFS"]["Layers"].reverse()
    with pytest.raises(ValueError, match="layer DiffIDs"):
        a03.assert_image_identity(invalid, selected, config, manifest_size)
    for replacement in (None, [], ["unlocked environment"]):
        invalid = copy.deepcopy(observed)
        invalid["Config"]["Env"] = replacement
        with pytest.raises(ValueError, match="runtime config differs at Env"):
            a03.assert_image_identity(invalid, selected, config, manifest_size)
    invalid = copy.deepcopy(observed)
    invalid["Config"].pop("Env")
    with pytest.raises(ValueError, match="runtime config differs at Env"):
        a03.assert_image_identity(invalid, selected, config, manifest_size)


@pytest.mark.parametrize("file_key", ["manifest_file", "config_file"])
def test_image_metadata_hashes_raw_bytes(file_key, monkeypatch):
    _, selected, _, _ = image_fixture("linux/arm64")
    original = Path.read_bytes

    def read_bytes(path):
        data = original(path)
        return data + b" " if path == a03.LOCK_DIR / selected[file_key] else data

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    with pytest.raises(ValueError, match="locked image file digest or size"):
        a03.read_locked_image(selected)


def test_main_reports_only_public_inspect_metadata_before_failed_gate(tmp_path, monkeypatch):
    import check_atomistic_a02

    observed, selected, _, manifest_size = image_fixture("linux/arm64", True)
    observed["Descriptor"]["size"] = manifest_size + 1
    observed["Descriptor"]["annotations"] = {"private": "hidden-fixture-value"}
    observed["RepoDigests"].append("private.invalid/internal@" + selected["digest"])
    observed["Config"]["Env"] = ["PRIVATE=hidden-fixture-value"]
    observed["GraphDriver"] = {"Data": {"UpperDir": "/private/hidden-fixture-value"}}
    output = tmp_path / "output"
    monkeypatch.setattr(sys, "argv", ["verify_atomistic_a03.py", "--output-dir", str(output)])
    monkeypatch.setattr(a03.os, "getuid", lambda: 1000)
    monkeypatch.setattr(a03.platform, "system", lambda: "Linux")
    monkeypatch.setattr(a03, "native_platform", lambda: "linux/arm64")
    monkeypatch.setattr(a03.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(a03.shutil, "disk_usage", lambda _: SimpleNamespace(free=10*1024**3))
    monkeypatch.setattr(check_atomistic_a02, "verify", lambda: {"passed": True})

    def fake_run(args, **_):
        if args[:2] == ["docker", "pull"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        assert args == ["docker", "image", "inspect", selected["immutable_reference"]]
        return subprocess.CompletedProcess(args, 0, json.dumps([observed]), "")

    monkeypatch.setattr(a03, "run", fake_run)
    assert a03.main() == 2
    raw = (output / "report.json").read_text()
    report = json.loads(raw)
    assert report["cases"] == []
    assert "manifest descriptor" in report["error"]
    assert "image_identity" not in report
    assert report["image_observed"]["Id"] == selected["digest"]
    assert report["image_observed"]["Descriptor"]["size"] == manifest_size + 1
    assert report["image_observed"]["RootFS"] == observed["RootFS"]
    assert "Config" not in report["image_observed"]
    assert "hidden-fixture-value" not in raw
    assert "private.invalid" not in raw


@pytest.mark.parametrize("origin", ["https://127.0.0.1:8765", "http://example.com:8765", "http://127.0.0.1:8765/secrets", "http://key@127.0.0.1:8765", "http://127.0.0.1", "http://127.0.0.1:8765/?token=x"])
def test_web_observer_cannot_target_external_or_authenticated_endpoints(origin):
    with pytest.raises(ValueError):
        a03.validate_web_origin(origin)


def test_container_controls_and_fixed_paths_are_present(tmp_path):
    p = a03.DockerProbe("repo@sha256:"+"a"*64, tmp_path, 180)
    args = p.create_args("controlled-test", tmp_path)
    assert args[args.index("--network")+1] == "none"
    assert args[args.index("--memory")+1] == "2g"
    assert args[args.index("--memory-swap")+1] == "2g"
    assert "--read-only" in args and "ALL" in args
    assert "org.quanta.atomistic-a03="+str(tmp_path) in args
    assert any("/work:rw,nosuid,nodev,noexec,size=268435456" in s for s in args)
    assert all("/srv/quanta/data" not in s and "app.env" not in s for s in args)


def test_force_artifact_extraction_keeps_actual_values(tmp_path):
    p = tmp_path / "forces.xyz"
    p.write_text("2\n Forces (a.u.)\n H 0 0 0.0002\n H 0 0 -0.0002\n")
    assert a03.parse_force_artifact(p) == [[0, 0, 0.0002], [0, 0, -0.0002]]


def test_density_geometry_cannot_silently_relabel_atom_or_position(tmp_path):
    observed = a03.parse_cube(cube(tmp_path))
    metadata = {"atoms": [{"element": "He", "engine_position_angstrom": [0, 0, 0]}]}
    assert a03.check_density_geometry(observed, metadata)["atoms_and_composition_match"]
    metadata["atoms"][0]["element"] = "H"
    with pytest.raises(ValueError, match="composition"):
        a03.check_density_geometry(observed, metadata)
    metadata["atoms"][0] = {"element": "He", "engine_position_angstrom": [1, 0, 0]}
    with pytest.raises(ValueError, match="rounding budget"):
        a03.check_density_geometry(observed, metadata)


def test_production_boundary_headers_are_fixed_to_oci_loopback():
    sampler = a03.WebSampler("http://127.0.0.1:8765", True)
    assert sampler.headers == {"Host": "quanta.kro.kr", "Origin": "https://quanta.kro.kr"}
    with pytest.raises(ValueError, match="fixed OCI loopback"):
        a03.WebSampler("http://127.0.0.1:9999", True)


def test_web_and_case_timings_share_ordered_phase_evidence(tmp_path, monkeypatch):
    ticks = iter(range(100))
    cpu_ticks = iter((1.0, 1.125, 2.0, 2.25))
    monkeypatch.setattr(a03, "time", SimpleNamespace(monotonic=ticks.__next__, thread_time=cpu_ticks.__next__))
    sampler = a03.WebSampler("http://127.0.0.1:8765", True)
    sampler.phase = "during"
    requests, reads = [], []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, size):
            reads.append(size)
            sampler.phase = "after"
            return b"x"

    def fake_urlopen(request, *, timeout):
        requests.append((request.full_url, timeout))
        if request.full_url.endswith("/v1/capabilities"):
            raise HTTPError(request.full_url, 401, "fixture", {}, None)
        return Response()

    monkeypatch.setattr(a03, "urlopen", fake_urlopen)
    probe = a03.DockerProbe("fixed-image", tmp_path, 180)
    monkeypatch.setattr(probe, "sample", lambda *_: [])
    monkeypatch.setattr(probe, "inspect", lambda _: {
        "State": {"Running": True}, "HostConfig": {}, "Config": {"User": "1000:1000"},
    })

    def fake_run(args, **_):
        if args[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(args, 1, "", "")
        return subprocess.CompletedProcess(args, 0, "0\n", "")

    def fake_copy_work(_, destination):
        sampler.sample()
        destination.mkdir()
        (destination / "cp2k.out").write_text(
            "GAPW PBE cc-pVDZ.cp2k ALL_POTENTIALS\n"
            " ENERGY| Total FORCE_EVAL ( QS ) energy [hartree] -2.8\n"
            " *** SCF run converged in 9 steps ***\n PROGRAM ENDED AT timestamp\n"
        )
        (destination / "forces.xyz").write_text("1\n Forces (a.u.)\n He 0 0 0\n")
        (destination / "he-TOTAL_ELECTRON_DENSITY.cube").write_bytes(cube(tmp_path).read_bytes())
        (destination / "engine-resource.json").write_text('{"engine_children_peak_rss_kib": 1}')
        return {"transport": "fixture"}

    monkeypatch.setattr(a03, "run", fake_run)
    monkeypatch.setattr(probe, "copy_work", fake_copy_work)
    record = probe.execute("he", "fixture", {
        "atoms": [{"element": "He", "engine_position_angstrom": [0, 0, 0]}], "basis": "cc-pVDZ",
    })
    assert record["passed_execution_gate"]
    assert record["container_removed"]
    ok, unauthorized = sampler.samples
    assert requests == [("http://127.0.0.1:8765/", 2), ("http://127.0.0.1:8765/v1/capabilities", 2)]
    assert reads == [1]
    assert (ok["status"], unauthorized["status"]) == (200, 401)
    assert ok["timing"]["phase_at_start"] == "during"
    assert ok["phase"] == "after"
    assert unauthorized["timing"]["phase_at_start"] == "after"
    assert unauthorized["timing"]["first_body_byte_monotonic"] is None
    assert ok["timing"]["thread_cpu_seconds"] == 0.125
    assert unauthorized["timing"]["thread_cpu_seconds"] == 0.25
    case = record["timing"]
    first, second = ok["timing"], unauthorized["timing"]
    ordered = [
        case["case_started_monotonic"], case["engine_start_requested_monotonic"],
        case["engine_completion_observed_monotonic"], case["archive_transfer_started_monotonic"],
        first["started_monotonic"], first["headers_monotonic"], first["first_body_byte_monotonic"],
        first["finished_monotonic"], second["started_monotonic"], second["headers_monotonic"],
        second["finished_monotonic"], case["archive_transfer_finished_monotonic"],
        case["artifact_hashing_started_monotonic"], case["artifact_hashing_finished_monotonic"],
        case["cube_parsing_started_monotonic"], case["cube_parsing_finished_monotonic"],
        case["cleanup_started_monotonic"], case["cleanup_finished_monotonic"],
    ]
    assert all(before < after for before, after in zip(ordered, ordered[1:]))


def make_archive(path, name="cp2k.out", content=b"CP2K actual tmpfs output\n", kind=tarfile.REGTYPE, pax=None, declared_size=None):
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT if pax else tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo(name)
        info.type = kind
        info.size = len(content) if declared_size is None else declared_size
        if pax:
            info.pax_headers = pax
        tf.addfile(info, io.BytesIO(content) if kind == tarfile.REGTYPE and declared_size is None else None)
    return path


def test_live_tmpfs_artifacts_use_exec_stream_not_docker_cp(tmp_path, monkeypatch):
    source = make_archive(tmp_path / "source.tar")
    observed = []
    real_popen = subprocess.Popen
    def fake_docker(args, **kwargs):
        observed.append(args)
        return real_popen([sys.executable, "-c", "import sys;sys.stdout.buffer.write(open(sys.argv[1],'rb').read())", str(source)], **kwargs)
    monkeypatch.setattr(a03.subprocess, "Popen", fake_docker)
    probe = a03.DockerProbe("fixed-image", tmp_path, 180)
    receipt = probe.copy_work("fixed-container", tmp_path / "raw")
    assert observed == [["docker", "exec", "fixed-container", "tar", "-C", "/work", "-cf", "-", "."]]
    assert (tmp_path / "raw/cp2k.out").read_bytes() == b"CP2K actual tmpfs output\n"
    assert receipt["regular_file_bytes"] == len(b"CP2K actual tmpfs output\n")
    assert not (tmp_path / "engine-artifacts.tar").exists()


@pytest.mark.parametrize("name,kind,pax,size", [
    ("../escape", tarfile.REGTYPE, None, None),
    ("/absolute", tarfile.REGTYPE, None, None),
    ("link", tarfile.SYMTYPE, None, None),
    ("hardlink", tarfile.LNKTYPE, None, None),
    ("device", tarfile.CHRTYPE, None, None),
    ("regular", tarfile.REGTYPE, {"comment": "metadata"}, None),
    ("too-large", tarfile.REGTYPE, None, a03.LIMITS["work_tmpfs_bytes"]+1),
])
def test_engine_tar_extraction_rejects_unsafe_or_oversized_entries(tmp_path, name, kind, pax, size):
    archive = make_archive(tmp_path / "bad.tar", name=name, kind=kind, pax=pax, declared_size=size)
    with pytest.raises(ValueError):
        a03.extract_work_archive(archive, tmp_path / "raw")
    assert not (tmp_path / "escape").exists()


def test_partial_log_read_uses_bounded_live_exec(tmp_path, monkeypatch):
    calls = []
    def fake(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "CP2K| active engine\n", "")
    monkeypatch.setattr(a03, "run", fake)
    probe = a03.DockerProbe("fixed-image", tmp_path, 180)
    assert probe.read_output("fixed-container", tmp_path / "partial.out") == "CP2K| active engine\n"
    assert calls == [["docker", "exec", "fixed-container", "head", "-c", str(512*1024+1), "/work/cp2k.out"]]
