"""Meaningful evidence parsing and fixed isolation boundary checks, no Docker."""
from pathlib import Path
import importlib.util
import json

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


def test_wrong_platform_and_wrong_config_are_rejected():
    lock = json.loads((a03.LOCK_DIR / "engine-lock.json").read_text())
    selected = a03.image_selection(lock, "linux/amd64")
    observed = {"Architecture": "arm64", "Os": "linux", "Id": selected["config_digest"], "RepoDigests": [selected["immutable_reference"]]}
    with pytest.raises(ValueError, match="architecture"):
        a03.assert_image_identity(observed, selected)
    observed["Architecture"] = "amd64"; observed["Id"] = "sha256:"+"0"*64
    with pytest.raises(ValueError, match="config digest"):
        a03.assert_image_identity(observed, selected)


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
