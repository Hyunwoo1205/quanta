"""Run the unchanged A03 He-D fixture against a locally built ARM64 candidate."""

import argparse
import hashlib
import json
import os
import platform
import re
from pathlib import Path

from atomistic_a03_inputs import generate_input, probe_metadata
from check_atomistic_a02 import verify
from verify_atomistic_a03 import DockerProbe, LIMITS, run


CP2K_REVISION = "67b5da876dd6a76b8b021d5a04d1c81ba79a4c50"
HE_INPUT_SHA256 = "6c91137086d77321edc954e4f316a2a837078b088260f7b3ae00c73691df8bc8"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--case-timeout", type=int, default=180)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "aarch64" or os.getuid() == 0:
        parser.error("A native ARM64 Linux host and nonroot Docker controller are required")
    if not 30 <= args.case_timeout <= 180:
        parser.error("case timeout must be 30..180 seconds")
    if args.image.startswith("-"):
        parser.error("a local image reference is required")

    out = args.output_dir.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {
        "schema_version": 1,
        "probe": "quanta.atomistic-armv8-candidate-he-d",
        "host_machine": platform.machine(),
        "limits": dict(LIMITS, case_timeout_seconds=args.case_timeout),
        "physical_validation_status": "unvalidated",
        "production_deployment_changed": False,
        "passed_execution_gate": False,
    }
    probe = None
    try:
        report["a02_lock_check"] = verify()
        images = json.loads(run(["docker", "image", "inspect", args.image]).stdout)
        if len(images) != 1:
            raise ValueError("The local image reference did not identify exactly one image")
        image = images[0]
        image_id = image.get("Id")
        if (
            not isinstance(image_id, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            or image.get("Architecture") != "arm64"
            or image.get("Os") != "linux"
        ):
            raise ValueError("Candidate must be a local Linux ARM64 Docker image")
        report["image_id"] = image_id
        report["image_repo_digests"] = image.get("RepoDigests") or []
        probe = DockerProbe(image_id, out, args.case_timeout)
        report["binary"] = probe.inventory()
        if report["binary"].get("reported_revision") != CP2K_REVISION:
            raise ValueError("Candidate did not report the full pinned CP2K source commit")
        if report["binary"].get("reported_version") != "2026.2":
            raise ValueError("Candidate did not report CP2K version 2026.2")
        fields = dict(system="he", basis="cc-pVDZ", project="he_dz", data_dir="/quanta-data")
        input_text = generate_input(**fields)
        if hashlib.sha256(input_text.encode()).hexdigest() != HE_INPUT_SHA256:
            raise ValueError("He-D input does not match the recorded failed OCI run")
        report["case"] = probe.execute("he-dz", input_text, probe_metadata(**fields))
        report["passed_execution_gate"] = report["case"]["passed_execution_gate"]
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if probe:
            for name in list(probe.names):
                probe.remove(name)
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed_execution_gate": report["passed_execution_gate"], "report": str(out / "report.json")}))
    return 0 if report["passed_execution_gate"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
