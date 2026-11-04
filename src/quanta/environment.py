"""Observe the selected development baseline without asserting scientific accuracy."""
from __future__ import annotations

import importlib.metadata
import os
import platform
import sys

from .profiles import profile_for_host

THREAD_VARIABLES = ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS")
BASELINE = {"python": "3.12.14", "numpy": "2.3.5", "scipy": "1.17.0"}


def environment_report() -> dict:
    """Apply documented one-thread defaults, then inspect the actual loaded pools."""
    for name in THREAD_VARIABLES:
        os.environ.setdefault(name, "1")
    errors: list[dict] = []
    warnings: list[dict] = []
    versions = {"python": platform.python_version()}
    for name in ("numpy", "scipy", "jsonschema", "referencing", "rfc8785", "threadpoolctl"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
            errors.append({"code": "ENV_DEPENDENCY", "path": "/versions/" + name,
                           "message": f"Required distribution is not installed: {name}"})
    for name, expected in BASELINE.items():
        if versions.get(name) != expected:
            errors.append({"code": "ENV_VERSION", "path": "/versions/" + name,
                           "message": f"Expected {expected}, observed {versions.get(name)}"})
    if platform.python_implementation() != "CPython":
        errors.append({"code": "ENV_IMPLEMENTATION", "path": "/implementation",
                       "message": "The selected baseline requires CPython."})
    runtime_profile = None
    try:
        runtime_profile = profile_for_host()["profile_id"]
    except ValueError as exc:
        errors.append({"code": "ENV_PLATFORM", "path": "/platform",
                       "message": str(exc)})
    thread_env = {name: os.environ[name] for name in THREAD_VARIABLES}
    for name, value in thread_env.items():
        if value != "1":
            errors.append({"code": "ENV_THREADS", "path": "/thread_environment/" + name,
                           "message": f"The one-thread baseline requires 1; observed {value}."})
    pools: list[dict] = []
    config: dict = {}
    try:
        import numpy as np
        import scipy.linalg.blas  # Load both numerical library backends for inspection.
        from threadpoolctl import threadpool_info
        config = np.show_config(mode="dicts")
        pools = threadpool_info()
        for index, pool in enumerate(pools):
            if pool.get("num_threads") != 1:
                errors.append({"code": "ENV_THREADPOOL", "path": f"/threadpools/{index}",
                               "message": "Actual numerical thread count differs from the baseline."})
        if not pools:
            errors.append({"code": "ENV_THREADPOOL", "path": "/threadpools",
                           "message": "No numerical thread pool was observed; the baseline cannot be confirmed."})
    except ImportError as exc:
        errors.append({"code": "ENV_IMPORT", "path": "/threadpools", "message": str(exc)})
    return {"valid": not errors, "baseline": BASELINE, "runtime_profile": runtime_profile, "versions": versions,
            "implementation": platform.python_implementation(),
            "platform": {"os": platform.system(), "architecture": platform.machine()},
            "python_executable": sys.executable, "thread_environment": thread_env,
            "threadpools": pools, "numpy_build_configuration": config,
            "errors": errors, "warnings": warnings,
            "physical_validation_status": "unvalidated", "simulation_executed": False}
