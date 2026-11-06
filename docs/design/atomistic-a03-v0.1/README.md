# A03 isolated engine probes

This is an internal installation, feature, resource and cancellation benchmark.
It does not register an atomistic module, enable public calculations or replace
the user-authored JSON experiment contract with an internal fixture catalogue.

The [predeclared policy](probe-policy.json) fixes the initial isolation and resource
limits before execution. A01/A02 reference criteria and locked bytes remain unchanged.
The CP2K numerical candidates in `scripts/atomistic_a03_inputs.py` are exploratory;
A04 must review and freeze the actual binary, settings and SI conversion policy.

`scripts/verify_atomistic_a03.py` runs only the architecture-specific image digest
already selected in A02. `scripts/run_atomistic_a03_ci.py` places a separate temporary
Quanta API alongside the native CI probe. Its web measurements do not establish
OCI production responsiveness. OCI measurements require the separately verified
fixed controller, successful native CI and a fresh UUID request on `ops/oci`.

Raw engine output and density grids belong to the corresponding execution artifact
and personal Drive result archive. Small measurements and provenance belong in
GitHub. A successful installation or finite electron-density integral does not
establish scientific convergence or physical validation.

## Status before first execution

- Native x86/ARM execution: pending.
- OCI production headroom and responsiveness: pending.
- Binary/source identity and actual dependencies: pending.
- Public atomistic enablement: no-go until contracts, quotas and scientific gates.
- Physical validation: `unvalidated`.

Resource-control reference: https://docs.docker.com/engine/containers/resource_constraints/
Versioned density semantics: https://manual.cp2k.org/cp2k-2026_2-branch/CP2K_INPUT/FORCE_EVAL/DFT/PRINT/E_DENSITY_CUBE.html
