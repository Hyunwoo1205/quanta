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

## Measured native execution; OCI pending

- Native x86/ARM execution: passed at source b621e836af61d7b63933ab7802722fa1ee79f531, run42262528023; see `../../atomistic_a03_native_verification.json`.
- OCI production headroom and responsiveness: pending.
- Actual binary hashes and installed dependency inventories: recorded in execution artifacts. Binary/source identity: unresolved (`revision unknown`); see [binding review](binary-source-binding-review.json).
- Public atomistic enablement: no-go until contracts, quotas and scientific gates.
- Physical validation: `unvalidated`.

Resource-control reference: https://docs.docker.com/engine/containers/resource_constraints/
Versioned density semantics: https://manual.cp2k.org/cp2k-2026_2-branch/CP2K_INPUT/FORCE_EVAL/DFT/PRINT/E_DENSITY_CUBE.html

Actual CUBE data are fixed13-column E13.5E3 fields with five significant digits. This corrects the A02 six-digit description without rewriting historical locks. Actual negative lobes and rounded-axis integral errors remain in the data; no clipping or renormalization is permitted.
