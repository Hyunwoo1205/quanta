Quanta contract bundle 0.3.0: standalone dynamics validation foundation.

Explicit selection: ContractRegistry(contract_version="0.3.0"). The default registry remains 0.2.0.

This is a versioned standalone solver request/payload/phase-state contract, not a generic experiment revision or executable dynamics module. Draft request markers are replaced with contract_version=0.3.0. Newton/pair/velocity-Verlet design is declared, but time propagation and D01-D11 numerical acceptance are not implemented/executed. Validation may check the initial domain/forces only.

All listed files are hash checked and schemas resolve only from this offline bundle. Never rewrite old 0.2 files or old input/implementation hashes. Generic experiment, workflow dispatch, actual solver, state publication, and UI remain later implementation gates.
