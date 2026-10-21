# Changelog

## 2026-10-20: fixes found by a source read

These were found by reading the source against its own documentation after release, not by the earlier test and review passes. Each fix has a regression test in
`tests/test_findings_20261020.py` that failed before the fix, and each fix was checked by undoing it and confirming a test fails. Behaviour that changed is listed under "Changed".

### Fixed
- **`Ledger.mint` could record one commitment twice** when two threads minted it through one `Ledger` (the "already minted?" check was outside any lock). The check and the record are now one step.
- **On POSIX, finding and killing a process group failed once the group leader had been reaped**, so a descendant that outlived a job could go undetected and unkilled. `ProcessJob` now records the group id at start and uses it. This path was tested with stand-ins for the operating-system calls, not on a POSIX machine.
- `dag.py`: a docstring named SNARK/STARK proofs; it now says "a tier-1/2/3 proof".
