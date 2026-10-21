# Offline distrust fixtures

`impacted.pem`, `roots.pem`, and both `dv-g3b*.pem` chains come from
[galadran/we-have-a-problem.com at 8c27813](https://github.com/galadran/we-have-a-problem.com/tree/8c27813eb898bd6f836da49a01f5e78b9cb6337a).
The first two concatenate the `pem` fields in `impacted-intermediates.json`
and `roots.json`. All 16 intermediate variants map to eight SHA256 SPKI hashes;
OpenSSL and X509 independently verify the fingerprints.

`enterprise-{root,leaf}.pem` are synthetic certificates with a localhost SAN.
No private keys are included. Tests use 2026-10-22T12:00:00Z, within both their
validity and the incident chains' validity, and assert baseline acceptance
before testing distrust. Tests need no network or machine trust store on Unix.
The public API custom-file test is Unix-only: Windows reads its ROOT store.
