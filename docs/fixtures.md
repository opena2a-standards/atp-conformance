# Fixture reference

The fixture-level detail behind the [README](../README.md): what each fixture
covers, what the suite does not verify, the values every fixture uses, the
versions the fixtures pin, and the rules for changing the fixture set.

## What this suite verifies

| Item | Covered by |
|---|---|
| ATP §7.1 well-known discovery response shape | `fixtures/discovery-valid.json` |
| ATP §4.2 trust proof shape | `fixtures/trust-proof-baseline.json`, `fixtures/trust-proof-hybrid.json` |
| ATP §4.3 canonical pipe-delimited 7-field signing form | both trust-proof fixtures |
| ATP §4.3 Ed25519 signing (baseline) | both trust-proof fixtures |
| ATP §4.3 hybrid Ed25519 + ML-DSA-65 signing (FIPS 204) | `fixtures/trust-proof-hybrid.json` (Go verifier validates both algorithms; Python validates Ed25519 only) |
| ATP §4.4 verification steps 1-5 (expiry, issuer, key, signature, semantic) | both trust-proof fixtures, all verifiers |
| ATP §4.4 step 1 must-reject: expired proof (valid signature, past expiresAt) | `fixtures/trust-proof-expired.json` |
| ATP §4.4 step 2 must-reject: untrusted issuer (valid signature, issuer not in trusted set) | `fixtures/trust-proof-untrusted-issuer.json` |
| ATP §4.4 step 4 must-reject: tampered Ed25519 signature (first byte XOR 0xFF) | `fixtures/trust-proof-tampered-signature.json` |
| ATP §4.4 step 5 must-reject: declared validity window above the §10.2 24-hour maximum (valid signature, trusted issuer, clock inside the window; `expiresAt` 25 hours after `issuedAt`) | `fixtures/trust-proof-window-exceeds-max.json` |
| ATP §5.6 Signed Tree Head | `fixtures/transparency-log-sth.json` |
| ATP §5.4 inclusion proof (RFC 6962 §2.1.1 audit path over the deterministic 8-leaf tree; RFC 9162 §2.1.3.2 verification) | `fixtures/transparency-inclusion-proof-valid.json` |
| ATP §5.4 must-reject: tampered audit path (first byte of `auditPath[0]` XOR 0xFF; STH still verifies, only the root recomputation catches it) | `fixtures/transparency-inclusion-proof-tampered-path.json` |
| ATP §5.5 consistency proof (4-leaf to 8-leaf growth; RFC 9162 §2.1.4.2 verification against both signed tree heads) | `fixtures/transparency-consistency-proof-valid.json` |
| ATP §5.5 must-reject: tampered consistency path (append-only claim broken) | `fixtures/transparency-consistency-proof-tampered-path.json` |
| ATP §8.1 revocation response (the spec example bytes; structural rules — the body is unsigned by design) | `fixtures/revocation-list-valid.json` |
| ATP §8.1 must-reject: malformed `revokedAt` timestamp (skipping an unparseable revocation keeps a revoked agent trusted) | `fixtures/revocation-list-malformed-timestamp.json` |

## What this suite does NOT verify (v0.3)

- Federation cosignature (ATP §6, Level 3). Production has no second
  authority to source a real cosigned proof from. Will be added once a real
  federation peer exists.
- §8.1 response authenticity. The spec does not sign the revocation body
  (the transport carries authenticity, plus `transparencyLogIndex` on an
  entry that carries one; an entry without it rests on the transport
  alone); the fixtures cover the structural rules only.
- §8.1 entries without a `transparencyLogIndex`. ATP §8.1 makes the member
  OPTIONAL: a client MUST apply such an entry exactly as one with the index
  and MUST NOT reject the entry or the response for its absence. No fixture
  carries such an entry yet, and the revocation schema vendored here
  predates the change and still lists the member as required.

## Fixtures

All fixtures use:

- Trusted authority DID: `did:opena2a:authority:opena2a.org`
- Test agent DID: `did:opena2a:mcp_server:agent_conformance_test_001`
- Pinned verifier clock: `2026-05-24T00:00:00Z`
- Trust-proof validity window: `2026-05-23T12:00:00Z` to `2026-05-24T06:00:00Z` (18 hours, inside the ATP §10.2 24-hour maximum; the expired fixture pins its own 12-hour window in the past; the window-exceeds-max fixture declares a 25-hour window on purpose, as the step-5 must-reject vector)
- Ed25519 keypair source: [RFC 8032 §7.1 Test 1](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1)
- ML-DSA-65 keypair source: fixed test seed (incrementing bytes `00..1f`), public key pinned in [`vectors/mldsa65-seed.json`](../vectors/mldsa65-seed.json)

| Fixture | Type | Expected | Exercises |
|---|---|---|---|
| `fixtures/discovery-valid.json` | discovery | ACCEPT | Well-formed `/.well-known/atp` response: required fields, `conformanceLevel` in `[1,3]`, structurally valid `publicKeys` (both Ed25519 and ML-DSA-65 entries). |
| `fixtures/trust-proof-baseline.json` | trustProof | ACCEPT | Trust proof with one Ed25519 signature over the 7-field canonical payload. MUST-implement baseline. |
| `fixtures/trust-proof-hybrid.json` | trustProof | ACCEPT | Trust proof with both Ed25519 AND ML-DSA-65 signatures over the same canonical payload. Production wire format. |
| `fixtures/transparency-log-sth.json` | sth | ACCEPT | Signed Tree Head with Ed25519 signature over the raw 32-byte decoded `rootHash`. Compatible with RFC 6962 §3.5 CT monitor expectations. |

## Version pinning

| Component | Version | Source |
|---|---|---|
| ATP spec | v1.0.0-rc1 | [`opena2a-org/agent-trust-protocol/ATP-SPEC.md`](https://github.com/opena2a-standards/agent-trust-protocol/blob/main/ATP-SPEC.md) |
| `did:opena2a` method | v0.1 (W3C registration filed, PR `w3c/did-extensions#717`) | [`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a/blob/main/did-method-opena2a.md) |
| Ed25519 test vector source | RFC 8032 §7.1 Test 1 | [datatracker.ietf.org/doc/html/rfc8032](https://datatracker.ietf.org/doc/html/rfc8032) |
| ML-DSA-65 | FIPS 204 final | [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final) |
| CIRCL (ML-DSA-65 implementation) | v1.6.2 | [github.com/cloudflare/circl](https://github.com/cloudflare/circl) |
| cryptography (Python Ed25519) | >= 42.0.0 | [pyca/cryptography](https://github.com/pyca/cryptography) |
| Conformance fixture format | v1 (this repo) | [`fixtures/trust-proof-baseline.json#$schema`](../fixtures/trust-proof-baseline.json) |

## Versioning and stability

- The conformance fixture file format (`$schema: fixture-v1`) is stable
  across patch revisions of this repository. Adding new fixture fields is
  a minor version bump; renaming or removing fields is a major version
  bump.
- The set of fixtures may grow. New fixtures are additive and do not
  invalidate prior `MANIFEST.sha256` entries; each new fixture appears as
  a new line in the manifest.
- Existing fixtures are immutable once published. If a fixture needs to
  change semantically, it ships under a new name. This is what makes
  `MANIFEST.sha256` a useful regression check.
