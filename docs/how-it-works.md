# How it works

The spec readings behind the fixtures, the steps the fixture generator runs,
and the repository layout. The [README](../README.md) has the commands that
run the verifiers and the generator.

## Honest scope notes

This is the section that future reviewers, second-implementation authors,
and A2A coordination-map readers should read before forming judgments.

### Canonicalization: 7 signed fields for trust proofs

ATP §4.3 signs a pipe-delimited canonical string, not the JSON body. The
signature covers exactly 7 fields, defined verbatim in
[`scripts/generate-fixtures/main.go`](../scripts/generate-fixtures/main.go)
`canonicalProofPayload()` and mirrored in both reference verifiers:

```
did | trustLevel | trustScore (%.6f) | verdict |
issuedAt (RFC 3339 UTC) | expiresAt (RFC 3339 UTC) | issuerDid
```

Fields in the JSON body that are NOT covered by the signature include
`signatures` (the signature container itself), `transparencyLogIndex`, and
any future extension fields. A consequence is that an attacker who can
write to a stored trust proof could modify `transparencyLogIndex` without
breaking signature verification. This is a known shape of ATP v1.0.0-rc1
and is documented here so reviewers do not have to discover it from the
code. JCS-canonical JSON signing (RFC 8785) is a candidate hardening for
v1.1.

### Signed Tree Head: literal reading of §5.6

ATP §5.6 says: `"signature": "base64-ed25519-signature-over-rootHash"`. This
suite implements the literal reading: strip the `SHA256:` prefix from the
`rootHash` string, hex-decode the remaining 64 characters to 32 raw bytes,
Ed25519-sign those 32 bytes. The signature is over the raw root-hash bytes
only — it does NOT also cover `treeSize` and `timestamp`.

Practical consequence: an attacker who can rewrite `treeSize` or `timestamp`
on a stored STH without modifying `rootHash` would not break the signature.
Monitors typically compare `rootHash` over time as the primary correctness
check, so this is mitigated in practice, but a v1.1 hardening could extend
the signed payload to include `treeSize || timestamp || rootHash`. Recorded
here as an open spec question.

### Hybrid signing: production status

ATP §4.3 paragraph 2 SHOULDs hybrid Ed25519 + ML-DSA-65 signing. The
production reference authority at `api.oa2a.org` emits hybrid trust proofs
today (per opena2a-registry PR #214 + #215 in the related ATX implementation;
that repository is private, so the observable evidence is the authority's own
output at `api.oa2a.org` and the hybrid fixture in this suite). Shipping a
hybrid fixture in v0.1
makes the SHOULD-path concrete and gives second implementers a wire-format
target.

The Go reference verifier in this repository
([`verifiers/go`](../verifiers/go)) DOES verify ML-DSA-65 signatures per
FIPS 204 via `github.com/cloudflare/circl`. The Python reference verifier
([`verifiers/python`](../verifiers/python)) treats ML-DSA-65 as
present-but-out-of-scope (the post-quantum Python library landscape is
fragmented; no stdlib support). The hybrid fixture is annotated to ACCEPT
on the Ed25519 path alone in Python, with a banner. For full hybrid
verification end to end, run the Go verifier.

### Keypair reuse with atx-conformance

The `issuer-primary` Ed25519 keypair in
[`vectors/issuer-primary.json`](../vectors/issuer-primary.json) is the SAME
bytes as the `issuer-primary` vector in
[`atx-conformance/vectors/issuer-primary.json`](https://github.com/opena2a-standards/atx-conformance/blob/main/vectors/issuer-primary.json):
RFC 8032 §7.1 Test 1 seed, `did:opena2a:authority:opena2a.org` issuer DID.
The ML-DSA-65 seed in [`vectors/mldsa65-seed.json`](../vectors/mldsa65-seed.json)
is also the same 32-byte seed as atx-conformance's. This is deliberate: a
peer cosigner who has already audited the atx-conformance vectors can rely
on the same audit for this suite. Both vector files are TEST-ONLY; the
seeds are publicly known and MUST NOT be used in production.

### DID method

The `did:opena2a:<type>:<id>` identifiers in this suite (issuer and agent
DIDs) are governed by the `did:opena2a` DID method specification at
[`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a)
(Apache-2.0), filed for registration with the W3C DID Extensions registry
on [`w3c/did-extensions#717`](https://github.com/w3c/did-extensions/pull/717).
The method is registry-mediated rather than fully decentralized; trust in
a resolved DID is trust in the OpenA2A Registry that issued it. This
property is acknowledged in the method spec and does not affect the
fixture-level verifier behavior in this repository, which configures
trusted authorities directly from each fixture rather than resolving them
over the network.

## The fixture generator

The README's [Reproducing the fixtures](../README.md#reproducing-the-fixtures)
section has the command.

The generator:

1. Loads each Ed25519 keypair vector. Verifies that the seed-derived public
   key matches the vector's `publicKeyHex`. Panics on drift.
2. Loads the ML-DSA-65 seed. Re-derives the public key from the seed (using
   CIRCL's `mldsa65.NewKeyFromSeed`). Compares against the pinned
   `publicKeyHex`. Panics on drift.
3. Builds each fixture's payload deterministically (no random nonces).
4. Computes the pipe-delimited canonical payload for trust proofs (the same
   7-field function the spec's §4.3 defines, duplicated verbatim in the
   generator and in each reference verifier).
5. Computes the raw 32-byte `rootHash` for the STH (literal reading of §5.6).
6. Ed25519-signs (and ML-DSA-65-signs where applicable) the canonical
   payload or STH bytes.
7. Marshals each fixture to byte-stable JSON (`encoding/json` with 2-space
   indent, fields in struct-declaration order).
8. Writes the fixture file. Recomputes its SHA-256. Updates
   `MANIFEST.sha256` in path-sorted order.

## Repository layout

```
LICENSE                          Apache 2.0
README.md                        overview and commands
MANIFEST.sha256                  per-fixture SHA-256 (path-sorted)
COSIGNERS.md                     second-party cosigner registry
fixtures/                        the 14 conformance fixtures (byte-stable JSON)
vectors/                         test keypair vectors (TEST-ONLY)
verifiers/go/                    Go reference verifier (full hybrid)
verifiers/python/                Python reference verifier (Ed25519)
scripts/generate-fixtures/       deterministic fixture generator (Go)
```
