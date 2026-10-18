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

### Wire types: both verifiers decode before they verify

Each payload member is decoded against the JSON type the vendored schema
gives it before the verification steps run, and a member that does not fit
is `REJECT[PARSE_ERROR]` naming the member. The reading is the Go
verifier's `encoding/json` decode, mirrored member for member by the shape
tables and `_decode` in [`verifiers/python/verify.py`](../verifiers/python/verify.py):

- an `integer` member is a JSON number written without fraction or
  exponent that fits a signed 64-bit integer, so `"5"`, `true`,
  `1847300.0`, `1e3`, `-0.5` and `9223372036854775808` are rejected
  where the schema says integer;
- a `number` member (`trustScore`) is a JSON number that fits a binary64
  float, so `"0.825"` is rejected;
- a `string` member is a JSON string, so `1` for `reason` and `["#"]` for
  `revokedByKeyId` are rejected;
- `null` is a value of no schema type, so a `null` member, array element
  or object value is rejected the same way, where `encoding/json` alone
  would decode it to the zero value: `revocations: null` is a malformed
  response, not an empty revocation list, and `logIndex: null` is not
  leaf 0. Two kinds of member take `null` as absent: the optional
  `transparencyLogIndex` on a §8.1 revocation entry and on a trust proof,
  which is then not checked (a present index must be `>= 0`), and an
  embedded payload or tree head object, which the steps then report as
  missing, also `PARSE_ERROR`;
- a member is read by its exact name, since JSON member names are
  case-sensitive: in a tree head, `TreeSize` or `treesize` is not
  `treeSize`, and both verifiers ignore it as they ignore any member they
  do not read, so `treeSize` is absent. `encoding/json` alone matches a
  member name to a field case-insensitively, so the Go verifier leaves
  out each member whose name is not exactly a field's before it decodes,
  in the fixture document and in each payload;
- an absent member decodes to the zero value (`""`, `0`, an empty array)
  and the verification steps then judge it.

This is stricter than JSON Schema 2020-12, which reads `1.0` as an integer
and puts no upper bound on one. The suite pins the stricter reading so the
two verifiers return the same verdict for inputs outside the committed
fixture set. The regression tables in
[`verifiers/go/verify_test.go`](../verifiers/go/verify_test.go) and
[`verifiers/python/test_verify.py`](../verifiers/python/test_verify.py)
hold the same cases for both verifiers.

### Repeated member names: both verifiers refuse them

RFC 8259 §4 leaves the meaning of a member name that one JSON object
repeats to the receiver, and the two verifiers' JSON decoders read it
differently: Go's `encoding/json` decodes the occurrences into the same
field one after another, so the members of an earlier object occurrence
survive and the first type error is the one reported, while Python's
`json.loads` keeps only the last occurrence. So
`"treeSize": "x", "treeSize": 1847294` in a Signed Tree Head would be a
type error to one verifier and a valid tree size to the other. Both
verifiers refuse a repeated name instead, whatever the values are, as
RFC 7493 §2.3 requires of I-JSON:

- a repeat inside a payload member, including in a member neither
  verifier reads, is `REJECT[PARSE_ERROR]` naming the first repeated
  member in document order, for example
  `signedTreeHead.treeSize: duplicate member name`;
- a repeat elsewhere in the fixture document, such as in `verifierState`
  or `expected`, or a payload member written twice at the top level, is a
  load error with the same text, because the verifier configuration or the
  expected outcome then has more than one reading.

The `repeatedNames` table in
[`verifiers/go/verify_test.go`](../verifiers/go/verify_test.go) and the
`REPEATED_NAMES` table in
[`verifiers/python/test_verify.py`](../verifiers/python/test_verify.py)
hold the same cases for both verifiers.

### Trust-proof timestamps: both verifiers read the years 1 to 9999

Python's `datetime` holds the years 1 to 9999. Go's `time.Parse` with the
RFC 3339 layout also reads a date written in year 0000, and a zone offset
can move a timestamp's UTC equivalent out of those years:
`0001-01-01T00:00:00+01:00` is `0000-12-31T23:00:00Z`, and
`9999-12-31T23:59:59-01:00` is `10000-01-01T00:59:59Z`, which has no
RFC 3339 form. The Go verifier would compare such a time where the Python
verifier cannot read it. So when a trust proof's `issuedAt` or
`expiresAt`, or the verifier's `clockRfc3339`, has a date as written or a
UTC equivalent outside the years 1 to 9999, both verifiers refuse it at
the step that reads it, before any step compares it:

- `issuedAt` or `expiresAt` is `REJECT[PARSE_ERROR]`, the category of a
  proof timestamp that does not parse, for example
  `bad expiresAt: 9999-12-31T23:59:59-01:00 falls outside the years 1 to 9999 in UTC`;
- `clockRfc3339` is `REJECT[VERIFIER_CONFIG_ERROR]`, the category of a
  verifier clock that does not parse as a timestamp: the clock is
  verifier configuration, not part of the proof.

A step that runs before the one that reads the timestamp can still reject
the proof first: with such an `issuedAt`, the expired fixture is
`EXPIRED`. A timestamp inside those years goes on to the verification
steps, at either end: with `expiresAt` set to `0001-01-01T00:00:00Z` the
baseline proof is `EXPIRED`. The `timestampRangeEdges` table in
[`verifiers/go/verify_test.go`](../verifiers/go/verify_test.go) and the
`TIMESTAMP_RANGE_EDGES` table in
[`verifiers/python/test_verify.py`](../verifiers/python/test_verify.py)
hold the same cases for both verifiers.

### Timestamps: both verifiers read RFC 3339 date-times only

Both verifiers read a timestamp only as an RFC 3339 §5.6 `date-time` with
the `T` and `Z` in upper case, as Go's `time.RFC3339` layout writes them:
`YYYY-MM-DDThh:mm:ss`, an optional fraction of one or more digits after
`.`, then `Z` or a `+hh:mm` or `-hh:mm` offset, with a year from 0001, an
hour and an offset hour of at most 23, an offset minute of at most 59, and
a date and time of day that exist (no `2026-02-29`, no second 60). That
holds for a trust proof's `issuedAt` and `expiresAt`, a tree head's
`timestamp`, a revocation list's `nextSince` and each entry's `revokedAt`,
and the verifier's `clockRfc3339`. On its own, Python's
`datetime.fromisoformat` also reads strings outside that grammar, such as
`2026-05-24 00:00:00Z`, `20260524T000000Z`, `2026-05-24T00:00:00+01` and a
timestamp with no zone, and Go's `time.Parse` with the RFC 3339 layout
also reads `2026-05-24T0:00:00Z`, `2026-05-24T00:00:00,5Z`,
`2026-05-24T00:00:00+24:00` and `0000-01-01T00:00:00Z`. RFC 3339 also
allows a lower-case `t` and `z`, which `time.Parse` refuses. Both
verifiers refuse a string outside the grammar at the step that reads it:

- a trust proof's or a revocation list's timestamp is
  `REJECT[PARSE_ERROR]`;
- a tree head's `timestamp` is `REJECT[STH_INVALID]`;
- `clockRfc3339` is `REJECT[VERIFIER_CONFIG_ERROR]`.

The `notRFC3339` and `rfc3339DateTimes` lists in
[`verifiers/go/verify_test.go`](../verifiers/go/verify_test.go) and the
`NOT_RFC3339` and `RFC3339_DATE_TIMES` lists in
[`verifiers/python/test_verify.py`](../verifiers/python/test_verify.py)
hold the same cases for both verifiers, each refused string with the
parser that reads it on its own.

### Fractions of a second: both verifiers read microseconds

Both verifiers read a timestamp to the microsecond: the first six digits
of a fraction of a second count, and any digit after the sixth is dropped,
not rounded, so `2026-05-24T06:00:00.0000009Z` is read as
`2026-05-24T06:00:00Z`. Python's `datetime` holds microseconds, and
`datetime.fromisoformat` drops the digits after the sixth (in Python 3.11
or later, which the README requires; Python 3.10 refuses such a
fraction). Go's `time.Parse` keeps nine digits (nanoseconds), so the Go
verifier truncates the time it reads to the microsecond. Read to two precisions, one string
would be two different times, and a step that compares times could return
a different verdict in each verifier. Three steps compare times: the
expiry check (the verifier's `clockRfc3339` against `expiresAt`), the
check that `issuedAt` is before `expiresAt`, and the 24-hour validity
window. With the baseline proof, which expires at `2026-05-24T06:00:00Z`,
18 hours after its `issuedAt`, both verifiers return:

- `ACCEPT` with `clockRfc3339` set to `2026-05-24T06:00:00.0000001Z`,
  which is read as the expiry time, and `EXPIRED` with
  `2026-05-24T06:00:00.000001Z`, a microsecond after it;
- `SIGNATURE_INVALID` with `expiresAt` set to
  `2026-05-24T12:00:00.0000001Z`: the window is read as exactly 24 hours,
  which the window check allows, and the signed form, which writes each
  timestamp to the whole second, then holds `2026-05-24T12:00:00Z`, not
  the `2026-05-24T06:00:00Z` the signature covers. With
  `2026-05-24T12:00:00.000001Z`, a window a microsecond over 24 hours, it
  is `SEMANTIC_INVALID`.

The `EXPIRED` reason writes the expiry time and the verifier's clock in
UTC to the microsecond the check compares, without the trailing zeros of
a fraction of a second and with no fraction when it is zero, so a clock a
microsecond after the expiry time does not read as the expiry time. With
`clockRfc3339` set to `2026-05-24T06:00:00.000001Z`, both verifiers
return
`REJECT[EXPIRED: expired at 2026-05-24T06:00:00Z, verifier clock is 2026-05-24T06:00:00.000001Z]`.

The `subMicrosecondTimestamps` and `expiredReasons` tables in
[`verifiers/go/verify_test.go`](../verifiers/go/verify_test.go) and the
`SUB_MICROSECOND_TIMESTAMPS` and `EXPIRED_REASONS` tables in
[`verifiers/python/test_verify.py`](../verifiers/python/test_verify.py)
hold the same cases for both verifiers.

### Hex values: both verifiers read hex digits only

Both verifiers read a hex value as Go's `hex.DecodeString` reads it: an
even number of hex digits in either case, and nothing else. That holds
for a `publicKeyHex` in `verifierState` or in a discovery response, for a
tree head's `rootHash`, and for a proof's `leafHash` and path hashes after
the `SHA256:` prefix. Python's `bytes.fromhex` on its own skips ASCII
whitespace between bytes, which `hex.DecodeString` refuses, and the Python
verifier refuses it as well:

- a configured Ed25519 `publicKeyHex` with whitespace in it is skipped,
  so a signature that only that key verifies is
  `REJECT[SIGNATURE_INVALID]`;
- whitespace in a tree head's `rootHash` is `REJECT[STH_INVALID]`, in a
  `leafHash` or a path hash `REJECT[PARSE_ERROR]`, and in a discovery
  response's `publicKeyHex` `REJECT[DISCOVERY_INVALID]`.

The `hexMembers` table in
[`verifiers/go/verify_test.go`](../verifiers/go/verify_test.go) and the
`HEX_MEMBERS` table in
[`verifiers/python/test_verify.py`](../verifiers/python/test_verify.py)
hold the same cases for both verifiers.

### Verifier configuration: `verifierState` decodes to zero values

`verifierState` is the verifier's configuration (its clock, trusted
issuers and public keys), not a protocol response, so the wire type rules
above do not apply to it. Both verifiers read it the way the Go
verifier's `encoding/json` decode does:

- an absent or `null` member, `verifierState` itself included, is its
  zero value (`""` or an empty array), and the verification steps then
  judge it. With no `verifierState`, a Signed Tree Head is
  `REJECT[SIGNATURE_INVALID]` (no configured key), a trust proof is
  `REJECT[VERIFIER_CONFIG_ERROR]` (no clock) and a discovery response is
  `REJECT[UNTRUSTED_ISSUER]` (no trusted issuer). A Signed Tree Head whose
  one configured key has no `publicKeyHex` is `REJECT[SIGNATURE_INVALID]`
  too;
- a member of the wrong JSON type, such as a number for `clockRfc3339` or
  an object for `publicKeys`, is a load error.

The `verifierStateMembers` table in
[`verifiers/go/verify_test.go`](../verifiers/go/verify_test.go) and the
`VERIFIER_STATE_MEMBERS` table in
[`verifiers/python/test_verify.py`](../verifiers/python/test_verify.py)
hold the same cases for both verifiers.

### Fixture members: both verifiers decode them with the Go types

Both verifiers decode `name`, `description`, `fixtureType`,
`keypairRefs` and `expected` the way they decode `verifierState`, with the
types of the Go verifier's fixture struct: `name`, `description` and
`fixtureType` are strings, `keypairRefs` is an array of objects of
strings, and `expected` is an object of strings. A member of the wrong
JSON type, such as a number for `name` or an array for `expected`, is a
load error in both verifiers, and an absent or `null` member is its zero
value. Members neither verifier reads, such as `$schema` and `spec`, are
ignored. The `fixtureMembers` table in
[`verifiers/go/verify_test.go`](../verifiers/go/verify_test.go) and the
`FIXTURE_MEMBERS` table in
[`verifiers/python/test_verify.py`](../verifiers/python/test_verify.py)
hold the same cases for both verifiers.

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

The Go verifier builds in a copy of `fixtures/`, `verifiers/go/fixtures/`,
so `go run github.com/opena2a-standards/atp-conformance/verifiers/go@latest`
verifies the suite with no clone. The generator does not write that copy:
CI runs the generator before the parity gate, so a copy it rewrote there
could no longer show that the committed copy had gone stale. After a
regeneration that changes `fixtures/`, copy the changed files across; the
parity gate names each file that differs and the command that fixes it.

## Repository layout

```
LICENSE                          Apache 2.0
README.md                        overview and commands
MANIFEST.sha256                  per-fixture SHA-256 (path-sorted)
COSIGNERS.md                     second-party cosigner registry
fixtures/                        the 14 conformance fixtures (byte-stable JSON)
vectors/                         test keypair vectors (TEST-ONLY)
verifiers/go/                    Go reference verifier (full hybrid)
verifiers/go/fixtures/           byte copy of fixtures/ built into the Go verifier
verifiers/python/                Python reference verifier (Ed25519)
scripts/generate-fixtures/       deterministic fixture generator (Go)
```
