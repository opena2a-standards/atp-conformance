# atp-conformance

Conformance fixtures and reference verifiers for the
[Agent Trust Protocol (ATP) v1.0.0-rc1](https://github.com/opena2a-standards/agent-trust-protocol).

Each fixture is a byte-stable JSON file that bundles a pinned ATP protocol
response (discovery, trust proof, or Signed Tree Head) with verifier
configuration and an expected outcome (ACCEPT or REJECT). Two
SDK-independent reference verifiers (Go and Python) walk the fixture set and
report PASS or FAIL per vector. Fixture bytes are pinned in
[`MANIFEST.sha256`](./MANIFEST.sha256).

## Running the verifiers

With Go 1.22 or later, one command fetches the Go verifier (full hybrid
Ed25519 plus ML-DSA-65) and runs it over the fixture set built into it. No
clone is needed:

```bash
go run github.com/opena2a-standards/atp-conformance/verifiers/go@latest
```

That command, and both verifiers run from a clone, report
`summary: 14 pass, 0 fail (14 fixtures)` against the shipped
fixture set (7 ACCEPT, 7 REJECT). Any divergence on bytes (the
fixture file was modified) or on verifier semantics (the verifier has
drifted from the spec) shows up as one or more FAIL lines.

The built-in set is [`verifiers/go/fixtures/`](./verifiers/go/fixtures), a
byte copy of `fixtures/` that the parity gate holds equal. The verifier's
first line of output names the module version the command fetched. Pass
fixture files or a directory as arguments to verify those instead.

### Go from a clone (full hybrid Ed25519 plus ML-DSA-65)

```bash
cd verifiers/go
go run . ../../fixtures
```

Both verifiers walk every `*.json` file in the directory you point them at
(or you may pass individual fixture files). Exit code is 0 if every
fixture's observed result matches the expected result and the rejection
category matches (when declared).

Depends on:

- Go 1.22 or later
- `github.com/cloudflare/circl v1.6.2` (resolved by `go mod tidy`)

### Python from a clone (Ed25519, ML-DSA-65 out of scope)

```bash
cd verifiers/python
pip install -r requirements.txt
python verify.py ../../fixtures
```

Depends on:

- Python 3.11 or later
- `cryptography >= 42.0.0`

For full hybrid verification end to end, use the Go verifier.

### Parity

To additionally assert the two verifiers agree with each other per fixture
(gate status, verdict, reject category), and that the Go verifier's
built-in set is a byte copy of `fixtures/` with the same results:

```bash
python3 scripts/parity/parity.py
```

Both verifiers decode each payload member against the JSON type the
vendored schema gives it before verifying, so a member of the wrong type
or range is `REJECT[PARSE_ERROR]` in both; the rule is in
[docs/how-it-works.md](docs/how-it-works.md#wire-types-both-verifiers-decode-before-they-verify).
A JSON object that repeats a member name is refused by both:
`REJECT[PARSE_ERROR]` inside a payload member and a load error elsewhere
in the fixture
([rule](docs/how-it-works.md#repeated-member-names-both-verifiers-refuse-them)).
A trust proof's `issuedAt` or `expiresAt`, or the verifier's
`clockRfc3339`, whose date as written or UTC equivalent falls outside the
years 1 to 9999 is refused by both at the step that reads it:
`REJECT[PARSE_ERROR]` for the proof's timestamps and
`REJECT[VERIFIER_CONFIG_ERROR]` for the clock
([rule](docs/how-it-works.md#trust-proof-timestamps-both-verifiers-read-the-years-1-to-9999)).
Both read a timestamp only as an RFC 3339 date-time with an upper-case `T`
and `Z`
([rule](docs/how-it-works.md#timestamps-both-verifiers-read-rfc-3339-date-times-only))
and a hex value only as an even number of hex digits
([rule](docs/how-it-works.md#hex-values-both-verifiers-read-hex-digits-only)),
and refuse a string outside those forms at the step that reads it.

## Scope

What this suite verifies, as 17 ATP items each mapped to its fixtures:
[docs/fixtures.md](docs/fixtures.md#what-this-suite-verifies).

Each negative fixture is valid in every respect except the one defect it
pins, so a verifier that skips that verification step (and only that step)
wrongly ACCEPTs it. Expected outcomes pin the reject category
(`EXPIRED`, `UNTRUSTED_ISSUER`, `SIGNATURE_INVALID`, `SEMANTIC_INVALID`,
`PROOF_INVALID`, `PARSE_ERROR`), so rejecting for the wrong reason also fails.

What this suite does NOT verify (v0.3):

- Federation cosignature (ATP §6, Level 3). Production has no second
  authority to source a real cosigned proof from.
- §8.1 response authenticity. The spec does not sign the revocation body;
  the fixtures cover the structural rules only.
- §8.1 entries without a `transparencyLogIndex`, which ATP §8.1 makes
  optional. No fixture carries one yet.

Each item in full: [docs/fixtures.md](docs/fixtures.md#what-this-suite-does-not-verify-v03).

The full requirement-to-fixture mapping is machine-readable in
[`conformance.json`](./conformance.json), regenerated from the fixtures by
[`scripts/conformance_profile.py`](./scripts/conformance_profile.py) and
CI-checked against drift.

Read before forming judgments: the
[honest scope notes](docs/how-it-works.md#honest-scope-notes) on unsigned
fields, the §5.6 Signed Tree Head, hybrid signing, shared test keys and the
DID method.

## Continuous verification

[`.github/workflows/conformance.yml`](./.github/workflows/conformance.yml)
enforces every claim in this README on each push and pull request:

1. Both reference verifiers run against `fixtures/` and must report
   `14 pass, 0 fail`.
2. The fixture generator re-runs and the committed fixture bytes plus
   `MANIFEST.sha256` must reproduce exactly (byte-pin).
3. The cross-implementation parity gate
   ([`scripts/parity/parity.py`](./scripts/parity/parity.py)) asserts the Go
   and Python verifiers agree per fixture on gate status, verdict, and
   reject category. It also runs the Go verifier with no arguments, as the
   first command above does, and fails unless that run agrees with the
   other two and the built-in set is a byte copy of `fixtures/`.
4. The parity gate publishes `parity-report.json` as a CI artifact.
5. `conformance.json` must match the fixture set.
6. Schema validation
   ([`scripts/schema_validation.py`](./scripts/schema_validation.py)): every
   fixture payload (`trustProof`, `signedTreeHead`, `discoveryResponse`) must
   validate against the ATP-SPEC machine-readable schemas.
7. Those schemas are vendored under `schemas/vendor/agent-trust-protocol/`
   and byte-drift-gated against a pinned agent-trust-protocol ref.

## Reproducing the fixtures

The fixtures in this repository are deterministic. To regenerate them from
the keypair vectors in [`vectors/`](./vectors):

```bash
cd scripts/generate-fixtures
go run .
```

The eight steps the generator runs:
[docs/how-it-works.md](docs/how-it-works.md#the-fixture-generator).

Re-running the generator MUST produce byte-identical fixtures. If the bytes
change, either (a) the generator changed, (b) the canonicalization shifted,
or (c) the CIRCL ML-DSA-65 implementation changed. Any of those is a
breaking change for downstream verifiers.

## Implementations that validate against this suite

| Implementation | Verifier | Status |
|---|---|---|
| `opena2a-standards/atp-conformance/verifiers/go` (this repo) | Go, full Ed25519 plus ML-DSA-65 | 14 / 14 PASS |
| `opena2a-standards/atp-conformance/verifiers/python` (this repo) | Python, Ed25519, ML-DSA-65 out of scope | 14 / 14 PASS |

Independent second-party implementations and cosigners are tracked in
[`COSIGNERS.md`](./COSIGNERS.md) and on the sibling issue
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885).

## Cosigning

Second-party cosigners sign [`MANIFEST.sha256`](./MANIFEST.sha256) using
[Sigstore keyless cosign](https://docs.sigstore.dev/cosign/signing/overview/) and
add an entry to [`COSIGNERS.md`](./COSIGNERS.md) recording:

- The commit SHA at which they verified
- The verifier exit summary they observed (e.g., `go=14 pass, 0 fail; python=14 pass, 0 fail`)
- Their identity / organization
- The Sigstore signature artifact path

Cosigners may also produce their own implementation of a verifier against
these fixtures and add it to the implementations table above via PR.

## Documentation

- [docs/fixtures.md](docs/fixtures.md): the coverage table, what is out of scope, shared fixture values, version pinning and stability rules.
- [docs/how-it-works.md](docs/how-it-works.md): the honest scope notes, the generator's steps and the repository layout.
- [docs/USE-CASES.md](docs/USE-CASES.md): how this suite relates to atx-conformance, a2a-idf-conformance, the A2A#1885 criterion and the ATP bash scripts.

Issues and PRs welcome on this repository. Substantive coordination on the
ATP wire format itself happens in
[`opena2a-org/agent-trust-protocol`](https://github.com/opena2a-standards/agent-trust-protocol)
and in the A2A coordination map on
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885).

## License

Apache 2.0, see [`LICENSE`](./LICENSE). All keypairs, seeds, and
identifiers in this repository are TEST-ONLY.
