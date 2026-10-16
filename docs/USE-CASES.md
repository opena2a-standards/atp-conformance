# Use cases and related suites

Where this suite sits next to the other OpenA2A conformance suites and the
ATP live-endpoint scripts. The [README](../README.md) has the commands that
run the verifiers.

## Related conformance suites

This suite mirrors the pattern set by
[`atx-conformance`](https://github.com/opena2a-standards/atx-conformance) (which
covers the ATX credential schema) and by
[`a2a-idf-conformance/fixtures/composition/aim-did-rfc9421/`](https://github.com/opena2a-standards/a2a-idf-conformance/tree/main/fixtures/composition/aim-did-rfc9421)
(APS interop conformance for A2A-IDF wire signatures). It closes criterion (c)
on the OpenA2A maturity bar tracked in
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885):
"peer-cosigned conformance fixtures for AIP, ATP, or ATX comparable to the
`aim-did-rfc9421/*` set."

## Relationship to the existing ATP bash conformance scripts

The ATP spec repo carries a live-endpoint bash conformance suite at
[`agent-trust-protocol/conformance/level{1,2}.sh`](https://github.com/opena2a-standards/agent-trust-protocol/tree/main/conformance).
Those scripts hit a running ATP authority (default `https://api.oa2a.org`)
and exercise the discovery, trust-proof, and transparency endpoints
end-to-end. They are complementary to this repository:

| Suite | Style | What it proves |
|---|---|---|
| `agent-trust-protocol/conformance/level*.sh` | Live curl against a running authority | Authority is reachable, returns conforming shapes, signatures verify in real time |
| `atp-conformance` (this repo) | Offline byte-stable fixtures with SDK-independent verifiers | A second-party verifier with only the spec and the public test keypairs can reproduce ACCEPT / REJECT byte-for-byte |

Both are needed for full coverage; neither replaces the other.
