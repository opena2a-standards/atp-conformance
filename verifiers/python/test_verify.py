#!/usr/bin/env python3
"""Regression tests for verify.py: the ATP §8.1 revocation-entry checks, the
PARSE_ERROR verdict for members of the wrong JSON type and the reading of
each member by its exact name, under the wire-shape rules both reference
verifiers apply, the verdicts for trust-proof timestamps at the edges of the
years 1 to 9999, the PARSE_ERROR verdict for a value that makes Python
raise OverflowError and for an integer literal too long for int(), and the
VERIFIER_CONFIG_ERROR verdict or load error for a bad verifierState.

Run from this directory:
    python3 -m unittest -v test_verify
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from typing import Any

import verify

# The ATP §8.1 example entry, as pinned in fixtures/revocation-list-valid.json.
SPEC_ENTRY: dict[str, Any] = {
    "agentDid": "did:opena2a:mcp_server:compromised-package",
    "revokedAt": "2026-03-22T15:00:00Z",
    "reason": "Supply chain compromise detected",
    "transparencyLogIndex": 1847300,
    "revokedByKeyId": "did:opena2a:authority:opena2a.org#key-v3",
}


def verify_entry(entry: dict[str, Any]) -> verify.VerifyResult:
    return verify.verify_fixture(
        {
            "fixtureType": "revocationList",
            "revocationList": {"revocations": [entry], "nextSince": "2026-03-22T15:00:00Z"},
        }
    )


class TransparencyLogIndexTest(unittest.TestCase):
    """transparencyLogIndex is optional on a §8.1 entry; a present one must be >= 0."""

    def test_absent_index_is_accepted(self) -> None:
        entry = {k: v for k, v in SPEC_ENTRY.items() if k != "transparencyLogIndex"}
        got = verify_entry(entry)
        self.assertTrue(got.accepted, str(got))

    def test_null_index_is_accepted(self) -> None:
        got = verify_entry({**SPEC_ENTRY, "transparencyLogIndex": None})
        self.assertTrue(got.accepted, str(got))

    def test_zero_index_is_accepted(self) -> None:
        got = verify_entry({**SPEC_ENTRY, "transparencyLogIndex": 0})
        self.assertTrue(got.accepted, str(got))

    def test_spec_example_index_is_accepted(self) -> None:
        got = verify_entry(dict(SPEC_ENTRY))
        self.assertTrue(got.accepted, str(got))

    def test_negative_index_is_rejected(self) -> None:
        got = verify_entry({**SPEC_ENTRY, "transparencyLogIndex": -1})
        self.assertFalse(got.accepted)
        self.assertEqual(got.reject_category, "PARSE_ERROR")
        self.assertIn("transparencyLogIndex", got.reason)


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


def revocation_with(**overrides: Any) -> dict[str, Any]:
    fx = load("revocation-list-valid.json")
    fx["revocationList"]["revocations"][0].update(overrides)
    return fx


class MalformedMemberTest(unittest.TestCase):
    """A member of the wrong JSON type is a PARSE_ERROR verdict, not an exception."""

    def assert_parse_error(self, fixture: dict[str, Any]) -> None:
        got = verify.verify_fixture(fixture)
        self.assertFalse(got.accepted, str(got))
        self.assertEqual(got.reject_category, "PARSE_ERROR", str(got))

    def test_transparency_log_index_wrong_type(self) -> None:
        for value in ("abc", "", "0x10", {}, []):
            with self.subTest(value=value):
                self.assert_parse_error(revocation_with(transparencyLogIndex=value))

    def test_revocations_null(self) -> None:
        fx = load("revocation-list-valid.json")
        fx["revocationList"]["revocations"] = None
        self.assert_parse_error(fx)

    def test_revoked_by_key_id_null(self) -> None:
        self.assert_parse_error(revocation_with(revokedByKeyId=None))

    def test_agent_did_number(self) -> None:
        self.assert_parse_error(revocation_with(agentDid=42))

    def test_revocation_entry_number(self) -> None:
        fx = load("revocation-list-valid.json")
        fx["revocationList"]["revocations"][0] = 7
        self.assert_parse_error(fx)

    def test_inclusion_log_index_null(self) -> None:
        fx = load("transparency-inclusion-proof-valid.json")
        fx["inclusionProof"]["logIndex"] = None
        self.assert_parse_error(fx)

    def test_sth_tree_size_null(self) -> None:
        fx = load("transparency-log-sth.json")
        fx["signedTreeHead"]["treeSize"] = None
        self.assert_parse_error(fx)

    def test_consistency_from_size_null(self) -> None:
        fx = load("transparency-consistency-proof-valid.json")
        fx["consistencyProof"]["fromSize"] = None
        self.assert_parse_error(fx)

    def test_discovery_conformance_level_wrong_type(self) -> None:
        for value in (None, "2"):
            with self.subTest(value=value):
                fx = load("discovery-valid.json")
                fx["discoveryResponse"]["conformanceLevel"] = value
                self.assert_parse_error(fx)


class DirectoryRunTest(unittest.TestCase):
    """A malformed fixture in a directory run does not stop the fixtures after it."""

    def test_run_continues_and_prints_summary(self) -> None:
        valid = load("revocation-list-valid.json")
        bad = revocation_with(transparencyLogIndex="abc")
        with tempfile.TemporaryDirectory() as d:
            for name, fx in (("a-valid.json", valid), ("b-bad.json", bad), ("c-valid.json", valid)):
                (Path(d) / name).write_text(json.dumps(fx))
            (Path(d) / "d-array.json").write_text("[]")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = verify.main(["verify.py", d])
        lines = out.getvalue().splitlines()
        self.assertEqual(code, 1)
        self.assertEqual([ln.split()[0] for ln in lines if ln.startswith(("PASS", "FAIL"))], ["PASS", "FAIL", "PASS", "FAIL"])
        self.assertIn("REJECT[PARSE_ERROR", out.getvalue())
        self.assertEqual(lines[-1], "summary: 2 pass, 2 fail (4 fixtures)")


def with_member(fixture: dict[str, Any], path: str, literal: str) -> dict[str, Any]:
    """A copy of fixture with the member at the dotted path (array steps as
    indexes) replaced by the JSON literal, read the way json.loads reads it
    from a fixture file."""
    doc = copy.deepcopy(fixture)
    steps: list[Any] = [int(step) if step.isdigit() else step for step in path.split(".")]
    cur: Any = doc
    for step in steps[:-1]:
        cur = cur[step]
    cur[steps[-1]] = json.loads(literal)
    return doc


# One member of a committed ACCEPT fixture replaced by a value whose JSON
# type or range the vendored schema rejects. ../go/verify_test.go holds the
# same table.
SCHEMA_TYPE_VIOLATIONS: list[tuple[str, str, str]] = [
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", '"5"'),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", '"1847300"'),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", '" 42 "'),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", '"1_000"'),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "true"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "false"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "1847300.0"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "1847300.5"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "1e3"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "1e30"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "9223372036854775808"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "9" * 400),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "-0.5"),
    ("revocation-list-valid.json", "revocationList.revocations.0.transparencyLogIndex", "-0.999"),
    ("revocation-list-valid.json", "revocationList.revocations.0.reason", "1"),
    ("revocation-list-valid.json", "revocationList.revocations.0.revokedByKeyId", '["#"]'),
    ("revocation-list-valid.json", "revocationList.revocations", "{}"),
    ("revocation-list-valid.json", "revocationList.nextSince", "20260322"),
    ("trust-proof-baseline.json", "trustProof.trustLevel", '"3"'),
    ("trust-proof-baseline.json", "trustProof.trustLevel", "3.7"),
    ("trust-proof-baseline.json", "trustProof.trustScore", '"0.825"'),
    ("trust-proof-baseline.json", "trustProof.transparencyLogIndex", '"7"'),
    ("trust-proof-baseline.json", "trustProof.transparencyLogIndex", "-0.5"),
    ("trust-proof-baseline.json", "trustProof.transparencyLogIndex", "-5"),
    ("trust-proof-baseline.json", "trustProof.signatures.0.value", "42"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.logIndex", "3.5"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.logIndex", '"3"'),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.treeSize", '"8"'),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.auditPath", '"SHA256:00"'),
    ("transparency-consistency-proof-valid.json", "consistencyProof.fromSize", '"4"'),
    ("transparency-log-sth.json", "signedTreeHead.treeSize", '"1847294"'),
    ("transparency-log-sth.json", "signedTreeHead.rootHash", '["SHA256:00"]'),
    ("discovery-valid.json", "discoveryResponse.conformanceLevel", "2.5"),
    ("discovery-valid.json", "discoveryResponse.conformanceLevel", "true"),
    ("discovery-valid.json", "discoveryResponse.version", "1.0"),
    ("discovery-valid.json", "discoveryResponse.endpoints", '["/api/v1/trust/proof"]'),
]


class SchemaTypeViolationTest(unittest.TestCase):
    """A member whose JSON type or range violates the vendored schema is
    REJECT[PARSE_ERROR] naming the member, the verdict the Go verifier
    returns for the same input, instead of being coerced with int() or
    float() and accepted."""

    def test_unmodified_fixtures_are_accepted(self) -> None:
        for name in sorted({case[0] for case in SCHEMA_TYPE_VIOLATIONS}):
            with self.subTest(fixture=name):
                got = verify.verify_fixture(load(name))
                self.assertTrue(got.accepted, str(got))

    def test_type_violation_is_parse_error(self) -> None:
        for name, path, literal in SCHEMA_TYPE_VIOLATIONS:
            with self.subTest(fixture=name, path=path, value=literal[:24]):
                got = verify.verify_fixture(with_member(load(name), path, literal))
                member = path.rsplit(".", 1)[-1]
                self.assertFalse(got.accepted, str(got))
                self.assertEqual(got.reject_category, "PARSE_ERROR", str(got))
                self.assertIn(member, got.reason)


# One member of a committed ACCEPT fixture set to JSON null where the vendored
# schema gives it a type: each member kind (string, integer, number, array,
# array element, object, object value) on each payload type.
# ../go/verify_test.go holds the same table.
NULL_VIOLATIONS: list[tuple[str, str]] = [
    ("revocation-list-valid.json", "revocationList.revocations"),
    ("revocation-list-valid.json", "revocationList.revocations.0"),
    ("revocation-list-valid.json", "revocationList.revocations.0.agentDid"),
    ("revocation-list-valid.json", "revocationList.revocations.0.reason"),
    ("revocation-list-valid.json", "revocationList.revocations.0.revokedByKeyId"),
    ("revocation-list-valid.json", "revocationList.nextSince"),
    ("trust-proof-baseline.json", "trustProof.did"),
    ("trust-proof-baseline.json", "trustProof.trustLevel"),
    ("trust-proof-baseline.json", "trustProof.trustScore"),
    ("trust-proof-baseline.json", "trustProof.signatures"),
    ("trust-proof-baseline.json", "trustProof.signatures.0.value"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.logIndex"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.auditPath"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.auditPath.0"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.treeSize"),
    ("transparency-consistency-proof-valid.json", "consistencyProof.fromSize"),
    ("transparency-consistency-proof-valid.json", "consistencyProof.consistencyPath"),
    ("transparency-consistency-proof-valid.json", "consistencyProof.toSignedTreeHead.rootHash"),
    ("transparency-log-sth.json", "signedTreeHead.treeSize"),
    ("transparency-log-sth.json", "signedTreeHead.timestamp"),
    ("discovery-valid.json", "discoveryResponse.conformanceLevel"),
    ("discovery-valid.json", "discoveryResponse.authorityDid"),
    ("discovery-valid.json", "discoveryResponse.endpoints"),
    ("discovery-valid.json", "discoveryResponse.endpoints.trustProof"),
    ("discovery-valid.json", "discoveryResponse.publicKeys.0.status"),
    ("discovery-valid.json", "discoveryResponse.supportedMethods"),
]


def member_label(path: str) -> str:
    """A dotted fixture path written the way both verifiers name the member in
    a reason, with array steps as [index]."""
    label = ""
    for step in path.split("."):
        if step.isdigit():
            label += f"[{step}]"
        else:
            label += f".{step}" if label else step
    return label


class NullMemberTest(unittest.TestCase):
    """JSON null is a value of no schema type, so a null member is
    REJECT[PARSE_ERROR] naming the member, the verdict the Go verifier
    returns for the same input, and not the zero value encoding/json decodes
    it to: revocations null is not an empty revocation list, and logIndex
    null is not leaf 0. The members that take null take it as absent: an
    optional transparencyLogIndex is then not checked
    (TransparencyLogIndexTest covers the §8.1 entry's) and an embedded tree
    head is reported missing."""

    def test_null_member_is_parse_error(self) -> None:
        for name, path in NULL_VIOLATIONS:
            with self.subTest(fixture=name, path=path):
                got = verify.verify_fixture(with_member(load(name), path, "null"))
                want = f"{member_label(path)}: JSON null does not fit the "
                self.assertFalse(got.accepted, str(got))
                self.assertEqual(got.reject_category, "PARSE_ERROR", str(got))
                self.assertTrue(got.reason.startswith(want), f"{got} does not begin {want!r}")

    def test_null_trust_proof_index_is_accepted(self) -> None:
        got = verify.verify_fixture(
            with_member(load("trust-proof-baseline.json"), "trustProof.transparencyLogIndex", "null")
        )
        self.assertTrue(got.accepted, str(got))

    def test_absent_trust_proof_index_is_accepted(self) -> None:
        doc = load("trust-proof-baseline.json")
        del doc["trustProof"]["transparencyLogIndex"]
        got = verify.verify_fixture(doc)
        self.assertTrue(got.accepted, str(got))

    def test_null_embedded_tree_head_is_missing(self) -> None:
        for name, path, reason in (
            ("transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead", "signedTreeHead missing"),
            (
                "transparency-consistency-proof-valid.json",
                "consistencyProof.fromSignedTreeHead",
                "fromSignedTreeHead/toSignedTreeHead missing",
            ),
        ):
            with self.subTest(path=path):
                got = verify.verify_fixture(with_member(load(name), path, "null"))
                self.assertEqual(got.reject_category, "PARSE_ERROR", str(got))
                self.assertIn(reason, got.reason)


def renamed(fixture: dict[str, Any], path: str, rename: str) -> dict[str, Any]:
    """A copy of fixture with the object member at the dotted path (array
    steps as indexes) renamed to rename with its value kept, or left out
    when rename is ""."""
    doc = copy.deepcopy(fixture)
    steps: list[Any] = [int(step) if step.isdigit() else step for step in path.split(".")]
    cur: Any = doc
    for step in steps[:-1]:
        cur = cur[step]
    value = cur.pop(steps[-1])
    if rename:
        cur[rename] = value
    return doc


# One member of a committed ACCEPT fixture renamed to a name that differs
# from the schema's only in letter case, with the verdict both verifiers
# return: ACCEPT or the REJECT category. A key of the free-form endpoints
# object is data, not a schema member name, and is kept as written.
# ../go/verify_test.go holds the same table.
CASE_VARIANT_MEMBERS: list[tuple[str, str, str, str]] = [
    ("transparency-log-sth.json", "signedTreeHead.treeSize", "TreeSize", "STH_INVALID"),
    ("transparency-log-sth.json", "signedTreeHead.treeSize", "treesize", "STH_INVALID"),
    ("transparency-log-sth.json", "signedTreeHead.treeSize", "tree\N{LATIN SMALL LETTER LONG S}ize", "STH_INVALID"),
    ("transparency-log-sth.json", "signedTreeHead", "SignedTreeHead", "PARSE_ERROR"),
    ("transparency-log-sth.json", "fixtureType", "FixtureType", "PARSE_ERROR"),
    ("trust-proof-baseline.json", "trustProof.issuerDid", "issuerDID", "UNTRUSTED_ISSUER"),
    ("trust-proof-baseline.json", "trustProof.signatures.0.value", "Value", "SIGNATURE_INVALID"),
    ("transparency-inclusion-proof-valid.json", "inclusionProof.signedTreeHead.treeSize", "TreeSize", "STH_INVALID"),
    ("transparency-consistency-proof-valid.json", "consistencyProof.toSize", "ToSize", "PARSE_ERROR"),
    ("revocation-list-valid.json", "revocationList.revocations.0.revokedByKeyId", "revokedByKeyID", "PARSE_ERROR"),
    ("discovery-valid.json", "discoveryResponse.authorityDid", "AuthorityDid", "DISCOVERY_INVALID"),
    ("discovery-valid.json", "discoveryResponse.endpoints.trustProof", "TrustProof", "ACCEPT"),
]


class CaseVariantMemberTest(unittest.TestCase):
    """JSON member names are case-sensitive and each member is read by its
    exact name, so a member renamed to another letter case verifies the same
    as the fixture with that member left out, the verdict the Go verifier
    returns for the same input. The unmodified fixtures verify ACCEPT
    (SchemaTypeViolationTest checks each one)."""

    def test_case_variant_member_is_absent(self) -> None:
        for name, path, rename, want in CASE_VARIANT_MEMBERS:
            with self.subTest(fixture=name, path=path, rename=rename):
                got = verify.verify_fixture(renamed(load(name), path, rename))
                absent = verify.verify_fixture(renamed(load(name), path, ""))
                self.assertEqual(str(got), str(absent))
                self.assertEqual("ACCEPT" if got.accepted else got.reject_category, want, str(got))


# One member of a committed fixture's verifierState, the verifier
# configuration, left out (literal "") or replaced by the JSON literal, with
# the outcome both verifiers return: ACCEPT, the REJECT category, or "load
# error". ../go/verify_test.go holds the same table.
VERIFIER_STATE_MEMBERS: list[tuple[str, str, str, str]] = [
    ("transparency-log-sth.json", "verifierState", "", "SIGNATURE_INVALID"),
    ("transparency-log-sth.json", "verifierState", "null", "SIGNATURE_INVALID"),
    ("transparency-log-sth.json", "verifierState.publicKeys", "", "SIGNATURE_INVALID"),
    ("transparency-log-sth.json", "verifierState.publicKeys", "null", "SIGNATURE_INVALID"),
    ("transparency-log-sth.json", "verifierState.publicKeys.0.publicKeyHex", "", "SIGNATURE_INVALID"),
    ("transparency-log-sth.json", "verifierState.publicKeys.0.publicKeyHex", "null", "SIGNATURE_INVALID"),
    ("transparency-log-sth.json", "verifierState.publicKeys.0.algorithm", "", "SIGNATURE_INVALID"),
    ("trust-proof-baseline.json", "verifierState", "", "VERIFIER_CONFIG_ERROR"),
    ("trust-proof-baseline.json", "verifierState.clockRfc3339", "", "VERIFIER_CONFIG_ERROR"),
    ("trust-proof-baseline.json", "verifierState.clockRfc3339", "null", "VERIFIER_CONFIG_ERROR"),
    ("trust-proof-baseline.json", "verifierState.trustedIssuers", "", "UNTRUSTED_ISSUER"),
    ("discovery-valid.json", "verifierState", "", "UNTRUSTED_ISSUER"),
    ("discovery-valid.json", "verifierState.trustedIssuers.0", "null", "UNTRUSTED_ISSUER"),
    ("transparency-inclusion-proof-valid.json", "verifierState", "", "SIGNATURE_INVALID"),
    ("transparency-consistency-proof-valid.json", "verifierState", "", "SIGNATURE_INVALID"),
    ("transparency-log-sth.json", "verifierState", '"x"', "load error"),
    ("transparency-log-sth.json", "verifierState.publicKeys", "{}", "load error"),
    ("transparency-log-sth.json", "verifierState.publicKeys.0.publicKeyHex", "5", "load error"),
    ("trust-proof-baseline.json", "verifierState.clockRfc3339", "5", "load error"),
]


class VerifierStateMemberTest(unittest.TestCase):
    """verifierState is decoded the way the Go verifier's encoding/json
    decodes it: an absent or null member is its zero value, which the
    verification steps then judge (no clock, no trusted issuer, no public
    key), and a member of the wrong JSON type is a load error. The reason
    names no Python exception. The unmodified fixtures verify ACCEPT
    (SchemaTypeViolationTest checks each one)."""

    def test_verifier_state_member(self) -> None:
        for name, path, literal, want in VERIFIER_STATE_MEMBERS:
            with self.subTest(fixture=name, path=path, value=literal):
                doc = with_member(load(name), path, literal) if literal else renamed(load(name), path, "")
                try:
                    fixture = verify.parse_fixture(json.dumps(doc))
                except ValueError as exc:
                    self.assertEqual(want, "load error", str(exc))
                    continue
                got = verify.verify_fixture(fixture)
                self.assertEqual("ACCEPT" if got.accepted else got.reject_category, want, str(got))
                self.assertNotRegex(got.reason, r"\w+Error: ")


class FixtureDocumentTest(unittest.TestCase):
    """parse_fixture refuses at load time what the Go verifier's decoder
    refuses: the NaN / Infinity extensions and a document that is not a
    JSON object."""

    def test_nan_literal_is_a_load_error(self) -> None:
        with self.assertRaises(ValueError):
            verify.parse_fixture('{"fixtureType": "trustProof", "trustProof": {"trustScore": NaN}}')

    def test_infinity_literal_is_a_load_error(self) -> None:
        with self.assertRaises(ValueError):
            verify.parse_fixture('{"trustProof": {"trustScore": -Infinity}}')

    def test_non_object_document_is_a_load_error(self) -> None:
        with self.assertRaises(ValueError):
            verify.parse_fixture("[]")

    def test_committed_fixture_parses(self) -> None:
        doc = verify.parse_fixture((FIXTURES / "trust-proof-baseline.json").read_text())
        self.assertEqual(doc["fixtureType"], "trustProof")


def fixture_text_with(name: str, old: str, new: str) -> str:
    """The text of a committed fixture with one literal replaced, for a value
    a fixture file can carry but json.dumps does not write (1e400) or a
    member name repeated in one JSON object."""
    text = (FIXTURES / name).read_text()
    if text.count(old) != 1:
        raise AssertionError(f"{old!r} does not occur exactly once in {name}")
    return text.replace(old, new)


# RFC 3339 timestamps whose UTC equivalent falls outside the years 1 to 9999
# that Python's datetime holds (0000-12-31T23:00:00Z and
# 10000-01-01T00:59:59Z), so converting them to UTC raises OverflowError.
OUT_OF_RANGE_TIMES = ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00")

# The trust-proof timestamps, as dotted paths in a trustProof fixture.
TIMESTAMP_MEMBERS = ("trustProof.issuedAt", "trustProof.expiresAt", "verifierState.clockRfc3339")

# Timestamps at the edges of the years 1 to 9999, each set in turn as the
# issuedAt, expiresAt and verifier clockRfc3339 of trust-proof-baseline.json,
# with the verdict both verifiers return for each: ACCEPT or the REJECT
# category. A UTC equivalent that differs from the value is noted beside it.
# ../go/verify_test.go holds the same table.
TIMESTAMP_RANGE_EDGES: list[tuple[str, str, str, str]] = [
    # (value, verdict as issuedAt, as expiresAt, as clockRfc3339)
    ("0001-01-01T00:00:00+01:00", "PARSE_ERROR", "PARSE_ERROR", "VERIFIER_CONFIG_ERROR"),  # 0000-12-31T23:00:00Z
    ("9999-12-31T23:59:59-01:00", "PARSE_ERROR", "PARSE_ERROR", "VERIFIER_CONFIG_ERROR"),  # 10000-01-01T00:59:59Z
    ("0000-06-15T00:00:00Z", "PARSE_ERROR", "PARSE_ERROR", "VERIFIER_CONFIG_ERROR"),
    ("0000-12-31T23:30:00-01:00", "PARSE_ERROR", "PARSE_ERROR", "VERIFIER_CONFIG_ERROR"),  # 0001-01-01T00:30:00Z
    ("0001-01-01T00:00:00Z", "SEMANTIC_INVALID", "EXPIRED", "ACCEPT"),
    ("0001-01-01T00:59:59+00:59", "SEMANTIC_INVALID", "EXPIRED", "ACCEPT"),  # 0001-01-01T00:00:59Z
    ("9999-12-31T23:59:59Z", "SEMANTIC_INVALID", "SEMANTIC_INVALID", "EXPIRED"),
    ("9999-12-31T23:00:00-00:59", "SEMANTIC_INVALID", "SEMANTIC_INVALID", "EXPIRED"),  # 9999-12-31T23:59:00Z
]


class TimestampRangeTest(unittest.TestCase):
    """A trust-proof timestamp whose date as written or whose UTC equivalent
    falls outside the years 1 to 9999 is refused at the step that reads it,
    before a step compares it. In trust-proof-baseline.json that is
    REJECT[PARSE_ERROR] as issuedAt or expiresAt and
    REJECT[VERIFIER_CONFIG_ERROR] as the verifier's clock, with a reason
    naming the member, the verdicts the Go verifier returns for the same
    input. Python's datetime holds no other years, where Go's time package
    reads a date written in year 0000 and puts the UTC equivalent of an
    offset time in year 0 or 10000. A timestamp inside the years, at either
    end, goes on to the verification steps."""

    def test_timestamp_range_edges(self) -> None:
        for value, *wants in TIMESTAMP_RANGE_EDGES:
            for path, want in zip(TIMESTAMP_MEMBERS, wants):
                with self.subTest(path=path, value=value):
                    got = verify.verify_fixture(
                        with_member(load("trust-proof-baseline.json"), path, json.dumps(value))
                    )
                    self.assertEqual("ACCEPT" if got.accepted else got.reject_category, want, str(got))
                    if want in ("PARSE_ERROR", "VERIFIER_CONFIG_ERROR"):
                        prefix = f"bad {path.rsplit('.', 1)[-1]}: "
                        self.assertTrue(got.reason.startswith(prefix), f"{got} does not begin {prefix!r}")

    def test_out_of_range_utc_reason(self) -> None:
        """Both verifiers give the same reason for a timestamp written inside
        the years whose UTC equivalent falls outside them."""
        for path in TIMESTAMP_MEMBERS:
            for value in OUT_OF_RANGE_TIMES:
                with self.subTest(path=path, value=value):
                    got = verify.verify_fixture(
                        with_member(load("trust-proof-baseline.json"), path, json.dumps(value))
                    )
                    member = path.rsplit(".", 1)[-1]
                    self.assertEqual(got.reason, f"bad {member}: {value} falls outside the years 1 to 9999 in UTC")


class OverflowErrorTest(unittest.TestCase):
    """A fixture value that makes Python raise OverflowError is
    REJECT[PARSE_ERROR] for that fixture, not a traceback that ends the run:
    a directory run goes on to the fixtures after it and prints its summary.
    The number literal 1e400, which json.loads reads as infinity, is refused
    by the wire-shape check in the integer members the directory run sets it
    in, and an expiresAt in OUT_OF_RANGE_TIMES, whose conversion to UTC
    raises OverflowError, by the trust-proof timestamp check
    (TimestampRangeTest)."""

    def test_directory_run_continues_and_prints_summary(self) -> None:
        files = {
            "a-revocation-index.json": fixture_text_with(
                "revocation-list-valid.json", '"transparencyLogIndex": 1847300', '"transparencyLogIndex": 1e400'
            ),
            "b-inclusion-index.json": fixture_text_with(
                "transparency-inclusion-proof-valid.json", '"logIndex": 3,', '"logIndex": 1e400,'
            ),
            "c-tree-size.json": fixture_text_with(
                "transparency-log-sth.json", '"treeSize": 1847294,', '"treeSize": 1e400,'
            ),
            "d-expires-at.json": fixture_text_with(
                "trust-proof-baseline.json",
                '"expiresAt": "2026-05-24T06:00:00Z"',
                f'"expiresAt": "{OUT_OF_RANGE_TIMES[1]}"',
            ),
            "e-valid.json": (FIXTURES / "revocation-list-valid.json").read_text(),
        }
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                (Path(d) / name).write_text(text)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = verify.main(["verify.py", d])
        lines = out.getvalue().splitlines()
        observed = [ln.strip() for ln in lines if ln.strip().startswith("observed:")]
        self.assertEqual(code, 1)
        self.assertEqual(
            [ln.split()[0] for ln in lines if ln.startswith(("PASS", "FAIL"))],
            ["FAIL", "FAIL", "FAIL", "FAIL", "PASS"],
        )
        self.assertEqual(len(observed), 5, observed)
        for got, wanted in zip(observed, ("transparencyLogIndex", "logIndex", "treeSize", "bad expiresAt: ")):
            self.assertTrue(got.startswith("observed: REJECT[PARSE_ERROR"), got)
            self.assertIn(wanted, got)
        self.assertEqual(observed[-1], "observed: ACCEPT")
        self.assertEqual(lines[-1], "summary: 1 pass, 4 fail (5 fixtures)")


# A member name written twice into one JSON object of a committed ACCEPT
# fixture: old occurs once in the file and new replaces it. Inside a payload
# member the repeat is REJECT[PARSE_ERROR] naming the first repeated member
# in document order, whatever the values are; anywhere else in the document
# it is a load error. ../go/verify_test.go holds the same table.
REPEATED_NAMES: list[tuple[str, str, str, str, bool]] = [
    ("transparency-log-sth.json", '"treeSize": 1847294,', '"treeSize": "x", "treeSize": 1847294,', "signedTreeHead.treeSize", False),
    ("transparency-log-sth.json", '"treeSize": 1847294,', '"treeSize": 1847294, "treeSize": "x",', "signedTreeHead.treeSize", False),
    ("transparency-log-sth.json", '"treeSize": 1847294,', '"treeSize": 0, "treeSize": 1847294,', "signedTreeHead.treeSize", False),
    ("transparency-log-sth.json", '"treeSize": 1847294,', '"treeSize": 1847294, "treeSize": 1847294,', "signedTreeHead.treeSize", False),
    ("transparency-log-sth.json", '"treeSize": 1847294,', '"note": {"a": 1, "a": 2}, "treeSize": 1847294,', "signedTreeHead.note.a", False),
    ("transparency-log-sth.json", '"treeSize": 1847294,', '"note": {"b": 1, "b": 2}, "note": 3, "treeSize": 1847294,', "signedTreeHead.note.b", False),
    ("transparency-log-sth.json", '"treeSize": 1847294,', '"note": 3, "note": {"b": 1, "b": 2}, "treeSize": 1847294,', "signedTreeHead.note", False),
    ("transparency-log-sth.json", '"treeSize": 1847294,', '"note": 1e400, "treeSize": 1847294, "treeSize": 1847294,', "signedTreeHead.treeSize", False),
    ("trust-proof-baseline.json", '"trustLevel": 3,', '"trustLevel": 4, "trustLevel": 3,', "trustProof.trustLevel", False),
    ("revocation-list-valid.json", '"reason": "Supply chain compromise detected",', '"reason": "", "reason": "Supply chain compromise detected",', "revocationList.revocations[0].reason", False),
    ("transparency-inclusion-proof-valid.json", '"treeSize": 8,', '"treeSize": 8, "treeSize": 8,', "inclusionProof.signedTreeHead.treeSize", False),
    ("transparency-consistency-proof-valid.json", '"fromSize": 4,', '"fromSize": 4, "fromSize": 4,', "consistencyProof.fromSize", False),
    ("discovery-valid.json", '"trustProof": "/api/v1/trust/proof",', '"trustProof": "/x", "trustProof": "/api/v1/trust/proof",', "discoveryResponse.endpoints.trustProof", False),
    ("transparency-log-sth.json", '"expected": {', '"verifierState": {"clockRfc3339": "2026-05-24T00:00:00Z"}, "expected": {', "verifierState", True),
    ("transparency-log-sth.json", '"clockRfc3339": "2026-05-24T00:00:00Z",', '"clockRfc3339": "2026-05-24T00:00:00Z", "clockRfc3339": "2026-05-24T00:00:00Z",', "verifierState.clockRfc3339", True),
    ("transparency-log-sth.json", '"verifyResult": "ACCEPT"', '"verifyResult": "REJECT", "verifyResult": "ACCEPT"', "expected.verifyResult", True),
    ("transparency-log-sth.json", '"signedTreeHead": {', '"signedTreeHead": {}, "signedTreeHead": {', "signedTreeHead", True),
]


class RepeatedMemberNameTest(unittest.TestCase):
    """json.loads and the Go verifier's encoding/json read a repeated member
    name differently, so both verifiers refuse it with the same text:
    REJECT[PARSE_ERROR] inside a payload member and a load error elsewhere.
    The unmodified fixtures verify ACCEPT (SchemaTypeViolationTest checks
    each one)."""

    def test_repeated_member_name(self) -> None:
        for name, old, new, member, load_error in REPEATED_NAMES:
            with self.subTest(fixture=name, new=new):
                text = fixture_text_with(name, old, new)
                want = f"{member}: duplicate member name"
                if load_error:
                    with self.assertRaises(ValueError) as caught:
                        verify.parse_fixture(text)
                    self.assertEqual(str(caught.exception), want)
                else:
                    got = verify.verify_fixture(verify.parse_fixture(text))
                    self.assertFalse(got.accepted, str(got))
                    self.assertEqual(got.reject_category, "PARSE_ERROR", str(got))
                    self.assertEqual(got.reason, want)

    def test_repeat_nested_past_the_recursion_limit(self) -> None:
        depth = sys.getrecursionlimit() + 100
        note = "[" * depth + '{"a": 1, "a": 2}' + "]" * depth
        text = fixture_text_with(
            "transparency-log-sth.json", '"treeSize": 1847294,', f'"note": {note}, "treeSize": 1847294,'
        )
        try:
            doc = verify.parse_fixture(text)
        except RecursionError:
            self.skipTest("json.loads on this interpreter does not read the document")
        got = verify.verify_fixture(doc)
        self.assertEqual(got.reject_category, "PARSE_ERROR", str(got)[:200])
        self.assertEqual(got.reason, "signedTreeHead.note" + "[0]" * depth + ".a: duplicate member name")


def run_main(files: dict[str, str]) -> tuple[int, list[str]]:
    """verify.main over a directory holding files, with its exit code and
    output lines."""
    with tempfile.TemporaryDirectory() as d:
        for name, text in files.items():
            (Path(d) / name).write_text(text)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = verify.main(["verify.py", d])
    return code, out.getvalue().splitlines()


class VerifierStateTest(unittest.TestCase):
    """A problem in verifierState, the verifier's own configuration, is
    reported as the Go verifier reports it: a clockRfc3339 string that is
    not an RFC 3339 timestamp is REJECT[VERIFIER_CONFIG_ERROR], and a
    verifierState member of the wrong JSON type is a load error (or
    VERIFIER_CONFIG_ERROR for a fixture that did not come through
    parse_fixture). Neither is a PARSE_ERROR, which names a payload
    member."""

    def assert_config_error(self, got: verify.VerifyResult, reason: str) -> None:
        self.assertFalse(got.accepted, str(got))
        self.assertEqual(got.reject_category, "VERIFIER_CONFIG_ERROR", str(got))
        self.assertTrue(got.reason.startswith(reason), str(got))

    def test_bad_clock_string_is_config_error(self) -> None:
        for value in ("not-a-time", "", "2026-05-24 00:00:00Z", "2026-05-24T00:00:00", *OUT_OF_RANGE_TIMES):
            with self.subTest(value=value):
                fx = with_member(load("trust-proof-baseline.json"), "verifierState.clockRfc3339", json.dumps(value))
                self.assert_config_error(verify.verify_fixture(fx), "bad clockRfc3339: ")

    def test_wrong_type_member_is_a_load_error(self) -> None:
        for path, literal, label in (
            ("verifierState.clockRfc3339", "5", "verifierState.clockRfc3339"),
            ("verifierState.trustedIssuers", '"did:x"', "verifierState.trustedIssuers"),
            ("verifierState.trustedIssuers", "[7]", "verifierState.trustedIssuers[0]"),
            ("verifierState.publicKeys", "{}", "verifierState.publicKeys"),
            ("verifierState.publicKeys", "[true]", "verifierState.publicKeys[0]"),
            ("verifierState.publicKeys.0.publicKeyHex", "[]", "verifierState.publicKeys[0].publicKeyHex"),
            ("verifierState", "[]", "verifierState"),
        ):
            with self.subTest(path=path, literal=literal):
                fx = with_member(load("trust-proof-baseline.json"), path, literal)
                with self.assertRaises(ValueError) as caught:
                    verify.parse_fixture(json.dumps(fx))
                self.assertTrue(str(caught.exception).startswith(f"{label}: JSON "), str(caught.exception))
                self.assert_config_error(verify.verify_fixture(fx), f"{label}: JSON ")

    def test_null_and_absent_members_take_the_zero_value(self) -> None:
        # encoding/json leaves a struct field at its zero value for JSON null:
        # an empty clock is a bad clock, an empty trusted set trusts no issuer.
        fx = with_member(load("trust-proof-baseline.json"), "verifierState.clockRfc3339", "null")
        self.assert_config_error(verify.verify_fixture(verify.parse_fixture(json.dumps(fx))), "bad clockRfc3339: ")
        for literal in ("null", "{}"):
            with self.subTest(verifierState=literal):
                fx = with_member(load("trust-proof-baseline.json"), "verifierState", literal)
                got = verify.verify_fixture(verify.parse_fixture(json.dumps(fx)))
                self.assertEqual(got.reject_category, "VERIFIER_CONFIG_ERROR", str(got))
                fx = with_member(load("transparency-log-sth.json"), "verifierState", literal)
                got = verify.verify_fixture(verify.parse_fixture(json.dumps(fx)))
                self.assertEqual(got.reject_category, "SIGNATURE_INVALID", str(got))

    def test_non_hex_configured_key_is_skipped(self) -> None:
        fx = with_member(load("transparency-log-sth.json"), "verifierState.publicKeys.0.publicKeyHex", '"zz"')
        got = verify.verify_fixture(fx)
        self.assertEqual(got.reject_category, "SIGNATURE_INVALID", str(got))

    def test_directory_run_reports_load_error_and_config_error(self) -> None:
        code, lines = run_main(
            {
                "a-clock-number.json": fixture_text_with(
                    "trust-proof-baseline.json", '"clockRfc3339": "2026-05-24T00:00:00Z"', '"clockRfc3339": 5'
                ),
                "b-clock-string.json": fixture_text_with(
                    "trust-proof-baseline.json", '"clockRfc3339": "2026-05-24T00:00:00Z"', '"clockRfc3339": "not-a-time"'
                ),
                "c-valid.json": (FIXTURES / "trust-proof-baseline.json").read_text(),
            }
        )
        self.assertEqual(code, 1)
        results = [ln for ln in lines if ln.startswith(("PASS", "FAIL"))]
        self.assertEqual([ln.split()[0] for ln in results], ["FAIL", "FAIL", "PASS"])
        self.assertIn("(load error: verifierState.clockRfc3339: JSON number 5 does not fit the string", results[0])
        observed = [ln.strip() for ln in lines if ln.strip().startswith("observed:")]
        self.assertTrue(observed[0].startswith("observed: REJECT[VERIFIER_CONFIG_ERROR: bad clockRfc3339: "), observed[0])
        self.assertEqual(observed[1], "observed: ACCEPT")


# An integer literal longer than the 4300 digits int() converts by default.
LONG_INTEGER = "9" * 5000


class LongIntegerLiteralTest(unittest.TestCase):
    """An integer literal too long for int() is read, not a load error: in
    an integer or number member it is REJECT[PARSE_ERROR] naming the member,
    as the Go verifier reports it."""

    def test_long_integer_is_parse_error(self) -> None:
        for name, old, label, word in (
            (
                "revocation-list-valid.json",
                '"transparencyLogIndex": 1847300',
                "revocationList.revocations[0].transparencyLogIndex",
                "integer",
            ),
            ("trust-proof-baseline.json", '"trustScore": 0.825', "trustProof.trustScore", "number"),
            ("transparency-log-sth.json", '"treeSize": 1847294', "signedTreeHead.treeSize", "integer"),
        ):
            for literal in (LONG_INTEGER, "-" + LONG_INTEGER):
                with self.subTest(label=label, sign=literal[0]):
                    text = fixture_text_with(name, old, old.split(":")[0] + ": " + literal)
                    got = verify.verify_fixture(verify.parse_fixture(text))
                    self.assertEqual(got.reject_category, "PARSE_ERROR", str(got)[:200])
                    self.assertEqual(
                        got.reason, f"{label}: JSON number {literal} does not fit the {word} the schema requires"
                    )

    def test_directory_run_gives_a_verdict(self) -> None:
        code, lines = run_main(
            {
                "a.json": fixture_text_with(
                    "revocation-list-valid.json",
                    '"transparencyLogIndex": 1847300',
                    f'"transparencyLogIndex": {LONG_INTEGER}',
                )
            }
        )
        self.assertEqual(code, 1)
        observed = [ln.strip() for ln in lines if ln.strip().startswith("observed:")]
        self.assertEqual(len(observed), 1, lines[:3])
        self.assertTrue(observed[0].startswith("observed: REJECT[PARSE_ERROR: revocationList."), observed[0][:200])


class UnexpectedExceptionTest(unittest.TestCase):
    """An exception other than the ValueError and OverflowError a payload
    value raises is a defect in the verifier, not a PARSE_ERROR verdict:
    verify_fixture lets it propagate and main reports it with no verdict
    and goes on to the next fixture."""

    def test_unexpected_exception_is_not_a_verdict(self) -> None:
        def broken(fixture: dict[str, Any]) -> verify.VerifyResult:
            raise KeyError("boom")

        with unittest.mock.patch.object(verify, "verify_sth", broken):
            with self.assertRaises(KeyError):
                verify.verify_fixture(load("transparency-log-sth.json"))
            code, lines = run_main(
                {
                    "a-sth.json": (FIXTURES / "transparency-log-sth.json").read_text(),
                    "b-valid.json": (FIXTURES / "revocation-list-valid.json").read_text(),
                }
            )
        self.assertEqual(code, 1)
        results = [ln for ln in lines if ln.startswith(("PASS", "FAIL"))]
        self.assertEqual([ln.split()[0] for ln in results], ["FAIL", "PASS"])
        self.assertIn("(verifier error: KeyError: 'boom')", results[0])
        self.assertEqual(lines[-1], "summary: 1 pass, 1 fail (2 fixtures)")


if __name__ == "__main__":
    unittest.main()
