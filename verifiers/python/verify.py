#!/usr/bin/env python3
"""Python reference verifier for the ATP v1.0.0-rc1 conformance fixture set.

Depends only on the Python standard library plus the `cryptography` package
(for Ed25519 verification). Does NOT import any opena2a-* SDK. The goal is to
demonstrate that an independent verifier in a second language reaches the same
ACCEPT / REJECT verdict as the Go reference verifier for every fixture.

Spec coverage:
  - ATP v1.0.0-rc1 §4.4 trust proof verification (Steps 1-5)
  - ATP §4.3 canonical pipe-delimited 7-field signing form
  - ATP §5.6 Signed Tree Head verification (Ed25519 over raw rootHash bytes)
  - ATP §7.1 well-known discovery structural verification
  - wire shape: each payload member must carry the JSON type the vendored
    schema gives it (decoded with the Go verifier's rules), else the
    verdict is REJECT[PARSE_ERROR] naming the member
  - repeated member names: a JSON object that repeats a member name is
    REJECT[PARSE_ERROR] naming the member inside a payload member, and a
    load error elsewhere in the fixture document, as in the Go verifier

Out of scope:
  - ML-DSA-65 verification. The post-quantum Python library landscape is
    fragmented (no stdlib support, liboqs / dilithium-py require optional
    native dependencies). The hybrid fixture is annotated and accepted on
    the Ed25519 path alone; the ML-DSA-65 signature is recorded as present
    but its verification is not attempted. For spec-mandate full hybrid
    verification, run the Go reference verifier in ../go.

Usage:
    python verify.py ../../fixtures/trust-proof-baseline.json
    python verify.py ../../fixtures
    python verify.py ../..                 # repo root; walks fixtures/*.json

Exit 0 iff every fixture's observed result matches expected.verifyResult.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write(
        "missing dependency: cryptography. install with `pip install -r requirements.txt`\n"
    )
    sys.exit(2)


SUPPORTED_VERSION = "1.0"
VALID_VERDICTS = {"passed", "warning", "blocked", "listed", "verified", "unknown"}
VALID_KEY_STATUS = {"active", "retired", "revoked"}


@dataclass
class VerifyResult:
    accepted: bool = False
    reject_category: str = ""
    reason: str = ""
    ed25519_valid: bool = False
    mldsa65_present: bool = False
    mldsa65_skipped: bool = False
    sigs_expected: int = 0
    sigs_valid: int = 0

    def __str__(self) -> str:
        if self.accepted:
            return "ACCEPT"
        return f"REJECT[{self.reject_category}: {self.reason}]"


def canonical_proof_payload(tp: dict[str, Any]) -> bytes:
    """Mirror generator/main.go canonicalProofPayload VERBATIM. tp is the
    trust proof as _decode returns it, so trustLevel is already an int and
    trustScore a float: the wire types are checked by _decode rather than
    coerced here."""
    return (
        f"{tp['did']}|"
        f"{tp['trustLevel']}|"
        f"{tp['trustScore']:.6f}|"
        f"{tp['verdict']}|"
        f"{_normalize_rfc3339(tp['issuedAt'])}|"
        f"{_normalize_rfc3339(tp['expiresAt'])}|"
        f"{tp['issuerDid']}"
    ).encode("utf-8")


def sth_signed_bytes(root_hash: str) -> bytes:
    """Literal reading of ATP §5.6: strip "SHA256:" prefix, hex-decode 32 raw bytes."""
    stripped = root_hash[len("SHA256:"):] if root_hash.startswith("SHA256:") else root_hash
    raw = bytes.fromhex(stripped)
    if len(raw) != 32:
        raise ValueError(f"rootHash must decode to 32 bytes, got {len(raw)}")
    return raw


def _normalize_rfc3339(s: str) -> str:
    s2 = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s2).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def index_public_keys(refs: list[dict[str, Any]]):
    eds: list[Ed25519PublicKey] = []
    mldsa_present = False
    for r in refs:
        if r["algorithm"] == "Ed25519":
            raw = bytes.fromhex(r["publicKeyHex"])
            if len(raw) != 32:
                continue
            eds.append(Ed25519PublicKey.from_public_bytes(raw))
        elif r["algorithm"] == "ML-DSA-65":
            mldsa_present = True
    return eds, mldsa_present


# ---------------------------------------------------------------------------
# wire shape
#
# The Go verifier decodes each payload member into a typed struct, so a
# member whose JSON type does not fit (a string where the schema says
# integer, a number with a fraction or exponent in an integer member, an
# array where a string is expected) does not reach its verification steps.
# The tables below mirror those struct types and _decode applies the same
# rules before the steps run, so both verifiers return REJECT[PARSE_ERROR]
# for the same wire values instead of this verifier coercing them with
# int() / float() or testing strings by duck typing.
#
# Leaf kinds:
#   "string"   a JSON string
#   "integer"  a JSON number written without fraction or exponent that fits
#              a signed 64-bit integer (the Go verifier's int64)
#   "?integer" the same, for a member the spec makes optional: absent and
#              null both decode to None, apart from 0 (the Go verifier's
#              *int64)
#   "number"   a JSON number that fits a binary64 float (the Go verifier's
#              float64)
# A one-element list is a JSON array of that shape. A dict is a JSON object:
# a listed member that is absent takes the Go zero value ("", 0, 0.0, [] or
# {}), a nested object member that is absent or null decodes to None (a nil
# pointer, which the verification steps report as missing), and unlisted
# members are ignored, as encoding/json does. A member is listed only under
# its exact name, so TreeSize is an unlisted member and treeSize stays
# absent; the Go verifier's exactMembers leaves such a member out before
# encoding/json, which matches names case-insensitively, decodes the
# object. {"*": shape} is a JSON object whose values each have that shape.
#
# JSON null is a value of no schema type, so a null member, array element or
# object value is REJECT[PARSE_ERROR] like any other wrong type rather than
# the zero value encoding/json would decode it to: revocations null is not an
# empty revocation list. Only a "?integer" member and a nested object member
# take null, as absent; the Go verifier's nullMember draws the same line at
# its pointer fields.
# ---------------------------------------------------------------------------

_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1

_STH_SHAPE: dict[str, Any] = {
    "treeSize": "integer",
    "timestamp": "string",
    "rootHash": "string",
    "signedBy": "string",
    "signature": "string",
}
_TRUST_PROOF_SHAPE: dict[str, Any] = {
    "did": "string",
    "trustLevel": "integer",
    "trustScore": "number",
    "verdict": "string",
    "issuedAt": "string",
    "expiresAt": "string",
    "issuerDid": "string",
    "signatures": [{"keyId": "string", "algorithm": "string", "value": "string"}],
    "transparencyLogIndex": "?integer",
}
_DISCOVERY_SHAPE: dict[str, Any] = {
    "authorityDid": "string",
    "version": "string",
    "conformanceLevel": "integer",
    "endpoints": {"*": "string"},
    "publicKeys": [
        {
            "keyId": "string",
            "algorithm": "string",
            "publicKeyHex": "string",
            "status": "string",
            "validFrom": "string",
        }
    ],
    "supportedMethods": ["string"],
    "capabilities": ["string"],
}
_INCLUSION_PROOF_SHAPE: dict[str, Any] = {
    "logIndex": "integer",
    "leafHash": "string",
    "auditPath": ["string"],
    "signedTreeHead": _STH_SHAPE,
}
_CONSISTENCY_PROOF_SHAPE: dict[str, Any] = {
    "fromSize": "integer",
    "toSize": "integer",
    "consistencyPath": ["string"],
    "fromSignedTreeHead": _STH_SHAPE,
    "toSignedTreeHead": _STH_SHAPE,
}
_REVOCATION_LIST_SHAPE: dict[str, Any] = {
    "revocations": [
        {
            "agentDid": "string",
            "revokedAt": "string",
            "reason": "string",
            "transparencyLogIndex": "?integer",
            "revokedByKeyId": "string",
        }
    ],
    "nextSince": "string",
}


class ShapeError(ValueError):
    """A wire value whose JSON type or range does not fit its member's shape."""


def _json_kind(value: Any) -> str:
    """The JSON type of a decoded value, with the literal for numbers, in the
    words the Go verifier's decode error uses."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return f"number {json.dumps(value)}"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def _absent(shape: Any) -> Any:
    """What a member absent from its object decodes to: the Go zero value of
    its shape, or None for an optional integer and a nested object (a nil
    pointer in the Go verifier)."""
    if isinstance(shape, str):
        return {"string": "", "integer": 0, "?integer": None, "number": 0.0}[shape]
    if isinstance(shape, list):
        return []
    if "*" in shape:
        return {}
    return None


def _null_error(label: str, shape: Any) -> ShapeError:
    """The type violation for a JSON null where shape does not take one."""
    if isinstance(shape, str):
        word = shape.lstrip("?")
    elif isinstance(shape, list):
        word = "array"
    else:
        word = "object"
    return ShapeError(f"{label}: JSON null does not fit the {word} the schema requires")


def _decode(label: str, value: Any, shape: Any) -> Any:
    """Decode one wire value against its shape the way the Go verifier
    decodes it. Raises ShapeError naming the member."""
    if value is None:
        if shape == "?integer" or (isinstance(shape, dict) and "*" not in shape):
            return None
        raise _null_error(label, shape)
    if isinstance(shape, str):
        kind = shape.lstrip("?")
        if kind == "string":
            if isinstance(value, str):
                return value
        elif kind == "integer":
            if isinstance(value, int) and not isinstance(value, bool) and _INT64_MIN <= value <= _INT64_MAX:
                return value
        elif kind == "number":
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                try:
                    number = float(value)
                except OverflowError:
                    number = math.inf
                if math.isfinite(number):
                    return number
        raise ShapeError(f"{label}: JSON {_json_kind(value)} does not fit the {kind} the schema requires")
    # An array element or an object value is never optional, so a null one is
    # a type violation even where its shape is a nested object.
    if isinstance(shape, list):
        if not isinstance(value, list):
            raise ShapeError(f"{label}: JSON {_json_kind(value)} does not fit the array the schema requires")
        decoded = []
        for i, item in enumerate(value):
            if item is None:
                raise _null_error(f"{label}[{i}]", shape[0])
            decoded.append(_decode(f"{label}[{i}]", item, shape[0]))
        return decoded
    if "*" in shape:
        if not isinstance(value, dict):
            raise ShapeError(f"{label}: JSON {_json_kind(value)} does not fit the object the schema requires")
        decoded_values = {}
        for key, item in value.items():
            if item is None:
                raise _null_error(f"{label}.{key}", shape["*"])
            decoded_values[key] = _decode(f"{label}.{key}", item, shape["*"])
        return decoded_values
    if not isinstance(value, dict):
        raise ShapeError(f"{label}: JSON {_json_kind(value)} does not fit the object the schema requires")
    return {
        key: _decode(f"{label}.{key}", value[key], sub) if key in value else _absent(sub)
        for key, sub in shape.items()
    }


# ---------------------------------------------------------------------------
# repeated member names
#
# RFC 8259 §4 leaves the meaning of a member name that one JSON object repeats
# to the receiver, and the two verifiers' decoders read it differently:
# json.loads keeps only the last occurrence, where the Go verifier's
# encoding/json decodes the occurrences into the same field one after
# another, so the members of an earlier object occurrence survive and the
# first type error is the one reported. Both verifiers refuse such a document
# instead, as RFC 7493 §2.3 requires of I-JSON, so neither verifies its own
# reading of it: a repeat inside a payload member is REJECT[PARSE_ERROR]
# naming the member, and a repeat elsewhere in the fixture document is a
# load error.
# ---------------------------------------------------------------------------

# The fixture members _decode_payload decodes: the protocol response under
# test. The Go verifier's payloadMembers holds the same names.
_PAYLOAD_MEMBERS = frozenset(
    {"discoveryResponse", "trustProof", "signedTreeHead", "inclusionProof", "consistencyProof", "revocationList"}
)


class _JSONObject(dict):
    """A JSON object as parse_fixture reads it: the dict json.loads builds,
    in which the last occurrence of a repeated member name wins, with pairs
    holding every member in document order, repeats included."""

    pairs: list[tuple[str, Any]]

    @classmethod
    def from_pairs(cls, pairs: list[tuple[str, Any]]) -> _JSONObject:
        obj = cls(pairs)
        obj.pairs = pairs
        return obj


def _repeated_member(label: str, value: Any, skip: frozenset[str] = frozenset()) -> str:
    """The first member name, in document order, that a JSON object in value
    repeats, named the way _decode names members (object.member,
    array[index]; a top-level member with an empty label is its bare name),
    or "" when no object repeats a name. The same walk as the Go verifier's
    repeatedMember. A dict that json.loads built without parse_fixture's
    hook has no pairs and holds no repeats. The value of a member whose path
    is in skip is not walked."""
    # An explicit stack rather than recursion, so a deeply nested document
    # cannot raise RecursionError here. Each entry walks one array or object:
    # its path, an iterator over its (index or name, value) pairs, and the
    # member names seen so far (None for an array).
    stack: list[tuple[str, Any, set[str] | None]] = []

    def enter(path: str, item: Any) -> None:
        if isinstance(item, list):
            stack.append((path, iter(enumerate(item)), None))
        elif isinstance(item, dict):
            pairs = item.pairs if isinstance(item, _JSONObject) else item.items()
            stack.append((path, iter(pairs), set()))

    enter(label, value)
    while stack:
        path, members, seen = stack[-1]
        step = next(members, None)
        if step is None:
            stack.pop()
            continue
        key, item = step
        if seen is None:
            item_path = f"{path}[{key}]"
        else:
            item_path = f"{path}.{key}" if path else key
            if key in seen:
                return item_path
            seen.add(key)
        if item_path not in skip:
            enter(item_path, item)
    return ""


def _decode_payload(fixture: dict[str, Any], label: str, shape: dict[str, Any]) -> Any:
    """_decode for the payload member label of fixture, after checking, as
    the Go verifier's decodePayload does first, that no JSON object in it
    repeats a member name. Raises ShapeError naming the member."""
    value = fixture.get(label)
    repeated = _repeated_member(label, value)
    if repeated:
        raise ShapeError(f"{repeated}: duplicate member name")
    return _decode(label, value, shape)


# ---------------------------------------------------------------------------
# per-type verifiers
# ---------------------------------------------------------------------------

def verify_discovery(fixture: dict[str, Any]) -> VerifyResult:
    try:
        d = _decode_payload(fixture, "discoveryResponse", _DISCOVERY_SHAPE)
    except ShapeError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    if d is None:
        return VerifyResult(reject_category="PARSE_ERROR", reason="discoveryResponse missing")

    if not d["authorityDid"]:
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason="authorityDid missing")
    if not d["version"]:
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason="version missing")
    if d["version"] != SUPPORTED_VERSION:
        return VerifyResult(
            reject_category="UNSUPPORTED_VERSION",
            reason=f"unsupported atp version {d['version']!r} (this verifier supports {SUPPORTED_VERSION})",
        )
    cl = d["conformanceLevel"]
    if not (1 <= cl <= 3):
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason=f"conformanceLevel {cl} out of range [1,3]")
    if not d["endpoints"]:
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason="endpoints missing")
    if not d["publicKeys"]:
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason="publicKeys missing")

    vs = fixture["verifierState"]
    if d["authorityDid"] not in vs.get("trustedIssuers", []):
        return VerifyResult(
            reject_category="UNTRUSTED_ISSUER",
            reason=f"authority DID {d['authorityDid']} is not in the verifier's trusted set",
        )

    for i, pk in enumerate(d["publicKeys"]):
        algo = pk["algorithm"]
        if algo == "Ed25519":
            try:
                raw = bytes.fromhex(pk["publicKeyHex"])
            except ValueError:
                return VerifyResult(
                    reject_category="DISCOVERY_INVALID",
                    reason=f"publicKeys[{i}] Ed25519 publicKeyHex not hex",
                )
            if len(raw) != 32:
                return VerifyResult(
                    reject_category="DISCOVERY_INVALID",
                    reason=f"publicKeys[{i}] Ed25519 publicKeyHex invalid (need 32 bytes)",
                )
        elif algo == "ML-DSA-65":
            try:
                bytes.fromhex(pk["publicKeyHex"])
            except ValueError:
                return VerifyResult(
                    reject_category="DISCOVERY_INVALID",
                    reason=f"publicKeys[{i}] ML-DSA-65 publicKeyHex not hex",
                )
            # Structural-only: ML-DSA-65 parse-validation is out of scope here;
            # the Go verifier performs the full UnmarshalBinary check.
        else:
            return VerifyResult(
                reject_category="DISCOVERY_INVALID",
                reason=f"publicKeys[{i}] unsupported algorithm {algo!r}",
            )
        if pk["status"] not in VALID_KEY_STATUS:
            return VerifyResult(
                reject_category="DISCOVERY_INVALID",
                reason=f"publicKeys[{i}] status {pk['status']!r} not in {sorted(VALID_KEY_STATUS)}",
            )

    return VerifyResult(accepted=True)


def verify_trust_proof(fixture: dict[str, Any]) -> VerifyResult:
    try:
        tp = _decode_payload(fixture, "trustProof", _TRUST_PROOF_SHAPE)
    except ShapeError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    if tp is None:
        return VerifyResult(reject_category="PARSE_ERROR", reason="trustProof missing")
    # transparencyLogIndex sits outside the §4.3 signed form and is not read
    # here, but the schema says integer, minimum 0: a negative index is a
    # malformed proof, not a proof to verify. The member is optional, so an
    # absent or null index is not checked.
    log_index = tp["transparencyLogIndex"]
    if log_index is not None and log_index < 0:
        return VerifyResult(
            reject_category="PARSE_ERROR",
            reason=f"trustProof.transparencyLogIndex {log_index} must be >= 0",
        )
    vs = fixture["verifierState"]
    now = datetime.fromisoformat(vs["clockRfc3339"].replace("Z", "+00:00")).astimezone(timezone.utc)

    # Step 1: expiry.
    try:
        expires = datetime.fromisoformat(tp["expiresAt"].replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=f"bad expiresAt: {exc}")
    if now > expires:
        return VerifyResult(
            reject_category="EXPIRED",
            reason=f"expired at {expires.strftime('%Y-%m-%dT%H:%M:%SZ')}, verifier clock is {now.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        )

    # Step 2: issuer trust.
    if tp["issuerDid"] not in vs.get("trustedIssuers", []):
        return VerifyResult(
            reject_category="UNTRUSTED_ISSUER",
            reason=f"issuer DID {tp['issuerDid']} is not in the verifier's trusted set",
        )

    # Step 5 semantic.
    tl = tp["trustLevel"]
    if not (0 <= tl <= 4):
        return VerifyResult(reject_category="SEMANTIC_INVALID", reason=f"trustLevel {tl} out of range [0,4]")
    ts = tp["trustScore"]
    if not (0.0 <= ts <= 1.0):
        return VerifyResult(reject_category="SEMANTIC_INVALID", reason=f"trustScore {ts:.6f} out of range [0.0,1.0]")
    if tp["verdict"] not in VALID_VERDICTS:
        return VerifyResult(reject_category="SEMANTIC_INVALID", reason=f"verdict {tp['verdict']} not in {sorted(VALID_VERDICTS)}")
    try:
        issued = datetime.fromisoformat(tp["issuedAt"].replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=f"bad issuedAt: {exc}")
    if issued >= expires:
        return VerifyResult(reject_category="SEMANTIC_INVALID", reason="issuedAt must be before expiresAt")
    # ATP §4.4 step 5, §10.2 maximum: the declared window may not exceed
    # 24 hours. Exact comparison, no skew tolerance (§10.2: the skew bound
    # MUST NOT extend the 24-hour validity), whatever the verifier's clock.
    if expires - issued > timedelta(hours=24):
        return VerifyResult(reject_category="SEMANTIC_INVALID", reason="validity window exceeds 24 hours")

    # Steps 3-4: signature.
    payload = canonical_proof_payload(tp)
    eds, _ = index_public_keys(vs["publicKeys"])
    result = VerifyResult(sigs_expected=len(tp["signatures"]))

    for sig in tp["signatures"]:
        try:
            sig_bytes = base64.b64decode(sig["value"])
        except Exception as exc:
            return VerifyResult(
                reject_category="SIGNATURE_INVALID",
                reason=f"signature {sig.get('keyId')} has invalid base64: {exc}",
            )
        if sig["algorithm"] == "Ed25519":
            verified = False
            for pk in eds:
                try:
                    pk.verify(sig_bytes, payload)
                    verified = True
                    break
                except InvalidSignature:
                    continue
            if not verified:
                return VerifyResult(
                    reject_category="SIGNATURE_INVALID",
                    reason=f"Ed25519 signature {sig.get('keyId')} did not verify against any configured public key",
                )
            result.ed25519_valid = True
            result.sigs_valid += 1
        elif sig["algorithm"] == "ML-DSA-65":
            # Out of scope for this Python reference verifier. Recorded as present.
            result.mldsa65_present = True
            result.mldsa65_skipped = True
        else:
            return VerifyResult(
                reject_category="SIGNATURE_INVALID",
                reason=f"unsupported signature algorithm {sig['algorithm']}",
            )

    if not result.ed25519_valid:
        return VerifyResult(reject_category="SIGNATURE_INVALID", reason="no valid Ed25519 signature (ATP §4.3 baseline)")

    result.accepted = True
    return result


def verify_sth(fixture: dict[str, Any]) -> VerifyResult:
    try:
        sth = _decode_payload(fixture, "signedTreeHead", _STH_SHAPE)
    except ShapeError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    if sth is None:
        return VerifyResult(reject_category="PARSE_ERROR", reason="signedTreeHead missing")
    vs = fixture["verifierState"]

    if sth["treeSize"] <= 0:
        return VerifyResult(reject_category="STH_INVALID", reason=f"treeSize {sth['treeSize']} must be > 0")
    try:
        datetime.fromisoformat(sth["timestamp"].replace("Z", "+00:00"))
    except ValueError as exc:
        return VerifyResult(reject_category="STH_INVALID", reason=f"bad timestamp: {exc}")
    try:
        root_bytes = sth_signed_bytes(sth["rootHash"])
    except ValueError as exc:
        return VerifyResult(reject_category="STH_INVALID", reason=str(exc))
    try:
        sig_bytes = base64.b64decode(sth["signature"])
    except Exception as exc:
        return VerifyResult(reject_category="SIGNATURE_INVALID", reason=f"STH signature has invalid base64: {exc}")

    eds, _ = index_public_keys(vs["publicKeys"])
    for pk in eds:
        try:
            pk.verify(sig_bytes, root_bytes)
            return VerifyResult(accepted=True, ed25519_valid=True, sigs_expected=1, sigs_valid=1)
        except InvalidSignature:
            continue
    return VerifyResult(reject_category="SIGNATURE_INVALID", reason="STH Ed25519 signature did not verify against any configured public key")


# ---------------------------------------------------------------------------
# RFC 6962 Merkle verification (ATP §5.4/§5.5)
#
# leaf = SHA-256(0x00 || entry), node = SHA-256(0x01 || left || right).
# Verification follows RFC 9162 §2.1.3.2 (inclusion) and §2.1.4.2
# (consistency). VERBATIM mirror of the Go verifier.
# ---------------------------------------------------------------------------

def _merkle_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _wire_hash_bytes(wire: str) -> bytes:
    """Decodes a "SHA256:<64 lowercase hex>" wire hash."""
    if not wire.startswith("SHA256:"):
        raise ValueError(f"hash {wire!r} missing SHA256: prefix")
    raw = bytes.fromhex(wire[len("SHA256:"):])
    if len(raw) != 32:
        raise ValueError(f"hash {wire!r} must decode to 32 bytes, got {len(raw)}")
    return raw


def _verify_merkle_inclusion(leaf_index: int, tree_size: int, leaf_hash: bytes, path: list[bytes], root: bytes) -> bool:
    if leaf_index < 0 or tree_size < 1 or leaf_index >= tree_size:
        return False
    fn, sn = leaf_index, tree_size - 1
    r = leaf_hash
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = _merkle_node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _merkle_node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _verify_merkle_consistency(from_size: int, to_size: int, path: list[bytes], from_root: bytes, to_root: bytes) -> bool:
    if from_size < 1 or from_size > to_size:
        return False
    if from_size == to_size:
        return len(path) == 0 and from_root == to_root
    full = list(path)
    if from_size & (from_size - 1) == 0:
        full = [from_root] + full
    if not full:
        return False
    fn, sn = from_size - 1, to_size - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1
    fr = sr = full[0]
    for c in full[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = _merkle_node_hash(c, fr)
            sr = _merkle_node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _merkle_node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == from_root and sr == to_root


def _check_embedded_sth(label: str, sth: dict[str, Any] | None, keys: list[dict[str, Any]]) -> tuple[str, str]:
    """Validates a tree head embedded in a §5.4/§5.5 payload — same rules as
    verify_sth, factored so the proof verifiers stay behaviorally identical.
    sth is the head as _decode returns it (None when absent or null).
    Returns (category, reason); empty category means the head verifies."""
    if sth is None:
        return ("PARSE_ERROR", f"{label} missing")
    if sth["treeSize"] <= 0:
        return ("STH_INVALID", f"{label}.treeSize {sth['treeSize']} must be > 0")
    try:
        datetime.fromisoformat(sth["timestamp"].replace("Z", "+00:00"))
    except ValueError as exc:
        return ("STH_INVALID", f"{label} bad timestamp: {exc}")
    try:
        root_bytes = sth_signed_bytes(sth["rootHash"])
    except ValueError as exc:
        return ("STH_INVALID", f"{label}: {exc}")
    try:
        sig_bytes = base64.b64decode(sth["signature"])
    except Exception as exc:  # noqa: BLE001 - any decode failure is the same verdict
        return ("SIGNATURE_INVALID", f"{label} signature has invalid base64: {exc}")
    eds, _ = index_public_keys(keys)
    for pk in eds:
        try:
            pk.verify(sig_bytes, root_bytes)
            return ("", "")
        except InvalidSignature:
            continue
    return ("SIGNATURE_INVALID", f"{label} Ed25519 signature did not verify against any configured public key")


def verify_inclusion_proof(fixture: dict[str, Any]) -> VerifyResult:
    """ATP §5.4: embedded tree head per §5.6, then RFC 9162 §2.1.3.2
    recomputation from leafHash along auditPath must reproduce sth.rootHash."""
    try:
        ip = _decode_payload(fixture, "inclusionProof", _INCLUSION_PROOF_SHAPE)
    except ShapeError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    if ip is None:
        return VerifyResult(reject_category="PARSE_ERROR", reason="inclusionProof missing")
    vs = fixture["verifierState"]

    try:
        leaf = _wire_hash_bytes(ip["leafHash"])
        path = [_wire_hash_bytes(p) for p in ip["auditPath"]]
    except ValueError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    sth = ip["signedTreeHead"]
    cat, reason = _check_embedded_sth("signedTreeHead", sth, vs["publicKeys"])
    if cat:
        return VerifyResult(reject_category=cat, reason=reason)
    try:
        root = _wire_hash_bytes(sth["rootHash"])
    except ValueError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    log_index = ip["logIndex"]
    tree_size = sth["treeSize"]
    if log_index < 0 or log_index >= tree_size:
        return VerifyResult(reject_category="PARSE_ERROR", reason=f"logIndex {log_index} out of range for treeSize {tree_size}")
    if not _verify_merkle_inclusion(log_index, tree_size, leaf, path, root):
        return VerifyResult(reject_category="PROOF_INVALID", reason="recomputed root from leafHash along auditPath does not equal signedTreeHead.rootHash")
    return VerifyResult(accepted=True, ed25519_valid=True, sigs_expected=1, sigs_valid=1)


def verify_consistency_proof(fixture: dict[str, Any]) -> VerifyResult:
    """ATP §5.5: both embedded tree heads per §5.6, then RFC 9162 §2.1.4.2
    must reproduce both roots."""
    try:
        cp = _decode_payload(fixture, "consistencyProof", _CONSISTENCY_PROOF_SHAPE)
    except ShapeError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    if cp is None:
        return VerifyResult(reject_category="PARSE_ERROR", reason="consistencyProof missing")
    vs = fixture["verifierState"]

    from_sth = cp["fromSignedTreeHead"]
    to_sth = cp["toSignedTreeHead"]
    if from_sth is None or to_sth is None:
        return VerifyResult(reject_category="PARSE_ERROR", reason="fromSignedTreeHead/toSignedTreeHead missing")
    from_size = cp["fromSize"]
    to_size = cp["toSize"]
    if from_size != from_sth["treeSize"] or to_size != to_sth["treeSize"]:
        return VerifyResult(reject_category="PARSE_ERROR", reason="fromSize/toSize must equal the embedded tree heads' treeSize values")
    if from_size >= to_size:
        return VerifyResult(reject_category="PARSE_ERROR", reason=f"fromSize {from_size} must be < toSize {to_size}")
    try:
        path = [_wire_hash_bytes(p) for p in cp["consistencyPath"]]
    except ValueError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    for label, sth in (("fromSignedTreeHead", from_sth), ("toSignedTreeHead", to_sth)):
        cat, reason = _check_embedded_sth(label, sth, vs["publicKeys"])
        if cat:
            return VerifyResult(reject_category=cat, reason=reason)
    try:
        from_root = _wire_hash_bytes(from_sth["rootHash"])
        to_root = _wire_hash_bytes(to_sth["rootHash"])
    except ValueError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    if not _verify_merkle_consistency(from_size, to_size, path, from_root, to_root):
        return VerifyResult(reject_category="PROOF_INVALID", reason="consistencyPath does not connect fromSignedTreeHead.rootHash to toSignedTreeHead.rootHash (append-only claim broken)")
    return VerifyResult(accepted=True, ed25519_valid=True, sigs_expected=2, sigs_valid=2)


def verify_revocation_list(fixture: dict[str, Any]) -> VerifyResult:
    """ATP §8.1: structural verification of the unsigned revocation body. A
    malformed timestamp rejects the WHOLE response — skipping unparseable
    entries keeps a revoked agent trusted."""
    try:
        rl = _decode_payload(fixture, "revocationList", _REVOCATION_LIST_SHAPE)
    except ShapeError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=str(exc))
    if rl is None:
        return VerifyResult(reject_category="PARSE_ERROR", reason="revocationList missing")

    def _parse_rfc3339_strict(value: str) -> None:
        # Python's fromisoformat accepts a space separator and zone-less
        # timestamps; the wire rule is RFC 3339 (as Go's time.RFC3339 layout
        # enforces), so require the 'T' separator and a zone designator.
        if "T" not in value:
            raise ValueError("missing 'T' date/time separator")
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("missing zone designator")

    next_since = rl["nextSince"]
    if not next_since:
        return VerifyResult(reject_category="PARSE_ERROR", reason="nextSince missing")
    try:
        _parse_rfc3339_strict(next_since)
    except ValueError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=f"nextSince is not RFC 3339: {exc}")
    for i, entry in enumerate(rl["revocations"]):
        agent_did = entry["agentDid"]
        if not agent_did.startswith("did:"):
            return VerifyResult(reject_category="PARSE_ERROR", reason=f"revocations[{i}].agentDid {agent_did!r} is not a DID")
        try:
            _parse_rfc3339_strict(entry["revokedAt"])
        except ValueError as exc:
            return VerifyResult(reject_category="PARSE_ERROR", reason=f"revocations[{i}].revokedAt is not RFC 3339: {exc}")
        if not entry["reason"]:
            return VerifyResult(reject_category="PARSE_ERROR", reason=f"revocations[{i}].reason missing")
        # transparencyLogIndex is optional: an absent (or null) index does not
        # reject the entry or the response. A present index must be >= 0.
        log_index = entry["transparencyLogIndex"]
        if log_index is not None and log_index < 0:
            return VerifyResult(reject_category="PARSE_ERROR", reason=f"revocations[{i}].transparencyLogIndex must be >= 0")
        if "#" not in entry["revokedByKeyId"]:
            return VerifyResult(reject_category="PARSE_ERROR", reason=f"revocations[{i}].revokedByKeyId is not fragment-qualified")
    return VerifyResult(accepted=True)


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def verify_fixture(fixture: dict[str, Any]) -> VerifyResult:
    # A member of the wrong JSON type (null, a string where an integer is
    # required, a number where an object is required) surfaces as one of
    # these exceptions inside the per-type verifiers, and so does a timestamp
    # whose UTC equivalent falls outside the years 1 to 9999 that datetime
    # holds (OverflowError from astimezone). It is a PARSE_ERROR for this
    # fixture, not a reason to abort the run.
    try:
        return _verify_fixture(fixture)
    except (TypeError, ValueError, AttributeError, KeyError, IndexError, OverflowError) as exc:
        ft = fixture.get("fixtureType") if isinstance(fixture, dict) else None
        return VerifyResult(
            reject_category="PARSE_ERROR",
            reason=f"malformed {ft or 'fixture'} member: {type(exc).__name__}: {exc}",
        )


def _verify_fixture(fixture: dict[str, Any]) -> VerifyResult:
    ft = fixture.get("fixtureType")
    if ft == "discovery":
        return verify_discovery(fixture)
    if ft == "trustProof":
        return verify_trust_proof(fixture)
    if ft == "sth":
        return verify_sth(fixture)
    if ft == "inclusionProof":
        return verify_inclusion_proof(fixture)
    if ft == "consistencyProof":
        return verify_consistency_proof(fixture)
    if ft == "revocationList":
        return verify_revocation_list(fixture)
    return VerifyResult(reject_category="PARSE_ERROR", reason=f"unknown fixtureType {ft!r}")


def _reject_non_finite(literal: str) -> Any:
    # json.loads would otherwise read the NaN, Infinity and -Infinity
    # extensions, which the JSON grammar and the Go verifier's decoder refuse.
    raise ValueError(f"{literal} is not a JSON value")


def parse_fixture(text: str) -> dict[str, Any]:
    """Parses a fixture document with the Go verifier's acceptance: the
    document must be a JSON object, may not use the NaN / Infinity
    extensions, and may not hold a JSON object outside the payload members
    that repeats a member name (a repeat inside one is a PARSE_ERROR verdict
    from _decode_payload). A document this refuses is a load error, not a
    verdict."""
    fixture = json.loads(text, object_pairs_hook=_JSONObject.from_pairs, parse_constant=_reject_non_finite)
    if not isinstance(fixture, dict):
        raise ValueError(f"top-level JSON value is {type(fixture).__name__}, not an object")
    repeated = _repeated_member("", fixture, _PAYLOAD_MEMBERS)
    if repeated:
        raise ValueError(f"{repeated}: duplicate member name")
    return fixture


def load_fixture(path: Path) -> dict[str, Any]:
    return parse_fixture(path.read_text())


def expand_paths(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args:
        p = Path(a)
        if not p.exists():
            raise FileNotFoundError(a)
        if p.is_dir():
            fixtures_dir = p / "fixtures"
            target = fixtures_dir if fixtures_dir.is_dir() else p
            out.extend(sorted(target.glob("*.json")))
        else:
            out.append(p)
    return sorted(set(out))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: verify.py <fixture.json|dir>...\n")
        return 2
    try:
        paths = expand_paths(argv[1:])
    except FileNotFoundError as exc:
        sys.stderr.write(f"error: path not found: {exc}\n")
        return 2
    if not paths:
        sys.stderr.write("no fixture *.json files found\n")
        return 2

    total_pass = total_fail = 0
    for p in paths:
        try:
            fixture = load_fixture(p)
        except Exception as exc:
            print(f"FAIL  {p}  (load error: {exc})")
            total_fail += 1
            continue

        got = verify_fixture(fixture)
        expected = fixture.get("expected")
        if not isinstance(expected, dict):
            expected = {}
        want_accept = str(expected.get("verifyResult", "")).upper() == "ACCEPT"

        ok = (want_accept and got.accepted) or (not want_accept and not got.accepted)
        if ok and not want_accept and expected.get("rejectCategory"):
            ok = got.reject_category == expected["rejectCategory"]
        if ok and not want_accept and expected.get("reasonContains"):
            ok = str(expected["reasonContains"]).lower() in got.reason.lower()

        status = "PASS" if ok else "FAIL"
        if ok:
            total_pass += 1
        else:
            total_fail += 1

        try:
            rel = p.relative_to(Path.cwd())
        except ValueError:
            rel = p
        print(f"{status}  {rel}  [{fixture.get('fixtureType', '?')}]")
        print(f"       expected: {expected.get('verifyResult', '')}", end="")
        if expected.get("rejectCategory"):
            print(f" [{expected['rejectCategory']}]")
        else:
            print()
        print(f"       observed: {got}")
        if got.sigs_expected:
            mldsa_note = ""
            if got.mldsa65_present:
                mldsa_note = " (ML-DSA-65 present, verification out of scope for this Python reference; use Go verifier for full hybrid)"
            print(
                f"       signatures: {got.sigs_valid}/{got.sigs_expected} valid (ed25519={got.ed25519_valid}){mldsa_note}"
            )

    print()
    print(f"summary: {total_pass} pass, {total_fail} fail ({total_pass + total_fail} fixtures)")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
