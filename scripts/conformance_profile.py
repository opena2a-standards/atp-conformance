#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.

Both modes also refuse a `notCovered` list that disagrees with the fixtures
on a rule in PENDING_COVERAGE: the rule stays listed while no fixture
exercises it and leaves the list once one does.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if committed file is stale
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"

# --- suite metadata (hand-maintained; everything under `requirements` is derived) ---
SUITE = {
    "$schema": "https://specs.opena2a.org/schemas/conformance-profile-v1.json",
    "suite": "atp-conformance",
    "spec": {
        "id": "ATP",
        "name": "Agent Trust Protocol",
        "version": "1.0.0-rc1",
        "ref": "https://github.com/opena2a-standards/agent-trust-protocol/blob/main/ATP-SPEC.md",
    },
    "fixtureManifest": "MANIFEST.sha256",
    "verifiers": [
        {
            "language": "go",
            "path": "verifiers/go",
            "coverage": "full: Ed25519 and ML-DSA-65 (FIPS 204) hybrid signatures",
        },
        {
            "language": "python",
            "path": "verifiers/python",
            "coverage": "Ed25519; ML-DSA-65 signatures recorded as present, verification delegated to the Go verifier",
        },
    ],
    "notCovered": [
        {
            "specSection": "§6 Federation cosignature (Level 3)",
            "reason": "no second production authority exists to source a real cosigned proof from",
        },
        {
            "specSection": "§8.1 response authenticity",
            "reason": "the spec does not sign the revocation body (the transport carries authenticity, plus the transparencyLogIndex of an entry that carries one; an entry without it rests on the transport alone); the fixtures cover the structural rules only",
        },
        {
            "specSection": "§8.1 entries without a transparencyLogIndex",
            "reason": "§8.1 makes transparencyLogIndex OPTIONAL and a client MUST apply an entry without it; no fixture carries such an entry yet",
        },
    ],
}


# --- spec rules no fixture exercises yet ---
# ATP-SPEC Section 2.1 keeps the authoritative list of rules the fixtures do
# not cover, and `notCovered` can lag it. Each rule here maps its `notCovered`
# specSection to a test over one fixture that is true once a fixture
# exercises the rule.
def _accepts_revocation_without_index(fx: dict) -> bool:
    if fx.get("fixtureType") != "revocationList" or fx["expected"]["verifyResult"] != "ACCEPT":
        return False
    entries = (fx.get("revocationList") or {}).get("revocations") or []
    return any("transparencyLogIndex" not in entry for entry in entries)


PENDING_COVERAGE = {
    "§8.1 entries without a transparencyLogIndex": _accepts_revocation_without_index,
}


def load_fixtures() -> list[tuple[Path, dict]]:
    paths = sorted((REPO_ROOT / "fixtures").glob("*.json"))
    return [(path, json.loads(path.read_text())) for path in paths]


def coverage_errors(profile: dict, fixtures: list[dict]) -> list[str]:
    declared = {item["specSection"] for item in profile["notCovered"]}
    errors = []
    for section, exercises in PENDING_COVERAGE.items():
        covered = any(exercises(fx) for fx in fixtures)
        if not covered and section not in declared:
            errors.append(f"no fixture exercises {section!r}; add it to SUITE notCovered")
        if covered and section in declared:
            errors.append(f"a fixture exercises {section!r}; remove it from SUITE notCovered")
    return errors


def build() -> dict:
    requirements = []
    for path, fx in load_fixtures():
        expected = fx["expected"]
        outcome = expected["verifyResult"]
        if expected.get("rejectCategory"):
            outcome = f"REJECT[{expected['rejectCategory']}]"
        requirements.append(
            {
                "fixture": f"fixtures/{path.name}",
                "name": fx["name"],
                "fixtureType": fx["fixtureType"],
                "level": "MUST",
                "specRefs": fx["spec"],
                "expected": outcome,
                "description": fx["description"],
            }
        )
    profile = dict(SUITE)
    profile["requirements"] = requirements
    return profile


def main() -> int:
    profile = build()
    errors = coverage_errors(profile, [fx for _, fx in load_fixtures()])
    if errors:
        for error in errors:
            print(f"notCovered disagrees with fixtures/: {error}")
        return 1
    rendered = json.dumps(profile, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            return 1
        if OUT.read_text() != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            return 1
        print("conformance.json is current")
        return 0
    OUT.write_text(rendered)
    print(f"wrote conformance.json ({len(profile['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
