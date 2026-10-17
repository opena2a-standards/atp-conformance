#!/usr/bin/env python3
"""Assert the fixture counts stated in README.md, and the per-fixture table in
docs/fixtures.md, match the fixture set.

The README states the expected verifier result in four places: the summary
under "Running the verifiers" ("summary: N pass, 0 fail (N fixtures)" and
the "(A ACCEPT, R REJECT)" split after it), the continuous verification list
("N pass, 0 fail"), the implementations table ("N / N PASS") and the cosigner
example ("go=N pass, 0 fail; python=N pass, 0 fail"). All are measurements
over fixtures/, so they are enforced here rather than maintained by hand:
every "N pass, M fail" needs N equal to the fixture count and M equal to 0,
every "(N fixtures)" and "N / N PASS" needs N equal to the fixture count, and
the ACCEPT/REJECT split must equal the verifyResult counts in the fixtures'
expected blocks. Each of these four claim shapes must appear at least once,
and a mismatch names its README line. The list and the table drifted once
already: the list claimed 7 pass and the table claimed 4 / 4 after the
fixture set had grown to 13.

The fixture reference the README links (docs/fixtures.md) has a Fixtures
table with one row per fixture. It listed only the original four fixtures
while the set grew to 14, so it is enforced here too: each fixture needs
exactly one row, each row must name a fixture in fixtures/, and the Type and
Expected cells must equal the fixture's fixtureType and expected block
("ACCEPT", or "REJECT (`CATEGORY`)" with the pinned reject category).

Exit 0 when every stated count and table row matches the fixture set, 1
otherwise.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
FIXTURE_DOC = ROOT / "docs" / "fixtures.md"
FIXTURES = ROOT / "fixtures"

FIXTURE_TABLE_HEADER = ["Fixture", "Type", "Expected", "Exercises"]


def readme_failures(outcomes):
    """Failures for the README count claims. `outcomes` holds the
    expected.verifyResult of each fixture in fixtures/."""
    readme = README.read_text(encoding="utf-8")
    actual = len(outcomes)
    accept = outcomes.count("ACCEPT")
    reject = outcomes.count("REJECT")
    failures = []

    def claims(pattern):
        """(README line, groups) for each match. The patterns match across
        whitespace, so a claim that rewrapping splits over two lines is still
        read; the line is the one the claim starts on."""
        return [
            (f"{README.name}:{readme.count(chr(10), 0, m.start()) + 1}", m.groups())
            for m in re.finditer(pattern, readme)
        ]

    # "summary: 20 pass, 0 fail" under Running the verifiers, "`20 pass, 0
    # fail`" in the continuous-verification list, and the cosigner example
    # "go=20 pass, 0 fail; python=20 pass, 0 fail".
    pass_fail = claims(r"\b(\d+)\s+pass,\s+(\d+)\s+fail\b")
    if not pass_fail:
        failures.append("no `N pass, 0 fail` claim found in README")
    for where, (stated, failed) in pass_fail:
        if int(stated) != actual:
            failures.append(
                f"{where}: README claims `{stated} pass` but fixtures/ holds {actual}"
            )
        if int(failed) != 0:
            failures.append(f"{where}: README claims `{failed} fail`, expected 0")

    # "(20 fixtures)" after the summary.
    fixture_count = claims(r"\((\d+)\s+fixtures\)")
    if not fixture_count:
        failures.append("no `(N fixtures)` claim found in README")
    for where, (stated,) in fixture_count:
        if int(stated) != actual:
            failures.append(
                f"{where}: README claims {stated} fixtures but fixtures/ holds {actual}"
            )

    # "(10 ACCEPT, 10 REJECT)", the split of the shipped fixture set.
    split = claims(r"\((\d+)\s+ACCEPT,\s+(\d+)\s+REJECT\)")
    if not split:
        failures.append("no `(N ACCEPT, M REJECT)` claim found in README")
    for where, (stated_accept, stated_reject) in split:
        if (int(stated_accept), int(stated_reject)) != (accept, reject):
            failures.append(
                f"{where}: README claims {stated_accept} ACCEPT, {stated_reject} REJECT "
                f"but the fixtures' expected blocks hold {accept} ACCEPT, {reject} REJECT"
            )

    # "20 / 20 PASS" rows in the implementations table.
    table = claims(r"(\d+)\s*/\s*(\d+)\s+PASS")
    if not table:
        failures.append("no `N / N PASS` row found in README")
    for where, (got, total) in table:
        if int(total) != actual:
            failures.append(
                f"{where}: README implementations table claims {got} / {total} PASS "
                f"but fixtures/ holds {actual}"
            )
        if got != total:
            failures.append(
                f"{where}: README table row {got} / {total} PASS is not a full pass"
            )

    return failures


def table_cells(line, count):
    """The first `count` cells of a Markdown table row. The last cell keeps
    the rest of the row, so a pipe inside the Exercises text cannot shift the
    cells before it."""
    return [cell.strip() for cell in line.strip().strip("|").split("|", count - 1)]


def expected_cell(expected):
    """The Expected cell a fixture's expected block calls for."""
    category = expected.get("rejectCategory")
    if category:
        return f"{expected['verifyResult']} (`{category}`)"
    return expected["verifyResult"]


def fixture_table_failures(paths):
    rel = FIXTURE_DOC.relative_to(ROOT)
    lines = FIXTURE_DOC.read_text(encoding="utf-8").splitlines()
    width = len(FIXTURE_TABLE_HEADER)
    header = next(
        (
            i
            for i, line in enumerate(lines)
            if line.startswith("|") and table_cells(line, width) == FIXTURE_TABLE_HEADER
        ),
        None,
    )
    if header is None:
        return [f"no `| Fixture | Type | Expected | Exercises |` table found in {rel}"]

    fixtures = {}
    for path in paths:
        fx = json.loads(path.read_text(encoding="utf-8"))
        fixtures[f"fixtures/{path.name}"] = (fx["fixtureType"], expected_cell(fx["expected"]))

    first = header + 1
    if first < len(lines) and re.fullmatch(r"[|:\- ]+", lines[first]):
        first += 1  # the |---|---| delimiter row

    failures = []
    listed = set()
    for number, line in enumerate(lines[first:], first + 1):
        if not line.startswith("|"):
            break
        where = f"{rel}:{number}"
        cells = table_cells(line, width)
        if len(cells) < width:
            failures.append(f"{where}: row has {len(cells)} cells, expected {width}")
            continue
        name, type_text, expected_text = cells[0].strip("`"), cells[1], cells[2]
        if name not in fixtures:
            failures.append(f"{where}: row names {name}, which fixtures/ does not hold")
            continue
        if name in listed:
            failures.append(f"{where}: second row for {name}")
            continue
        listed.add(name)
        fixture_type, outcome = fixtures[name]
        if type_text != fixture_type:
            failures.append(
                f"{where}: {name} Type is {type_text!r}, its fixtureType is {fixture_type!r}"
            )
        if expected_text != outcome:
            failures.append(
                f"{where}: {name} Expected is {expected_text!r}, its expected block "
                f"calls for {outcome!r}"
            )

    for name in sorted(set(fixtures) - listed):
        failures.append(f"{rel} Fixtures table has no row for {name}")
    return failures


def main():
    paths = sorted(FIXTURES.glob("*.json"))
    actual = len(paths)
    if actual == 0:
        print("no fixtures found; refusing to pass vacuously", file=sys.stderr)
        return 1

    outcomes = [
        json.loads(path.read_text(encoding="utf-8"))["expected"]["verifyResult"]
        for path in paths
    ]
    failures = readme_failures(outcomes) + fixture_table_failures(paths)
    if failures:
        print("README.md or docs/fixtures.md does not match fixtures/:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(
        f"README counts match fixtures/: {actual} fixtures "
        f"({outcomes.count('ACCEPT')} ACCEPT, {outcomes.count('REJECT')} REJECT), "
        "all stated as passing"
    )
    print(
        f"docs/fixtures.md Fixtures table: one row for each of the {actual} fixtures, "
        "Type and Expected matching"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
