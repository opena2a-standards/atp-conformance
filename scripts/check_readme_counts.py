#!/usr/bin/env python3
"""Assert the fixture counts stated in README.md, and the per-fixture table in
docs/fixtures.md, match the fixture set.

The README states the expected verifier result in two places: the continuous
verification list ("N pass, 0 fail") and the implementations table ("N / N
PASS"). Both are measurements over fixtures/, so they are enforced here
rather than maintained by hand. Both drifted once already: the list claimed
7 pass and the table claimed 4 / 4 after the fixture set had grown to 13.

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


def readme_failures(actual):
    readme = README.read_text(encoding="utf-8")
    failures = []

    # "must report `20 pass, 0 fail`" in the continuous-verification list.
    pass_fail = re.findall(r"`(\d+) pass, (\d+) fail`", readme)
    if not pass_fail:
        failures.append("no `N pass, 0 fail` claim found in README")
    for stated, failed in pass_fail:
        if int(stated) != actual:
            failures.append(
                f"README claims `{stated} pass` but fixtures/ holds {actual}"
            )
        if int(failed) != 0:
            failures.append(f"README claims `{failed} fail`, expected 0")

    # "20 / 20 PASS" rows in the implementations table.
    table = re.findall(r"(\d+)\s*/\s*(\d+)\s+PASS", readme)
    if not table:
        failures.append("no `N / N PASS` row found in README")
    for got, total in table:
        if int(total) != actual:
            failures.append(
                f"README implementations table claims {got} / {total} PASS "
                f"but fixtures/ holds {actual}"
            )
        if got != total:
            failures.append(f"README table row {got} / {total} PASS is not a full pass")

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

    failures = readme_failures(actual) + fixture_table_failures(paths)
    if failures:
        print("README.md or docs/fixtures.md does not match fixtures/:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"README counts match fixtures/: {actual} fixtures, all stated as passing")
    print(
        f"docs/fixtures.md Fixtures table: one row for each of the {actual} fixtures, "
        "Type and Expected matching"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
