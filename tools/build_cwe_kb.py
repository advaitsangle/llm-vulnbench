#!/usr/bin/env python3
"""Regenerate A4's CWE knowledge base from the official MITRE CWE catalog.

The knowledge base A4 retrieves over is *sourced*, not authored: every line of prose
in it comes from MITRE's published catalog, so the condition's claim is "retrieval
over the CWE database" rather than "retrieval over descriptions we wrote after seeing
the corpus". This script is what makes that checkable — re-run it and diff.

    python tools/build_cwe_kb.py                 # fetch the latest catalog and rebuild
    python tools/build_cwe_kb.py --xml cwec.xml  # rebuild from a local copy

It writes :data:`OUT`, a small JSON file committed to the repo, so neither the 18 MB
catalog nor a network round-trip is needed at run time. The catalog version and the
retrieval date are recorded inside it; a scored run can therefore name the exact CWE
data it was given.

Only the eleven weaknesses OWASP BenchmarkJava contains are extracted (see
``vulnbench/conditions/cwe_kb.py`` for why the base is scoped that way).

CWE is a trademark of The MITRE Corporation. Content is reproduced from the CWE
catalog, which MITRE publishes for free public use with attribution.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import date
from pathlib import Path

CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
OUT = Path(__file__).resolve().parent.parent / "vulnbench" / "data" / "cwe_kb.json"

C = "{http://cwe.mitre.org/cwe-7}"
XHTML = "{http://www.w3.org/1999/xhtml}"

#: The CWEs BenchmarkJava v1.2 contains, verified against expectedresults-1.2.csv.
CWE_IDS = (22, 78, 79, 89, 90, 327, 328, 330, 501, 614, 643)

#: Length budget per entry. A4 shows k=5 entries per file on top of the file itself,
#: so untrimmed MITRE prose (CWE-78's extended description alone is 2.3 KB) would
#: crowd out the code the model is supposed to be reading.
MAX_DESCRIPTION = 700
MAX_MITIGATIONS = 3
MAX_MITIGATION = 300
MAX_EXAMPLE = 500

#: Mitigations are listed in no particular order and range from one line to two
#: kilobytes, so they have to be ranked before the first few are taken.
#:
#: MITRE tags most of them with a Strategy, and that tag is the useful signal: A4
#: reads source, so a mitigation is worth showing exactly insofar as it describes
#: what the *fixed code* looks like. "Parameterization" tells the model that a
#: PreparedStatement rules CWE-89 out; "Firewall" and "Environment Hardening"
#: describe deployment and are invisible in a file. Ranking by Phase instead put
#: CWE-89's generic "quote your arguments" and "keep error messages terse" ahead of
#: its parameterization entry, which is the one that actually discriminates.
STRATEGY_RANK = {
    "Parameterization": 0,
    "Output Encoding": 1,
    "Input Validation": 2,
    "Libraries or Frameworks": 3,
    "Enforcement by Conversion": 4,
    # Real controls, but nothing a source-reading model can observe.
    "Environment Hardening": 8,
    "Sandbox or Jail": 8,
    "Firewall": 9,
    "Attack Surface Reduction": 9,
    "Compilation or Build Hardening": 9,
}
#: Tiebreaker for the ~40% of mitigations MITRE leaves untagged.
PHASE_RANK = {"Implementation": 0, "Architecture and Design": 1, "Requirements": 2}
#: Untagged mitigations sort between the code-visible strategies and the deployment ones.
UNTAGGED_STRATEGY = 5


def flat(el: ET.Element | None) -> str:
    """Element text with markup and whitespace collapsed."""
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


def code_text(el: ET.Element) -> str:
    """A demonstrative example's code, keeping its line structure.

    The catalog marks line breaks with ``<xhtml:br/>`` rather than newlines, so
    ``itertext`` alone would run every statement together into one line.
    """
    parts: list[str] = []
    for node in el.iter():
        if node.tag == f"{XHTML}br":
            parts.append("\n")
        if node.text:
            parts.append(node.text)
        if node.tail:
            parts.append(node.tail)
    lines = [ln.strip() for ln in "".join(parts).splitlines()]
    return "\n".join(ln for ln in lines if ln)


def clip(text: str, limit: int) -> str:
    """Trim to ``limit`` on a sentence boundary where one is close enough."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    stop = cut.rfind(". ")
    return (cut[: stop + 1] if stop > limit * 0.6 else cut.rstrip() + "…")


def mitigations_of(weakness: ET.Element) -> list[str]:
    """MITRE's Potential_Mitigations, best phases first.

    These stand in for a "safe shape": the catalog carries no ``Good`` Java example
    for any of the eleven weaknesses in this base — six have no ``Good`` example in
    any language — so the description of the fix is the only sourced counter-signal
    available. Entries whose mitigation list is empty upstream (CWE-501) simply get
    none rather than an invented one.
    """
    scored: list[tuple[int, int, int, str]] = []
    for order, m in enumerate(weakness.iter(f"{C}Mitigation")):
        strategy = flat(m.find(f"{C}Strategy"))
        phases = [flat(p) for p in m.findall(f"{C}Phase")]
        text = flat(m.find(f"{C}Description"))
        if not text:
            continue
        scored.append((
            STRATEGY_RANK.get(strategy, UNTAGGED_STRATEGY),
            min((PHASE_RANK.get(p, 9) for p in phases), default=9),
            order,  # catalog order last, so the sort is total and the build reproducible
            clip(text, MAX_MITIGATION),
        ))
    scored.sort()
    return [text for *_, text in scored[:MAX_MITIGATIONS]]


def example_of(weakness: ET.Element) -> dict | None:
    """One vulnerable code example, Java if the catalog has one."""
    candidates = [
        ec for ec in weakness.iter(f"{C}Example_Code") if ec.get("Nature") == "Bad"
    ]
    if not candidates:
        return None
    java = [ec for ec in candidates if ec.get("Language") == "Java"]
    chosen = (java or candidates)[0]
    body = code_text(chosen)
    if not body:
        return None
    return {"language": chosen.get("Language") or "unspecified", "code": clip(body, MAX_EXAMPLE)}


def build(xml_path: Path) -> dict:
    root = ET.parse(xml_path).getroot()
    catalog_version = root.get("Version", "unknown")
    catalog_date = root.get("Date", "unknown")

    found = {
        int(w.get("ID")): w
        for w in root.iter(f"{C}Weakness")
        if int(w.get("ID")) in CWE_IDS
    }
    missing = set(CWE_IDS) - set(found)
    if missing:
        raise SystemExit(f"catalog {catalog_version} is missing CWE(s): {sorted(missing)}")

    entries = []
    for cwe in CWE_IDS:
        w = found[cwe]
        description = flat(w.find(f"{C}Description"))
        extended = flat(w.find(f"{C}Extended_Description"))
        entries.append({
            "cwe": cwe,
            "name": w.get("Name"),
            "description": clip(
                f"{description} {extended}".strip(), MAX_DESCRIPTION
            ),
            "mitigations": mitigations_of(w),
            "example": example_of(w),
        })

    return {
        "_source": {
            "catalog": "MITRE CWE",
            "url": CATALOG_URL,
            "version": catalog_version,
            "catalog_date": catalog_date,
            "retrieved": date.today().isoformat(),
            "generated_by": "tools/build_cwe_kb.py",
            "notice": (
                "CWE is a trademark of The MITRE Corporation. Prose reproduced from "
                "the CWE catalog, trimmed to length; see tools/build_cwe_kb.py."
            ),
        },
        "entries": entries,
    }


def fetch_catalog() -> Path:
    """Download and unzip the current catalog into a temp file beside the output."""
    print(f"fetching {CATALOG_URL} …")
    with urllib.request.urlopen(CATALOG_URL, timeout=120) as resp:
        blob = resp.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".xml"))
        dest = OUT.parent / name
        dest.write_bytes(zf.read(name))
    return dest


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--xml", type=Path, help="a local cwec_*.xml instead of downloading")
    args = ap.parse_args()

    xml_path = args.xml
    downloaded = None
    if xml_path is None:
        xml_path = downloaded = fetch_catalog()

    data = build(xml_path)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    if downloaded is not None:
        downloaded.unlink()  # the 18 MB catalog is not committed; the extract is

    src = data["_source"]
    print(f"wrote {OUT.relative_to(OUT.parent.parent.parent)} "
          f"— CWE {src['version']} ({src['catalog_date']}), {len(data['entries'])} entries")
    for e in data["entries"]:
        ex = e["example"]
        print(f"  CWE-{e['cwe']:<4} {len(e['description']):>4}c desc · "
              f"{len(e['mitigations'])} mitigations · "
              f"example: {ex['language'] if ex else 'none'}")


if __name__ == "__main__":
    main()
