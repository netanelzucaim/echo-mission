#!/usr/bin/env python3
"""Merge a Trivy and a Grype JSON report and rank vulnerabilities by urgency.

Usage:
    compare-scans.py TRIVY_JSON GRYPE_JSON [--out-dir DIR] [--top N]

Writes DIR/triage.md (summary + top N) and DIR/triage.csv (every vulnerability).

Ranking, most urgent first:
  1. Highest severity either scanner assigns.
  2. Agreement: reported by both scanners, and the lower of the two severities.
     (So "Critical in both" is first, then "Critical in one, High in the other",
      then "Critical in one, missing in the other", then "High in both", ...)
  3. Known exploited (CISA KEV), when Grype provides it.
  4. A fix is available (actionable now).
  5. EPSS exploit probability, then CVSS score, when available.
"""
import argparse, csv, json, os, sys

RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NEGLIGIBLE": 0, "UNKNOWN": 0}
NAME = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Negligible/Unknown"}


def sev(s):
    return RANK.get((s or "UNKNOWN").upper(), 0)


def new_entry(vid):
    return {"id": vid, "trivy": None, "grype": None, "pkgs": set(), "fixes": set(),
            "kev": False, "epss": 0.0, "cvss": 0.0, "title": ""}


def load_trivy(path, vulns):
    data = json.load(open(path))
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            e = vulns.setdefault(v["VulnerabilityID"], new_entry(v["VulnerabilityID"]))
            e["trivy"] = max(e["trivy"] if e["trivy"] is not None else -1, sev(v.get("Severity")))
            e["pkgs"].add(v.get("PkgName", "?"))
            if v.get("FixedVersion"):
                e["fixes"].add(v["FixedVersion"])
            e["title"] = e["title"] or (v.get("Title") or "")
            for src in (v.get("CVSS") or {}).values():
                e["cvss"] = max(e["cvss"], src.get("V3Score") or 0.0)


def load_grype(path, vulns):
    data = json.load(open(path))
    for m in data.get("matches", []) or []:
        v = m["vulnerability"]
        vid = v["id"]
        if not vid.startswith("CVE-"):  # e.g. GHSA ids: use the related CVE if there is one
            for r in m.get("relatedVulnerabilities", []) or []:
                if r.get("id", "").startswith("CVE-"):
                    vid = r["id"]
                    break
        e = vulns.setdefault(vid, new_entry(vid))
        e["grype"] = max(e["grype"] if e["grype"] is not None else -1, sev(v.get("severity")))
        e["pkgs"].add(m["artifact"].get("name", "?"))
        fix = v.get("fix") or {}
        if fix.get("state") == "fixed":
            e["fixes"].update(fix.get("versions") or [])
        if v.get("knownExploited"):
            e["kev"] = True
        for ep in v.get("epss") or []:
            e["epss"] = max(e["epss"], ep.get("epss") or 0.0)
        for c in v.get("cvss") or []:
            e["cvss"] = max(e["cvss"], (c.get("metrics") or {}).get("baseScore") or 0.0)


def urgency(e):
    t = e["trivy"] if e["trivy"] is not None else -1
    g = e["grype"] if e["grype"] is not None else -1
    return (max(t, g), min(t, g), e["kev"], bool(e["fixes"]), e["epss"], e["cvss"])


def label(x):
    return "-" if x is None else NAME[x]


def agreement(e):
    t, g = e["trivy"], e["grype"]
    if t is None:
        return "Grype only"
    if g is None:
        return "Trivy only"
    return "Agree" if t == g else "Severity differs"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trivy_json")
    ap.add_argument("grype_json")
    ap.add_argument("--out-dir", default=None, help="default: directory of TRIVY_JSON")
    ap.add_argument("--top", type=int, default=40, help="rows in the markdown table")
    a = ap.parse_args()
    out = a.out_dir or os.path.dirname(os.path.abspath(a.trivy_json))
    os.makedirs(out, exist_ok=True)

    vulns = {}
    load_trivy(a.trivy_json, vulns)
    load_grype(a.grype_json, vulns)
    rows = sorted(vulns.values(), key=lambda e: (urgency(e), e["id"]), reverse=True)

    both = [e for e in rows if e["trivy"] is not None and e["grype"] is not None]
    crit_both = [e for e in both if e["trivy"] == 4 and e["grype"] == 4]

    with open(os.path.join(out, "triage.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rank", "id", "trivy", "grype", "agreement", "packages", "fix_available",
                    "fixed_versions", "known_exploited", "epss", "cvss", "title"])
        for i, e in enumerate(rows, 1):
            w.writerow([i, e["id"], label(e["trivy"]), label(e["grype"]), agreement(e),
                        " ".join(sorted(e["pkgs"])), "yes" if e["fixes"] else "no",
                        " ".join(sorted(e["fixes"])), "yes" if e["kev"] else "no",
                        f'{e["epss"]:.4f}', e["cvss"], e["title"]])

    with open(os.path.join(out, "triage.md"), "w") as f:
        f.write("# Trivy vs Grype: vulnerabilities ranked by urgency\n\n")
        f.write(f"Inputs: `{os.path.basename(a.trivy_json)}`, `{os.path.basename(a.grype_json)}`. "
                "Full list: `triage.csv`.\n\n")
        f.write("| | Count |\n|---|---|\n")
        f.write(f"| Unique vulnerabilities (either scanner) | {len(rows)} |\n")
        f.write(f"| Reported by both | {len(both)} |\n")
        f.write(f"| Trivy only | {sum(1 for e in rows if e['grype'] is None)} |\n")
        f.write(f"| Grype only | {sum(1 for e in rows if e['trivy'] is None)} |\n")
        f.write(f"| Both report, same severity | {sum(1 for e in both if e['trivy'] == e['grype'])} |\n")
        f.write(f"| Both report, different severity | {sum(1 for e in both if e['trivy'] != e['grype'])} |\n")
        f.write(f"| **Critical in both** | **{len(crit_both)}** |\n")
        f.write(f"| Critical in both, fix available | {sum(1 for e in crit_both if e['fixes'])} |\n\n")
        f.write(f"## Top {min(a.top, len(rows))}\n\n")
        f.write("| # | ID | Trivy | Grype | Packages | Fix | KEV | EPSS |\n|---|---|---|---|---|---|---|---|\n")
        for i, e in enumerate(rows[: a.top], 1):
            pk = sorted(e["pkgs"])
            pk = ", ".join(pk[:4]) + (f" (+{len(pk) - 4})" if len(pk) > 4 else "")
            f.write(f"| {i} | {e['id']} | {label(e['trivy'])} | {label(e['grype'])} | {pk} | "
                    f"{'yes' if e['fixes'] else 'no'} | {'yes' if e['kev'] else ''} | "
                    f"{e['epss'] * 100:.1f}% |\n")
        f.write("\nRanking: highest severity from either scanner, then agreement between the two "
                "(both report it, lower of the two severities), then known-exploited, fix available, "
                "EPSS, CVSS.\n")
    print(f"{len(rows)} unique vulnerabilities, {len(both)} in both, {len(crit_both)} critical in both")
    print(f"wrote {os.path.join(out, 'triage.md')} and triage.csv")


if __name__ == "__main__":
    sys.exit(main())
