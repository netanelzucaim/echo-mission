#!/usr/bin/env python3
"""Merge a Trivy and a Grype JSON report and rank vulnerabilities by risk.

Usage:
    compare-scans.py TRIVY_JSON GRYPE_JSON [--linked FILE] [--out-dir DIR] [--top N]

Writes DIR/triage.md (summary + top N) and DIR/triage.csv (every vulnerability).

The ranking answers "what is most dangerous and reaches the most deployments",
not "what has the scariest severity label".

    score = 100 * danger * reach

  danger (0..1) = 0.6 * exploitation + 0.4 * severity
      exploitation = 1.0 if the CVE is in CISA's Known Exploited list (KEV),
                     otherwise its EPSS probability (chance of exploitation
                     in the next 30 days).
      severity     = average of the two scanners' severities, scaled to 0..1
                     (Critical = 1, High = 0.75, Medium = 0.5, Low = 0.25).
                     A scanner that does not report the CVE counts as 0, so
                     findings both scanners agree on score higher.

  reach (0.4..1) = how many deployments run the vulnerable code
      1.0  the affected package is a library the main program loads
           (listed in --linked), so every running container executes it;
      0.4  the package only sits in the image (a tool, or a library used by
           an optional component);
      plus 0.05 per additional affected package, up to +0.15, capped at 1.0.

Without --linked, reach cannot tell the two cases apart and every finding gets
the "sits in the image" value; the script says so.
"""
import argparse, csv, json, os, sys

RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NEGLIGIBLE": 0, "UNKNOWN": 0}
NAME = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Negligible/Unknown"}
REACH_LINKED, REACH_PRESENT = 1.0, 0.4


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


def score(e, linked):
    exploitation = 1.0 if e["kev"] else e["epss"]
    severity = ((e["trivy"] or 0) + (e["grype"] or 0)) / 8.0
    e["danger"] = 0.6 * exploitation + 0.4 * severity
    e["linked"] = sorted(e["pkgs"] & linked)
    base = REACH_LINKED if e["linked"] else REACH_PRESENT
    e["reach"] = min(1.0, base + 0.05 * min(len(e["pkgs"]) - 1, 3))
    e["score"] = 100.0 * e["danger"] * e["reach"]


def label(x):
    return "-" if x is None else NAME[x]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trivy_json")
    ap.add_argument("grype_json")
    ap.add_argument("--linked", default=None,
                    help="file listing the packages the main program loads, one per line "
                         "(default: linked-packages.txt next to TRIVY_JSON, if it exists)")
    ap.add_argument("--out-dir", default=None, help="default: directory of TRIVY_JSON")
    ap.add_argument("--top", type=int, default=40, help="rows in the markdown table")
    a = ap.parse_args()
    src_dir = os.path.dirname(os.path.abspath(a.trivy_json))
    out = a.out_dir or src_dir
    os.makedirs(out, exist_ok=True)

    linked_path = a.linked or os.path.join(src_dir, "linked-packages.txt")
    linked = set()
    if os.path.exists(linked_path):
        linked = set(open(linked_path).read().split())
    else:
        print(f"warning: no linked-packages file ({linked_path}); reach is not "
              "distinguishing libraries the main program loads", file=sys.stderr)

    vulns = {}
    load_trivy(a.trivy_json, vulns)
    load_grype(a.grype_json, vulns)
    for e in vulns.values():
        score(e, linked)
    rows = sorted(vulns.values(), key=lambda e: (e["score"], bool(e["fixes"]), e["cvss"], e["id"]),
                  reverse=True)

    both = [e for e in rows if e["trivy"] is not None and e["grype"] is not None]
    in_linked = [e for e in rows if e["linked"]]

    with open(os.path.join(out, "triage.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rank", "id", "score", "danger", "reach", "loaded_by_main_program", "trivy",
                    "grype", "packages", "fix_available", "fixed_versions", "known_exploited",
                    "epss", "cvss", "title"])
        for i, e in enumerate(rows, 1):
            w.writerow([i, e["id"], f'{e["score"]:.1f}', f'{e["danger"]:.3f}', f'{e["reach"]:.2f}',
                        "yes" if e["linked"] else "no", label(e["trivy"]), label(e["grype"]),
                        " ".join(sorted(e["pkgs"])), "yes" if e["fixes"] else "no",
                        " ".join(sorted(e["fixes"])), "yes" if e["kev"] else "no",
                        f'{e["epss"]:.4f}', e["cvss"], e["title"]])

    with open(os.path.join(out, "triage.md"), "w") as f:
        f.write("# Trivy vs Grype: vulnerabilities ranked by danger and reach\n\n")
        f.write(f"Inputs: `{os.path.basename(a.trivy_json)}`, `{os.path.basename(a.grype_json)}`. "
                "Full list: `triage.csv`.\n\n")
        f.write("| | Count |\n|---|---|\n")
        f.write(f"| Unique vulnerabilities (either scanner) | {len(rows)} |\n")
        f.write(f"| Reported by both | {len(both)} |\n")
        f.write(f"| Trivy only | {sum(1 for e in rows if e['grype'] is None)} |\n")
        f.write(f"| Grype only | {sum(1 for e in rows if e['trivy'] is None)} |\n")
        f.write(f"| Both report, different severity | {sum(1 for e in both if e['trivy'] != e['grype'])} |\n")
        f.write(f"| Critical in both | {sum(1 for e in both if e['trivy'] == 4 and e['grype'] == 4)} |\n")
        f.write(f"| Known exploited (KEV) | {sum(1 for e in rows if e['kev'])} |\n")
        f.write(f"| In a library the main program loads | {len(in_linked)} |\n")
        f.write(f"| ...of those, with a fix available | {sum(1 for e in in_linked if e['fixes'])} |\n\n")
        if linked:
            f.write("Libraries the main program loads: " + ", ".join(f"`{p}`" for p in sorted(linked)) + ".\n\n")
        else:
            f.write("No linked-packages file was given, so reach does not separate libraries the "
                    "main program loads from packages that only sit in the image.\n\n")
        f.write(f"## Top {min(a.top, len(rows))}\n\n")
        f.write("| # | ID | Score | Loaded | Trivy | Grype | Packages | Fix | KEV | EPSS |\n"
                "|---|---|---|---|---|---|---|---|---|---|\n")
        for i, e in enumerate(rows[: a.top], 1):
            pk = sorted(e["pkgs"])
            pk = ", ".join(pk[:4]) + (f" (+{len(pk) - 4})" if len(pk) > 4 else "")
            f.write(f"| {i} | {e['id']} | {e['score']:.1f} | {'yes' if e['linked'] else 'no'} | "
                    f"{label(e['trivy'])} | {label(e['grype'])} | {pk} | "
                    f"{'yes' if e['fixes'] else 'no'} | {'yes' if e['kev'] else ''} | "
                    f"{e['epss'] * 100:.1f}% |\n")
        f.write("\nScore = 100 x danger x reach. Danger = 0.6 x exploitation (1 if known exploited, "
                "else EPSS) + 0.4 x severity (average of both scanners). Reach = 1.0 if the main "
                "program loads the affected library, 0.4 if the package only sits in the image, "
                "plus a small bonus per extra affected package.\n\n"
                "Limits: \"loaded\" means the library is loaded, not that the vulnerable function "
                "is called. That still needs reading the advisory. Vulnerabilities the scanners "
                "do not report at all are not in this list.\n")
    print(f"{len(rows)} unique vulnerabilities, {len(both)} in both, "
          f"{len(in_linked)} in libraries the main program loads")
    print(f"wrote {os.path.join(out, 'triage.md')} and triage.csv")


if __name__ == "__main__":
    sys.exit(main())
