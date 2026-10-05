#!/usr/bin/env python3
"""Compare the scan of a patched image with the baseline scan.

Usage:
    diff-scans.py BASELINE_DIR NEW_DIR [--vex FILE ...] [--top N]

Both folders must have the layout written by scan-baseline.sh and compare-scans.py:
    triage.csv, image/packages.tsv, image/linked-packages.txt, reports/*.json

Writes into NEW_DIR:
    diff.md   before/after summary, what was fixed, what remains, what is new,
              package version changes, and the VEX check
    diff.csv  every CVE from either scan with its status: fixed, remaining or new

VEX check: for every statement in the given OpenVEX files it compares the plain
reports (reports/trivy.json, grype.json) with the reports produced with --vex
(reports/trivy-vex.json, grype-vex.json) and says, per scanner, whether the finding
was suppressed, was never reported, or is still reported.
"""
import argparse, collections, csv, json, os, sys

SEV = ["Critical", "High", "Medium", "Low", "Negligible/Unknown"]
RANK = {s: len(SEV) - i for i, s in enumerate(SEV)}
RANK["-"] = 0


def load_dir(d):
    path = os.path.join(d, "triage.csv")
    if not os.path.exists(path):
        sys.exit(f"error: {path} not found; run compare-scans.py for {d} first")
    rows = {r["id"]: r for r in csv.DictReader(open(path))}
    pkgs = {}
    tsv = os.path.join(d, "image", "packages.tsv")
    if os.path.exists(tsv):
        for line in open(tsv):
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2:
                pkgs[parts[0]] = parts[1]
    return rows, pkgs


def top_sev(r):
    return max(r["trivy"], r["grype"], key=lambda s: RANK.get(s, 0))


def is_high(r):
    return RANK.get(top_sev(r), 0) >= RANK["High"]


def findings(path, kind):
    """Set of (cve, package) pairs in a scanner report, or None if the file is missing."""
    if not os.path.exists(path):
        return None
    d = json.load(open(path))
    if kind == "trivy":
        return {(v["VulnerabilityID"], v.get("PkgName", "?"))
                for r in d.get("Results", []) or [] for v in r.get("Vulnerabilities", []) or []}
    return {(m["vulnerability"]["id"], m["artifact"].get("name", "?")) for m in d.get("matches", []) or []}


def summary_row(label, rows, pkgs):
    vals = list(rows.values())
    return (f"| {label} | {len(pkgs)} | {len(vals)} | {sum(map(is_high, vals))} | "
            f"{sum(1 for r in vals if r['trivy'] == 'Critical' and r['grype'] == 'Critical')} | "
            f"{sum(1 for r in vals if r['known_exploited'] == 'yes')} | "
            f"{sum(1 for r in vals if r['loaded_by_main_program'] == 'yes')} |")


def cve_table(w, rows, limit):
    w("| ID | Trivy | Grype | Packages | Loaded | Fix available | KEV |")
    w("|---|---|---|---|---|---|---|")
    for r in rows[:limit]:
        pk = r["packages"].split()
        pk = ", ".join(pk[:4]) + (f" (+{len(pk) - 4})" if len(pk) > 4 else "")
        w(f"| {r['id']} | {r['trivy']} | {r['grype']} | {pk} | {r['loaded_by_main_program']} | "
          f"{r['fix_available']} | {'yes' if r['known_exploited'] == 'yes' else ''} |")
    if len(rows) > limit:
        w(f"\n{len(rows) - limit} more in `diff.csv`.")
    w()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("baseline_dir")
    ap.add_argument("new_dir")
    ap.add_argument("--vex", action="append", default=[], help="OpenVEX file that was applied; repeatable")
    ap.add_argument("--top", type=int, default=25, help="rows per CVE table")
    a = ap.parse_args()

    base_all, base_pkgs = load_dir(a.baseline_dir)
    new_all, new_pkgs = load_dir(a.new_dir)
    # Compare only what the scanners report. Rows added by hand from upstream advisories
    # (review.tsv; no Trivy or Grype rating) are not in either scan, so a missing row in
    # the patched ranking says nothing about whether they were fixed. They are listed
    # separately below, marked fixed only when a VEX file says status "fixed".
    scanned = lambda rows: {k: v for k, v in rows.items() if v["trivy"] != "-" or v["grype"] != "-"}
    base, new = scanned(base_all), scanned(new_all)
    advisory = sorted((r for k, r in base_all.items() if k not in base), key=lambda r: r["id"])
    vex_fixed = set()
    for path in a.vex:
        for st in json.load(open(path)).get("statements", []):
            if st.get("status") == "fixed":
                vex_fixed.add((st.get("vulnerability") or {}).get("name"))
    adv_fixed = [r for r in advisory if r["id"] in vex_fixed]
    adv_open = [r for r in advisory if r["id"] not in vex_fixed]
    by_score = lambda rows: sorted(rows, key=lambda r: float(r["score"]), reverse=True)
    fixed = by_score([base[i] for i in base if i not in new])
    remaining = by_score([new[i] for i in new if i in base])
    added = by_score([new[i] for i in new if i not in base])

    with open(os.path.join(a.new_dir, "diff.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["id", "status", "trivy_before", "grype_before", "trivy_after", "grype_after",
                     "packages", "loaded_by_main_program", "fix_available_now", "known_exploited"])
        for status, rows in (("fixed", fixed), ("remaining", remaining), ("new", added)):
            for r in rows:
                b, n = base.get(r["id"]), new.get(r["id"])
                wr.writerow([r["id"], status, b["trivy"] if b else "", b["grype"] if b else "",
                             n["trivy"] if n else "", n["grype"] if n else "", r["packages"],
                             r["loaded_by_main_program"], n["fix_available"] if n else "",
                             r["known_exploited"]])
        for status, rows in (("advisory-fixed", adv_fixed), ("advisory-open", adv_open)):
            for r in rows:
                wr.writerow([r["id"], status, "", "", "", "", r["packages"],
                             r["loaded_by_main_program"], "", r["known_exploited"]])

    with open(os.path.join(a.new_dir, "diff.md"), "w") as f:
        w = lambda text="": f.write(text + "\n")
        w("# Patched image compared with the baseline")
        w()
        w(f"Generated by `scripts/diff-scans.py` from `{a.baseline_dir}` and `{a.new_dir}`. Do not edit")
        w("by hand; rerun the script. Counts are unique CVE IDs across Trivy and Grype. Full list:")
        w("`diff.csv`.")
        w()
        w("## Before and after")
        w()
        w("| Image | Packages | Unique CVEs | Critical or High | Critical in both | Known exploited | In loaded packages |")
        w("|---|---|---|---|---|---|---|")
        w(summary_row("Baseline", base, base_pkgs))
        w(summary_row("Patched", new, new_pkgs))
        w()
        w("```mermaid")
        w(f"pie showData title What happened to the {len(base)} baseline CVEs")
        if fixed:
            w(f'    "No longer reported" : {len(fixed)}')
        if remaining:
            w(f'    "Still reported" : {len(remaining)}')
        w("```")
        w()
        w(f"- **{len(fixed)}** baseline CVEs are no longer reported.")
        w(f"- **{len(remaining)}** are still reported "
          f"({sum(1 for r in remaining if r['fix_available'] == 'yes')} of them have a fixed version available).")
        w(f"- **{len(added)}** are reported now but were not in the baseline.")
        w()
        w("| Highest severity | No longer reported | Still reported | New |")
        w("|---|---|---|---|")
        count = lambda rows: collections.Counter(top_sev(r) for r in rows)
        cf, cr, cn = count(fixed), count(remaining), count(added)
        for s in SEV:
            w(f"| {s} | {cf[s]} | {cr[s]} | {cn[s]} |")
        w()

        w("## Package versions that changed")
        w()
        linked = set()
        lp = os.path.join(a.new_dir, "image", "linked-packages.txt")
        if os.path.exists(lp):
            linked = set(open(lp).read().split())
        changed = sorted(p for p in base_pkgs if p in new_pkgs and base_pkgs[p] != new_pkgs[p])
        gone = sorted(p for p in base_pkgs if p not in new_pkgs)
        came = sorted(p for p in new_pkgs if p not in base_pkgs)
        w(f"{len(changed)} packages changed version, {len(gone)} were removed, {len(came)} were added.")
        w()
        fixes_per_pkg = collections.Counter(p for r in fixed for p in r["packages"].split())
        show = [p for p in changed if p in linked] + \
               [p for p, _ in fixes_per_pkg.most_common() if p in changed and p not in linked][:12]
        if show:
            w("| Package | Before | After | Loaded by nginx | Baseline CVEs no longer reported |")
            w("|---|---|---|---|---|")
            for p in show:
                w(f"| `{p}` | {base_pkgs[p]} | {new_pkgs[p]} | {'yes' if p in linked else 'no'} | {fixes_per_pkg[p]} |")
            w()
        if gone:
            w("Removed: " + ", ".join(f"`{p}`" for p in gone) + ".")
            w()
        if came:
            w("Added: " + ", ".join(f"`{p}`" for p in came) + ".")
            w()

        w(f"## No longer reported ({len(fixed)})")
        w()
        if fixed:
            w("Ranked by their baseline danger-and-reach score.")
            w()
            cve_table(w, fixed, a.top)
        w(f"## Still reported ({len(remaining)})")
        w()
        if remaining:
            w("This is the residual risk. Ranked by current score.")
            w()
            cve_table(w, remaining, a.top)
        w(f"## New ({len(added)})")
        w()
        if added:
            w("Not in the baseline. Either a package was added, or the scanner database gained")
            w("entries between the two scan dates.")
            w()
            cve_table(w, added, a.top)

        w(f"## CVEs from upstream advisories, not in either scan ({len(advisory)})")
        w()
        if advisory:
            w("Added to the baseline ranking by hand from the upstream project's advisories,")
            w("because the scanners compare these packages with the wrong (distribution) data and")
            w("never report them. They are not counted in the numbers above. A CVE here is fixed")
            w("only if a VEX file records `status: fixed` for it; all others are still present.")
            w()
            w(f"- **{len(adv_fixed)}** fixed in this image: "
              + (", ".join(r["id"] for r in adv_fixed) or "none") + ".")
            w(f"- **{len(adv_open)}** still present.")
            w()
            w("| ID | Package | Advisory severity | Reach | Status |")
            w("|---|---|---|---|---|")
            for r in adv_fixed + adv_open:
                w(f"| {r['id']} | {r['packages']} | {r.get('advisory_severity', '')} | {r['verdict']} | "
                  f"{'fixed (VEX status: fixed)' if r in adv_fixed else 'still present'} |")
            w()

        w("## VEX check")
        w()
        if not a.vex:
            w("No VEX file was applied.")
            w()
        else:
            plain = {k: findings(os.path.join(a.new_dir, "reports", f"{k}.json"), k) for k in ("trivy", "grype")}
            vexed = {k: findings(os.path.join(a.new_dir, "reports", f"{k}-vex.json"), k) for k in ("trivy", "grype")}

            def verdict(k, cve, pkg):
                if plain[k] is None or vexed[k] is None:
                    return "report missing"
                before, after = (cve, pkg) in plain[k], (cve, pkg) in vexed[k]
                if before and not after:
                    return "suppressed"
                if not before and not after:
                    return "never reported"
                return "STILL REPORTED" if after else "?"

            w("Each scanner was run twice on the patched image, without and with the VEX file(s).")
            w()
            w("| VEX file | CVE | Package | Status claimed | Trivy | Grype |")
            w("|---|---|---|---|---|---|")
            outcomes = []
            for path in a.vex:
                doc = json.load(open(path))
                for st in doc.get("statements", []):
                    cve = (st.get("vulnerability") or {}).get("name", "?")
                    for prod in st.get("products", []):
                        pid = prod.get("@id", "")
                        pkg = pid.split("/")[-1].split("@")[0].split("?")[0] if pid.startswith("pkg:") else pid
                        t, g = verdict("trivy", cve, pkg), verdict("grype", cve, pkg)
                        outcomes += [t, g]
                        w(f"| `{os.path.basename(path)}` | {cve} | `{pkg}` | {st.get('status', '?')} | {t} | {g} |")
            w()
            w("- **suppressed**: reported without the VEX file, gone with it. The VEX file works.")
            w("- **never reported**: the scanner did not report this CVE for this package even")
            w("  without the VEX file, so there was nothing to suppress. For nginx built from")
            w("  nginx.org sources this is expected: see docs/scanner-blind-spot.md.")
            w("- **STILL REPORTED**: the VEX statement did not match. Check the package name and")
            w("  version in the product purl.")
            w()
            for k in ("trivy", "grype"):
                if plain[k] is not None and vexed[k] is not None:
                    w(f"{k.capitalize()}: {len(plain[k])} findings without VEX, {len(vexed[k])} with.")
            w()

    print(f"baseline {len(base)} CVEs -> patched {len(new)}: "
          f"{len(fixed)} no longer reported, {len(remaining)} still reported, {len(added)} new")
    print(f"upstream-advisory CVEs (not in either scan): {len(advisory)}: "
          f"{len(adv_fixed)} fixed, {len(adv_open)} still present")
    print(f"wrote diff.md and diff.csv in {a.new_dir}")


if __name__ == "__main__":
    sys.exit(main())
