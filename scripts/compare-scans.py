#!/usr/bin/env python3
"""Merge a Trivy and a Grype JSON report and rank vulnerabilities by risk.

Usage:
    compare-scans.py TRIVY_JSON GRYPE_JSON [--linked FILE] [--modules FILE]
                     [--review FILE] [--out-dir DIR] [--top N] [--csv-only]

Writes into DIR:
    triage.md   summary and the top N vulnerabilities, each explained
    triage.csv  every vulnerability, ranked, with its explanation
    stats.md    the statistics as Mermaid diagrams and tables (renders on GitHub)
With --csv-only, only triage.csv (what `make rescan` needs to compare scans).

--modules FILE is a two-column TSV (module, package) naming the packages that are
installed only for an optional module, for example an nginx module package and the
libraries it pulls in. With it, stats.md shows what each module costs.

--linked and --modules default to linked-packages.txt and modules.tsv next to
TRIVY_JSON, or in a sibling "image" folder (../image/), whichever exists.
--review defaults to review.tsv in the output folder.

The ranking answers "what is most dangerous and reaches the most deployments",
not "what has the scariest severity label".

    score = 100 * danger * reach

  danger (0..1) = 0.6 * exploitation + 0.4 * severity
      exploitation = 1.0 if the CVE is in CISA's Known Exploited list (KEV),
                     otherwise its EPSS probability (chance of exploitation
                     in the next 30 days). EPSS describes the bug anywhere,
                     not in this image; reach is what puts it in context.
      severity     = average of the two scanners' severities, scaled to 0..1
                     (Critical = 1, High = 0.75, Medium = 0.5, Low = 0.25).
                     A scanner that does not report the CVE counts as 0, so
                     findings both scanners agree on score higher. A CVE
                     added from REVIEW (not reported by either scanner) uses
                     the advisory's own severity instead.

  reach (0..1) = does this image actually run the vulnerable code?
      From REVIEW, when a person checked it (see the triage-cves skill):
          always 1.0   runs in every container, even with the default config
          common 0.8   runs under a common setup (TLS, HTTP/2, proxy_pass)
          config 0.5   needs a specific, less common feature switched on
          manual 0.2   only when someone runs a tool by hand in the container
          unused 0.05  the code is installed but nothing in the image calls it
          n/a    0.0   cannot happen here (other CPU, other version, absent)
          unknown      checked but not settled: the unreviewed default below
      Otherwise, by where the package sits (not reviewed):
          0.6  a library the main program loads (listed in --linked)
          0.3  installed only for an optional module (listed in --modules)
          0.2  anything else (tools and their libraries)

REVIEW is a tab-separated file: id, verdict, reason, evidence, and for CVEs the
scanners miss, package and severity. Lines starting with # are comments. An id of
the form pkg:NAME gives a verdict for every CVE in that package; it is used only
when every package the CVE affects has one, and a CVE-level line always wins.
Every row gets an explanation of its score in the explanation column of triage.csv.
"""
import argparse, collections, csv, json, os, sys

RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NEGLIGIBLE": 0, "UNKNOWN": 0}
NAME = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Negligible/Unknown"}
VERDICT_REACH = {"always": 1.0, "common": 0.8, "config": 0.5, "manual": 0.2,
                 "unused": 0.05, "n/a": 0.0}
UNREVIEWED_REACH = {"loaded": 0.6, "module": 0.3, "other": 0.2}
VERDICT_TEXT = {
    "always": "runs in every container, even with the default config",
    "common": "runs under a common setup",
    "config": "needs a specific feature switched on",
    "manual": "only reached when someone runs a tool by hand",
    "unused": "installed, but nothing in the image calls the vulnerable code",
    "n/a": "cannot happen in this image",
    "unknown": "checked, but not settled",
}
ADVISORY_SEV = {"critical": 4, "major": 3, "high": 3, "medium": 2, "moderate": 2, "low": 1}


def sev(s):
    return RANK.get((s or "UNKNOWN").upper(), 0)


def sev_name(s):
    return (s or "Unknown").capitalize()


def new_entry(vid):
    return {"id": vid, "trivy": None, "grype": None, "pkgs": set(), "fixes": set(),
            "kev": False, "epss": 0.0, "cvss": 0.0, "title": "", "advisory": None}


def load_trivy(path, vulns, findings):
    data = json.load(open(path))
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            findings[sev_name(v.get("Severity"))] += 1
            e = vulns.setdefault(v["VulnerabilityID"], new_entry(v["VulnerabilityID"]))
            e["trivy"] = max(e["trivy"] if e["trivy"] is not None else -1, sev(v.get("Severity")))
            e["pkgs"].add(v.get("PkgName", "?"))
            if v.get("FixedVersion"):
                e["fixes"].add(v["FixedVersion"])
            e["title"] = e["title"] or (v.get("Title") or "")
            for src in (v.get("CVSS") or {}).values():
                e["cvss"] = max(e["cvss"], src.get("V3Score") or 0.0)


def load_grype(path, vulns, findings):
    data = json.load(open(path))
    for m in data.get("matches", []) or []:
        v = m["vulnerability"]
        findings[sev_name(v.get("severity"))] += 1
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


def load_review(path):
    """id -> {verdict, reason, evidence, package, severity}. Missing file: empty."""
    review = {}
    if not os.path.exists(path):
        return review
    for n, line in enumerate(open(path), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cols = (line.rstrip("\n").split("\t") + [""] * 6)[:6]
        if cols[0] == "id":
            continue
        vid, verdict, reason, evidence, package, severity = (c.strip() for c in cols)
        if verdict not in VERDICT_REACH and verdict != "unknown":
            sys.exit(f"{path}:{n}: unknown verdict {verdict!r}")
        review[vid] = {"verdict": verdict, "reason": reason, "evidence": evidence,
                       "package": package, "severity": severity.lower()}
    return review


def load_foreign(path):
    """Packages that do not come from the distribution's repositories.
    Returns (list of dicts, checked). checked is False when the scan could not tell."""
    if not os.path.exists(path):
        return [], False
    out, checked = [], True
    for line in open(path):
        if line.startswith("# not checked"):
            checked = False
        if not line.strip() or line.startswith("#"):
            continue
        c = (line.rstrip("\n").split("\t") + [""] * 5)[:5]
        out.append({"package": c[0], "installed": c[1], "distro": c[2], "why": c[3], "maintainer": c[4]})
    return out, checked


def add_unreported(vulns, review):
    """CVEs a person added to the review (e.g. from the upstream advisories) that no
    scanner reports. They have no EPSS, so only severity counts toward danger."""
    for vid, r in review.items():
        if vid in vulns or not r["package"]:
            continue
        e = vulns[vid] = new_entry(vid)
        e["pkgs"].add(r["package"])
        e["advisory"] = ADVISORY_SEV.get(r["severity"], 0)
        e["title"] = r["reason"].split(". ")[0]


def where(e, linked, mod_pkgs):
    return "loaded" if e["pkgs"] & linked else "module" if e["pkgs"] & mod_pkgs else "other"


def score(e, linked, mod_pkgs, review):
    exploitation = 1.0 if e["kev"] else e["epss"]
    if e["advisory"] is not None:
        severity = e["advisory"] / 4.0
    else:
        severity = ((e["trivy"] or 0) + (e["grype"] or 0)) / 8.0
    e["exploitation"], e["severity"] = exploitation, severity
    e["danger"] = 0.6 * exploitation + 0.4 * severity
    e["linked"] = sorted(e["pkgs"] & linked)
    e["where"] = where(e, linked, mod_pkgs)
    e["review"] = review.get(e["id"])
    e["scope"] = "CVE"
    if not e["review"]:
        per_pkg = [review.get("pkg:" + p) for p in sorted(e["pkgs"])]
        if per_pkg and all(r and r["verdict"] in VERDICT_REACH for r in per_pkg):
            e["review"] = max(per_pkg, key=lambda r: VERDICT_REACH[r["verdict"]])
            e["scope"] = "package"
    v = e["review"]["verdict"] if e["review"] else None
    e["verdict"] = v or "not reviewed"
    e["reach"] = VERDICT_REACH[v] if v in VERDICT_REACH else UNREVIEWED_REACH[e["where"]]
    e["score"] = 100.0 * e["danger"] * e["reach"]


def explain(e, rank, modules):
    """Why this CVE sits where it does, in plain sentences."""
    pk = ", ".join(f"`{p}`" for p in sorted(e["pkgs"]))
    out = [f"#{rank}, score {e['score']:.1f} = 100 x danger {e['danger']:.3f} x reach {e['reach']:.2f}."]
    if e["kev"]:
        ex = "on CISA's known-exploited list, so exploitation counts as 1.0"
    elif e["advisory"] is not None:
        ex = "no EPSS (the scanners do not report it), so exploitation counts as 0"
    else:
        ex = f"EPSS {e['epss'] * 100:.1f}% chance of exploitation in the next 30 days (anywhere, not in this image)"
    if e["advisory"] is not None:
        sv = f"the advisory rates it {NAME[e['advisory']]}"
    else:
        sv = f"Trivy {label(e['trivy'])}, Grype {label(e['grype'])}"
        if e["trivy"] is None or e["grype"] is None:
            sv += " (a missing scanner counts as 0)"
    out.append(f"Danger: {ex} (x 0.6 = {0.6 * e['exploitation']:.3f}); severity {sv} "
               f"(x 0.4 = {0.4 * e['severity']:.3f}).")
    r = e["review"]
    if r and r["verdict"] in VERDICT_REACH:
        scope = "" if e["scope"] == "CVE" else " for the whole package, not this CVE alone"
        out.append(f"Reach {e['reach']:.2f}, reviewed{scope} as **{r['verdict']}** "
                   f"({VERDICT_TEXT[r['verdict']]}): {r['reason']}")
    else:
        if e["where"] == "loaded":
            why = (f"nginx loads {', '.join('`%s`' % p for p in e['linked'])}, but whether it calls "
                   "the vulnerable code was not checked")
        elif e["where"] == "module":
            mods = sorted(m for m, ps in modules.items() if e["pkgs"] & ps)
            why = (f"{pk} is installed only for {', '.join('`%s`' % m for m in mods)}, "
                   "which no default config loads")
        else:
            why = f"{pk} is used by other programs in the image, not by nginx"
        tag = "checked but not settled" if r else "not reviewed"
        out.append(f"Reach {e['reach']:.2f} ({tag}, default for where the package sits): {why}."
                   + (f" Note: {r['reason']}" if r else ""))
    if r and r["evidence"]:
        out.append(f"Evidence: {r['evidence']}.")
    if e["advisory"] is not None:
        out.append("Fix: newer upstream version or a backported patch (not a distro package).")
    elif e["fixes"]:
        out.append(f"Fix: a fixed package exists ({', '.join(sorted(e['fixes']))}).")
    else:
        out.append("Fix: no fixed package version yet.")
    return " ".join(out)


def pie(title, slices):
    lines = ["```mermaid", f"pie showData title {title}"]
    lines += [f'    "{name}" : {n}' for name, n in slices if n > 0]
    return "\n".join(lines + ["```", ""])


def write_stats(path, rows, linked, modules, t_find, g_find, names):
    """Diagrams and tables for the whole report set. Everything is computed from the data."""
    hi = lambda e: max(e["trivy"] or 0, e["grype"] or 0) >= 3
    both = [e for e in rows if e["trivy"] is not None and e["grype"] is not None]
    mod_pkgs = set(p for ps in modules.values() for p in ps)
    where = lambda e: "loaded" if e["linked"] else "module" if e["pkgs"] & mod_pkgs else "other"
    groups = collections.Counter(where(e) for e in rows)
    fixed = collections.Counter((where(e), bool(e["fixes"])) for e in rows)
    t_u = sum(1 for e in rows if e["trivy"] is not None)
    g_u = sum(1 for e in rows if e["grype"] is not None)
    n = len(rows)
    with open(path, "w") as f:
        w = lambda text="": f.write(text + "\n")
        w("# Scan statistics")
        w()
        w(f"Generated by `scripts/compare-scans.py` from `{names[0]}` and `{names[1]}`. Do not edit by")
        w("hand; rerun the script. Counts are unique CVEs unless a line says \"findings\". GitHub")
        w("renders the diagrams; in a plain text editor they appear as code.")
        w()
        w(f"## How the {n} break down")
        w()
        w("```mermaid")
        w("flowchart TD")
        w(f'    T["Trivy<br/>{sum(t_find.values())} findings<br/>{t_u} unique CVEs"] --> U')
        w(f'    G["Grype<br/>{sum(g_find.values())} findings<br/>{g_u} unique CVEs"] --> U')
        w(f'    U["{n} unique CVEs"]')
        w(f'    U --> B["{len(both)} reported by both scanners"]')
        w(f'    U --> TO["{n - g_u} Trivy only"]')
        w(f'    U --> GO["{n - t_u} Grype only"]')
        w(f'    B --> BS["{sum(1 for e in both if e["trivy"] == e["grype"])} same severity"]')
        w(f'    B --> BD["{sum(1 for e in both if e["trivy"] != e["grype"])} different severity"]')
        if linked:
            w(f'    U --> L["{groups["loaded"]} in packages the main program loads"]')
            w(f'    L --> LF["{fixed[("loaded", True)]} have a fix"]')
            if modules:
                w(f'    U --> M["{groups["module"]} in optional modules\' packages"]')
                w(f'    M --> MF["{fixed[("module", True)]} have a fix"]')
            w(f'    U --> O["{groups["other"]} in other packages"]')
            w(f'    O --> OF["{fixed[("other", True)]} have a fix"]')
        w("```")
        w()
        if linked:
            w("## Where the vulnerabilities live")
            w()
            w(pie(f"Unique CVEs by where the package sits ({n})", [
                ("The main program and the libraries it loads", groups["loaded"]),
                ("Packages of optional modules", groups["module"]),
                ("Other tools and their libraries", groups["other"])]))
            per = collections.Counter(p for e in rows for p in e["linked"])
            w(pie("CVEs in loaded packages, by package", sorted(per.items(), key=lambda kv: (-kv[1], kv[0]))))
        w("## How severe")
        w()
        top = collections.Counter(NAME[max(e["trivy"] or 0, e["grype"] or 0)] for e in rows)
        w(pie(f"Unique CVEs by highest severity from either scanner ({n})",
              [(NAME[k], top[NAME[k]]) for k in (4, 3, 2, 1, 0)]))
        w("Findings per scanner (the same CVE in two packages counts twice):")
        w()
        w("| Severity | Trivy | Grype |")
        w("|---|---|---|")
        for k in ("Critical", "High", "Medium", "Low", "Negligible", "Unknown"):
            w(f"| {k} | {t_find[k]} | {g_find[k]} |")
        w(f"| **Total findings** | **{sum(t_find.values())}** | **{sum(g_find.values())}** |")
        w()
        w("## Do the scanners agree")
        w()
        w(pie(f"Agreement between Trivy and Grype ({n} unique CVEs)", [
            ("Both, same severity", sum(1 for e in both if e["trivy"] == e["grype"])),
            ("Both, different severity", sum(1 for e in both if e["trivy"] != e["grype"])),
            ("Trivy only", n - g_u), ("Grype only", n - t_u)]))
        w(f"{sum(1 for e in both if e['trivy'] == 4 and e['grype'] == 4)} CVEs are Critical in both scanners.")
        w()
        w("## Can it be fixed by updating")
        w()
        w(pie(f"Is a fixed package version available ({n} unique CVEs)", [
            ("Fix available", sum(1 for e in rows if e["fixes"])),
            ("No fix yet", sum(1 for e in rows if not e["fixes"]))]))
        w("## How likely to be exploited")
        w()
        kev = [e for e in rows if e["kev"]]
        kev_txt = ", ".join(f"{e['id']} in `{sorted(e['pkgs'])[0]}`" for e in kev)
        w("| Signal | Unique CVEs |")
        w("|---|---|")
        w(f"| On CISA's known-exploited list (KEV) | {len(kev)}{' (' + kev_txt + ')' if kev else ''} |")
        w(f"| EPSS of 10% or more | {sum(1 for e in rows if e['epss'] >= 0.10)} |")
        w(f"| EPSS of 1% or more | {sum(1 for e in rows if e['epss'] >= 0.01)} |")
        w(f"| EPSS below 1% | {sum(1 for e in rows if e['epss'] < 0.01)} |")
        w()
        if modules:
            w("## Optional modules")
            w()
            w("Packages installed only because of each module. Counts overlap where two")
            w(f"modules share a package; together they account for {groups['module']}.")
            w()
            w("| Module | Packages it brings in | CVEs in them | Critical or High | With a fix |")
            w("|---|---|---|---|---|")
            table = []
            for c, ps in modules.items():
                hit = [e for e in rows if e["pkgs"] & ps]
                table.append((len(hit), c, len(ps), sum(map(hi, hit)), sum(1 for e in hit if e["fixes"])))
            for cves, c, npk, nhi, nfix in sorted(table, reverse=True):
                w(f"| `{c}` | {npk} | {cves} | {nhi} | {nfix} |")
            w()
        w("## Packages with the most CVEs")
        w()
        w("| Package | Unique CVEs | Critical or High | Loaded by the main program |")
        w("|---|---|---|---|")
        per_pkg = collections.Counter(p for e in rows for p in e["pkgs"])
        for p, c in sorted(per_pkg.items(), key=lambda kv: (-kv[1], kv[0]))[:12]:
            nhi = sum(1 for e in rows if p in e["pkgs"] and hi(e))
            w(f"| `{p}` | {c} | {nhi} | {'Yes' if p in linked else 'No'} |")


SCORE_NOTE = (
    "Score = 100 x danger x reach. Danger = 0.6 x exploitation (1 if known exploited, else "
    "EPSS) + 0.4 x severity. Reach comes from a person's review of whether this image runs "
    "the vulnerable code (always 1.0, common 0.8, config 0.5, manual 0.2, unused 0.05, n/a 0); "
    "without a review it is 0.6 for a library nginx loads, 0.3 for a module-only package and "
    "0.2 for anything else. The weights are judgment calls, not measurements. Vulnerabilities "
    "that neither the scanners nor the review list are not here.\n")


def label(x):
    return "-" if x is None else NAME[x]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trivy_json")
    ap.add_argument("grype_json")
    ap.add_argument("--linked", default=None,
                    help="file listing the packages the main program loads, one per line "
                         "(default: linked-packages.txt next to TRIVY_JSON or in ../image/)")
    ap.add_argument("--modules", default=None,
                    help="TSV of module<TAB>package for optional modules "
                         "(default: modules.tsv next to TRIVY_JSON or in ../image/)")
    ap.add_argument("--review", default=None,
                    help="TSV of reviewed reach verdicts (default: review.tsv in the output folder)")
    ap.add_argument("--out-dir", default=None, help="default: directory of TRIVY_JSON")
    ap.add_argument("--top", type=int, default=40, help="rows in the markdown table")
    ap.add_argument("--csv-only", action="store_true", help="write only triage.csv")
    a = ap.parse_args()
    src_dir = os.path.dirname(os.path.abspath(a.trivy_json))
    out = a.out_dir or src_dir
    os.makedirs(out, exist_ok=True)

    def find(name):  # next to the report, or in a sibling "image" folder
        for d in (src_dir, os.path.join(os.path.dirname(src_dir), "image")):
            if os.path.exists(os.path.join(d, name)):
                return os.path.join(d, name)
        return os.path.join(src_dir, name)

    linked_path = a.linked or find("linked-packages.txt")
    linked = set()
    if os.path.exists(linked_path):
        linked = set(open(linked_path).read().split())
    else:
        print(f"warning: no linked-packages file ({linked_path}); reach is not "
              "distinguishing libraries the main program loads", file=sys.stderr)

    modules = collections.OrderedDict()
    mod_path = a.modules or find("modules.tsv")
    if os.path.exists(mod_path):
        for line in open(mod_path):
            parts = line.split()
            if len(parts) >= 2:
                modules.setdefault(parts[0], set()).add(parts[1])

    vulns = {}
    t_find, g_find = collections.Counter(), collections.Counter()
    load_trivy(a.trivy_json, vulns, t_find)
    load_grype(a.grype_json, vulns, g_find)
    review_path = a.review or os.path.join(out, "review.tsv")
    review = load_review(review_path)
    if not review:
        print(f"warning: no review file ({review_path}); every reach is the unreviewed default",
              file=sys.stderr)
    add_unreported(vulns, review)
    mod_pkgs = set(p for ps in modules.values() for p in ps)
    for e in vulns.values():
        score(e, linked, mod_pkgs, review)
    rows = sorted(vulns.values(), key=lambda e: (e["score"], bool(e["fixes"]), e["cvss"], e["id"]),
                  reverse=True)
    for i, e in enumerate(rows, 1):
        e["why"] = explain(e, i, modules)
    stale = sorted(k for k in set(review) - set(vulns) if not k.startswith("pkg:"))
    if stale:
        print(f"warning: {len(stale)} reviewed IDs are not in the reports and have no package "
              f"column: {', '.join(stale[:5])}", file=sys.stderr)

    both = [e for e in rows if e["trivy"] is not None and e["grype"] is not None]
    in_linked = [e for e in rows if e["linked"]]

    # Packages not from the distribution: the scanners judge them by the distribution's
    # version numbers, which is wrong for them. Their CVEs must come from upstream.
    foreign, foreign_checked = load_foreign(find("foreign-packages.tsv"))
    for fp in foreign:
        fp["scanner"] = sum(1 for e in rows if fp["package"] in e["pkgs"] and e["advisory"] is None)
        fp["upstream"] = sum(1 for e in rows if fp["package"] in e["pkgs"] and e["advisory"] is not None)
    # a module package shares its source with the main one: one advisory list covers the family
    family_upstream = sum(fp["upstream"] for fp in foreign)
    if foreign and not family_upstream:
        print("WARNING: " + ", ".join(fp["package"] for fp in foreign) + " do not come from the "
              "distribution, and no CVE from their upstream advisories is in the review. The scanner "
              "results for them cannot be trusted. Add the upstream advisories to review.tsv "
              "(see the triage-cves skill).", file=sys.stderr)
    if not foreign_checked:
        print("warning: the scan could not check which packages are not from the distribution "
              "(image/foreign-packages.tsv missing or not checked); rerun the scan with network access",
              file=sys.stderr)

    with open(os.path.join(out, "triage.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rank", "id", "score", "danger", "reach", "verdict", "loaded_by_main_program",
                    "trivy", "grype", "advisory_severity", "packages", "fix_available",
                    "fixed_versions", "known_exploited", "epss", "cvss", "title", "explanation"])
        for i, e in enumerate(rows, 1):
            w.writerow([i, e["id"], f'{e["score"]:.1f}', f'{e["danger"]:.3f}', f'{e["reach"]:.2f}',
                        e["verdict"], "yes" if e["linked"] else "no", label(e["trivy"]),
                        label(e["grype"]), label(e["advisory"]), " ".join(sorted(e["pkgs"])),
                        "yes" if e["fixes"] else "no", " ".join(sorted(e["fixes"])),
                        "yes" if e["kev"] else "no", f'{e["epss"]:.4f}', e["cvss"], e["title"],
                        e["why"]])

    if a.csv_only:
        print(f"{len(rows)} unique vulnerabilities; wrote triage.csv in {out}")
        return 0

    reviewed = [e for e in rows if e["review"] and e["verdict"] in VERDICT_REACH]
    by_cve = sum(1 for e in reviewed if e["scope"] == "CVE")
    verdicts = collections.Counter(e["verdict"] for e in rows)
    with open(os.path.join(out, "triage.md"), "w") as f:
        f.write("# Vulnerabilities ranked by danger and reach\n\n")
        f.write(f"Inputs: `{os.path.basename(a.trivy_json)}`, `{os.path.basename(a.grype_json)}`"
                f"{', `' + os.path.basename(review_path) + '`' if review else ''}. "
                "Full list, every score explained: `triage.csv`.\n\n")
        f.write("| | Count |\n|---|---|\n")
        f.write(f"| Unique vulnerabilities | {len(rows)} |\n")
        f.write(f"| Reported by both scanners | {len(both)} |\n")
        f.write(f"| Trivy only | {sum(1 for e in rows if e['trivy'] is not None and e['grype'] is None)} |\n")
        f.write(f"| Grype only | {sum(1 for e in rows if e['grype'] is not None and e['trivy'] is None)} |\n")
        f.write(f"| Added from the review, missed by both scanners | {sum(1 for e in rows if e['advisory'] is not None)} |\n")
        f.write(f"| Critical in both | {sum(1 for e in both if e['trivy'] == 4 and e['grype'] == 4)} |\n")
        f.write(f"| Known exploited (KEV) | {sum(1 for e in rows if e['kev'])} |\n")
        f.write(f"| In a library the main program loads | {len(in_linked)} |\n")
        f.write(f"| ...of those, with a fix available | {sum(1 for e in in_linked if e['fixes'])} |\n")
        f.write(f"| Reach checked by a person | {len(reviewed)} ({by_cve} one by one, "
                f"{len(reviewed) - by_cve} through a package-level verdict) |\n\n")
        f.write("Reach verdicts: " + ", ".join(
            f"{k} {verdicts[k]}" for k in list(VERDICT_REACH) + ["unknown", "not reviewed"] if verdicts[k])
            + ".\n\n")
        if linked:
            f.write("Libraries the main program loads: " + ", ".join(f"`{p}`" for p in sorted(linked)) + ".\n\n")
        else:
            f.write("No linked-packages file was given, so reach does not separate libraries the "
                    "main program loads from packages that only sit in the image.\n\n")
        f.write("## Packages that are not from the distribution\n\n")
        if not foreign_checked:
            f.write("**Not checked.** The scan could not compare the installed packages with the "
                    "distribution's repositories (no network). Until it can, assume the main program "
                    "may be one of them and take its CVEs from the upstream project's advisories.\n\n")
        elif not foreign:
            f.write("None. Every installed package comes from the distribution, so the scanners' "
                    "version comparison applies to all of them.\n\n")
        else:
            f.write("The scanners compare every package with the distribution's security data. These "
                    "packages were installed from somewhere else, so that comparison is wrong for them: "
                    "a CVE the distribution fixed in its own older version looks fixed here too. Their "
                    "CVEs must be taken from the upstream project's advisories for the exact installed "
                    "version, and added through `review.tsv`.\n\n")
            f.write("| Package | Installed | Newest in the distribution | Why it is listed | CVEs from the scanners | CVEs added from upstream advisories |\n")
            f.write("|---|---|---|---|---|---|\n")
            for fp in foreign:
                f.write(f"| `{fp['package']}` | {fp['installed']} | {fp['distro']} | {fp['why']} | "
                        f"{fp['scanner']} | {fp['upstream']} |\n")
            f.write("\n")
            if family_upstream:
                f.write(f"{family_upstream} CVEs from upstream advisories are in the ranking. Module packages "
                        "built from the main package's source are covered by its advisories; a module with "
                        "its own source (for example njs) has its own advisory list and needs its own check.\n\n")
            else:
                f.write("**No upstream advisory has been added for these packages. The ranking is missing "
                        "their CVEs.** Follow the `triage-cves` skill, step 3.\n\n")
        top = rows[: a.top]
        f.write(f"## Top {len(top)}\n\n")
        f.write("| # | ID | Score | Danger | Reach | Verdict | Packages | Fix | KEV | EPSS |\n"
                "|---|---|---|---|---|---|---|---|---|---|\n")
        for i, e in enumerate(top, 1):
            pk = sorted(e["pkgs"])
            pk = ", ".join(pk[:3]) + (f" (+{len(pk) - 3})" if len(pk) > 3 else "")
            fix = "upstream" if e["advisory"] is not None else "yes" if e["fixes"] else "no"
            epss = "-" if e["advisory"] is not None else f"{e['epss'] * 100:.1f}%"
            f.write(f"| {i} | {e['id']} | {e['score']:.1f} | {e['danger']:.2f} | {e['reach']:.2f} | "
                    f"{e['verdict']} | {pk} | {fix} | {'yes' if e['kev'] else ''} | {epss} |\n")
        f.write(f"\n## Why each is ranked where it is\n\n")
        for i, e in enumerate(top, 1):
            f.write(f"**{e['id']}**: {e['why']}\n\n")
        f.write(SCORE_NOTE)

    # stats.md describes what the scanners found; CVEs added from the review are left out
    write_stats(os.path.join(out, "stats.md"), [e for e in rows if e["advisory"] is None], linked, modules, t_find, g_find,
                (os.path.basename(a.trivy_json), os.path.basename(a.grype_json)))

    print(f"{len(rows)} unique vulnerabilities, {len(both)} in both, "
          f"{len(in_linked)} in libraries the main program loads")
    print(f"{len(reviewed)} with a reviewed reach, "
          f"{sum(1 for e in rows if e['advisory'] is not None)} added from the review")
    print(f"wrote triage.md, triage.csv and stats.md in {out}")


if __name__ == "__main__":
    sys.exit(main())
