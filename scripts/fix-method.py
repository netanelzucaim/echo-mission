#!/usr/bin/env python3
"""Decide how each CVE should be fixed: version bump, backport patch, or remove.

Usage:
    fix-method.py [SCAN_DIR] [CVE-ID ...] [--top N] [--remove-modules]
                  [--advisories FILE] [--refresh] [--out FILE]

    make fix-plan

For every CVE it answers the three questions the assignment's triage step asks:
    1. Which binary or library is affected?
    2. Does upstream have a fix, and in which version?
    3. Would it be fixed by a version bump, a backport patch, or removing the component?

It reads the scan folder written by scan-baseline.sh and compare-scans.py (default
scans/baseline) and writes SCAN_DIR/fix-plan.md.

Two sources are combined, because the scanners do not report nginx's own CVEs:
  * the scanner findings in triage.csv (the --top N by danger-and-reach score, or the
    CVE IDs given on the command line);
  * nginx's own security advisories, filtered to the installed nginx version. The page
    is saved to SCAN_DIR/image/nginx-security-advisories.html the first time and reused;
    --refresh downloads it again.

How the method is chosen
------------------------
  nginx itself, upstream advisory says this version is vulnerable
        -> BACKPORT. nginx must stay on the shipped 1.25.x line, so a newer nginx
           release is not an option; the upstream patch is adapted to this version.
  nginx itself, upstream advisory says this version is not vulnerable
        -> NONE. Scanner false positive; record the upstream statement.
  nginx itself, CVE not in upstream's advisories
        -> INVESTIGATE. Read the upstream changelog before claiming anything.
  a distribution package with a fixed version available
        -> VERSION BUMP to that version (the fresh base image provides it).
  a distribution package with no fixed version
        package only there for an optional module
            -> REMOVE the module if --remove-modules, otherwise ACCEPT (kept for
               compatibility) and list as residual risk.
        anything else
            -> ACCEPT and list as residual risk. A backport into that library is
               possible but means building the library from source too.

The script proposes; a person decides. It cannot tell whether nginx actually calls the
vulnerable function, and it does not read the patch. Check both before committing to
a fix.
"""
import argparse, csv, html, os, re, sys, urllib.request

ADVISORIES_URL = "https://nginx.org/en/security_advisories.html"
ORDER = {"BACKPORT": 0, "VERSION BUMP": 1, "REMOVE": 2, "INVESTIGATE": 3, "ACCEPT": 4, "NONE": 5}

# nginx modules that are only built when asked for with --with-http_<name>_module.
# Every other http module is built unless --without-http_<name>_module is given.
OPTIONAL_HTTP = {"ssl", "v2", "v3", "realip", "addition", "xslt", "image_filter", "geoip", "sub", "dav",
                 "flv", "mp4", "gunzip", "gzip_static", "auth_request", "random_index", "secure_link",
                 "degradation", "slice", "stub_status", "perl"}
# Advisory titles that name a feature without naming its module -> (label, configure flag or None).
KEYWORDS = [
    (r"HTTP/3|QUIC", "HTTP/3", "--with-http_v3_module"),
    (r"HTTP/2|SPDY", "HTTP/2", "--with-http_v2_module"),
    (r"CRAM-MD5|APOP|auth_http|XCLIENT|SMTP|mail", "mail proxy", "--with-mail"),
    (r"SSL|TLS|OCSP", "TLS", "--with-http_ssl_module"),
    (r"stream", "stream proxy", "--with-stream"),
]


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def in_ranges(version, text):
    """True if version falls in a list like '1.25.0-1.25.5, 1.26.0' or '1.27.1+, 1.26.2+'."""
    v = vtuple(version)
    for part in [p.strip() for p in text.split(",") if p.strip()]:
        if part.endswith("+"):
            lo = vtuple(part[:-1])
            # "1.26.2+" means that stable branch from .2 on; "1.27.1+" means everything later
            if v[:2] == lo[:2] and v >= lo:
                return True
            if lo[1] % 2 == 1 and v >= lo:      # odd minor = mainline: all later versions
                return True
        elif "-" in part:
            lo, hi = part.split("-", 1)
            if vtuple(lo) <= v <= vtuple(hi):
                return True
        elif re.match(r"^\d", part) and vtuple(part) == v:
            return True
    return False


def load_advisories(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    out = {}
    for item in re.findall(r"<li><p>(.*?)</p></li>", text, flags=re.S):
        cves = re.findall(r"CVE-\d{4}-\d+", item)
        if not cves:
            continue
        fields = [html.unescape(re.sub(r"<[^>]+>", "", f)).strip() for f in item.split("<br>")]
        get = lambda prefix: next((f[len(prefix):].strip() for f in fields if f.startswith(prefix)), "")
        patch = re.search(r'href="([^"]+)">The patch', item)
        advisory = re.search(r'href="([^"]+)">Advisory', item)
        entry = {"title": fields[0], "severity": get("Severity:"), "vulnerable": get("Vulnerable:"),
                 "not_vulnerable": get("Not vulnerable:"),
                 "patch": ("https://nginx.org" + patch.group(1)) if patch else "",
                 "advisory": advisory.group(1) if advisory else ""}
        for c in set(cves):
            out[c] = dict(entry, id=c)
    return out


def feature_of(title, configure):
    """Which part of nginx an advisory is about, and whether this build contains it."""
    found = []
    for kind, name in re.findall(r"ngx_(http|mail|stream)_(\w+?)_module", title):
        if kind == "mail":
            flag, present = "--with-mail", "--with-mail" in configure
        elif kind == "stream":
            flag, present = "--with-stream", "--with-stream" in configure
        elif name in OPTIONAL_HTTP:
            flag = f"--with-http_{name}_module"
            present = flag in configure
        else:
            present = f"--without-http_{name}_module" not in configure
        found.append((f"ngx_{kind}_{name}_module", present))
    if not found:
        for pattern, label, flag in KEYWORDS:
            if re.search(pattern, title, flags=re.I):
                found.append((label, flag in configure))
                break
    if not found:
        return "nginx core", "always present"
    names = " and ".join(n for n, _ in found)
    if all(p for _, p in found):
        return names, "compiled in"
    if not any(p for _, p in found):
        return names, "NOT compiled in"
    return names, "partly compiled in"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("args", nargs="*", help="optional scan folder, then optional CVE IDs")
    ap.add_argument("--top", type=int, default=15, help="scanner findings to include when no CVE IDs are given")
    ap.add_argument("--remove-modules", action="store_true",
                    help="project policy allows removing optional modules (default: keep them for compatibility)")
    ap.add_argument("--advisories", default=None, help="saved copy of nginx's security advisories page")
    ap.add_argument("--refresh", action="store_true", help="download the advisories page again")
    ap.add_argument("--out", default=None, help="default: SCAN_DIR/fix-plan.md")
    a = ap.parse_args()
    scan = next((x for x in a.args if not x.upper().startswith("CVE-")), "scans/baseline")
    wanted = [x.upper() for x in a.args if x.upper().startswith("CVE-")]

    img = os.path.join(scan, "image")
    triage = os.path.join(scan, "triage.csv")
    if not os.path.exists(triage):
        sys.exit(f"error: {triage} not found; run make scan-baseline and make triage first")
    rows = list(csv.DictReader(open(triage)))
    by_id = {r["id"]: r for r in rows}
    versions = {}
    for line in open(os.path.join(img, "packages.tsv")):
        p = line.rstrip("\n").split("\t")
        if len(p) >= 2:
            versions[p[0]] = p[1]
    linked = set(open(os.path.join(img, "linked-packages.txt")).read().split())
    module_of = {}
    mp = os.path.join(img, "modules.tsv")
    if os.path.exists(mp):
        for line in open(mp):
            p = line.split()
            if len(p) >= 2:
                module_of.setdefault(p[1], []).append(p[0].replace("nginx-module-", ""))
    nv = open(os.path.join(img, "nginx-V.txt")).read()
    nginx_version = re.search(r"nginx version: nginx/([\d.]+)", nv).group(1)
    configure = nv

    adv_path = a.advisories or os.path.join(img, "nginx-security-advisories.html")
    if a.refresh or not os.path.exists(adv_path):
        try:
            data = urllib.request.urlopen(ADVISORIES_URL, timeout=30).read()
            open(adv_path, "wb").write(data)
        except Exception as e:                                   # offline: carry on without it
            print(f"warning: could not download {ADVISORIES_URL}: {e}", file=sys.stderr)
    advisories = load_advisories(adv_path) if os.path.exists(adv_path) else {}

    def is_nginx(pkgs):
        return any(p == "nginx" or p.startswith("nginx-module-") for p in pkgs)

    plan = []          # dicts: id, where, fix, method, why, source, score

    # --- 1. scanner findings
    scanner_rows = [r for r in rows if r["trivy"] != "-" or r["grype"] != "-"]
    chosen = [by_id[c] for c in wanted if c in by_id and by_id[c] in scanner_rows] if wanted else scanner_rows[: a.top]
    for c in wanted:
        if c not in by_id and c not in advisories:
            print(f"warning: {c} is in neither the scan nor nginx's advisories", file=sys.stderr)
    for r in chosen:
        pkgs = r["packages"].split()
        fixed = r["fixed_versions"].split()
        installed = ", ".join(f"`{p}` {versions.get(p, '?')}" for p in pkgs[:3]) + (f" (+{len(pkgs) - 3})" if len(pkgs) > 3 else "")
        if is_nginx(pkgs):
            where = f"nginx itself ({installed})"
            ad = advisories.get(r["id"])
            if ad and in_ranges(nginx_version, ad["vulnerable"]):
                continue                                          # handled in part 2 with full detail
            if ad:
                method, fix = "NONE", f"upstream: not vulnerable in {ad['not_vulnerable']}"
                why = f"Upstream lists {nginx_version} as not vulnerable. Scanner false positive; record it."
            else:
                method, fix = "INVESTIGATE", "not in nginx's advisories"
                why = "Reported by a scanner but absent from upstream's advisory list. Read the nginx changelog before claiming it is fixed or open."
        else:
            mods = sorted({m for p in pkgs for m in module_of.get(p, [])})
            if set(pkgs) & linked:
                where = f"library nginx loads ({installed})"
            elif mods:
                where = f"library only for module {', '.join(mods)} ({installed})"
            else:
                where = f"other package, not used by nginx ({installed})"
            if fixed:
                method, fix = "VERSION BUMP", f"yes, in {fixed[0]}" + (f" (+{len(fixed) - 1} more)" if len(fixed) > 1 else "")
                why = "A fixed package exists in the distribution. The fresh base image installs it."
            elif mods and not (set(pkgs) & linked):
                fix = "no fixed version in the distribution"
                if a.remove_modules:
                    method, why = "REMOVE", f"No fix exists. Removing module {', '.join(mods)} takes this library out of the image."
                else:
                    method, why = "ACCEPT", (f"No fix exists. Removing module {', '.join(mods)} would clear it, but modules are "
                                             "kept for compatibility. List as residual risk.")
            else:
                method, fix = "ACCEPT", "no fixed version in the distribution"
                why = ("No fix exists and the package is needed. List as residual risk; a backport would mean "
                       "building this library from source.")
        plan.append({"id": r["id"], "where": where, "fix": fix, "method": method, "why": why,
                     "sev": f"{r['trivy']} / {r['grype']}", "score": float(r["score"]), "source": "scanners",
                     "reach": f"{r['verdict']} ({r['reach']})" if r.get("verdict") else "not reviewed",
                     "kev": r["known_exploited"] == "yes"})

    # --- 2. nginx's own advisories that apply to the installed version
    nginx_rows = []
    for cid, ad in advisories.items():
        if wanted and cid not in wanted:
            continue
        if not in_ranges(nginx_version, ad["vulnerable"]):
            continue
        feature, state = feature_of(ad["title"], configure)
        row = by_id.get(cid)      # review.tsv can add nginx.org CVEs to triage.csv; those have no scanner rating
        scanned = bool(row) and (row["trivy"] != "-" or row["grype"] != "-")
        seen = "reported by a scanner" if scanned else "not reported by either scanner"
        reach = f"{row['verdict']} ({row['reach']})" if row and row.get("verdict") else "not reviewed"
        method = "NONE" if state == "NOT compiled in" else "BACKPORT"
        why = ""
        nginx_rows.append({"id": cid, "title": ad["title"], "severity": ad["severity"], "vulnerable": ad["vulnerable"],
                           "fixed_in": ad["not_vulnerable"], "patch": ad["patch"], "advisory": ad["advisory"],
                           "feature": feature, "state": state, "method": method, "why": why, "seen": seen,
                           "reach": reach})
    sev_rank = {"critical": 0, "high": 1, "major": 1, "medium": 2, "low": 3}
    nginx_rows.sort(key=lambda r: (ORDER[r["method"]], sev_rank.get(r["severity"].lower(), 9), r["id"]))
    plan.sort(key=lambda r: (ORDER[r["method"]], -r["score"]))

    out = a.out or os.path.join(scan, "fix-plan.md")
    with open(out, "w") as f:
        w = lambda t="": f.write(t + "\n")
        w("# Fix plan: how each CVE would be fixed")
        w()
        w("Generated by `scripts/fix-method.py`. Do not edit by hand; rerun the script. It proposes a")
        w("method per CVE; the choice of which ones to fix, and the reasons, belong in the main README.")
        w()
        w(f"Image: nginx {nginx_version}. Policy: optional modules are "
          + ("removable" if a.remove_modules else "kept for compatibility") + ".")
        w()
        w("| Method | Meaning |")
        w("|---|---|")
        w("| BACKPORT | Stay on this version and adapt the upstream patch to it |")
        w("| VERSION BUMP | Install the newer package version that already has the fix |")
        w("| REMOVE | Take the vulnerable component out of the image |")
        w("| ACCEPT | No fix exists; keep it, and list it as residual risk |")
        w("| INVESTIGATE | Not enough information to choose; needs reading |")
        w("| NONE | Not vulnerable in this build |")
        w()
        w(f"## nginx's own CVEs that apply to {nginx_version}")
        w()
        if not advisories:
            w("The advisories page could not be read, so this section is empty. Rerun with network access.")
            w()
        elif not nginx_rows:
            w("None of upstream's advisories applies to this version.")
            w()
        else:
            w(f"From [nginx security advisories]({ADVISORIES_URL}), saved in `image/nginx-security-advisories.html`.")
            w("The scanners compare the nginx.org package with Debian's version numbers, so most of these")
            w("do not appear in the scan reports.")
            w()
            w("| CVE | What | Severity (upstream) | Where it lives | Reach verdict | Vulnerable versions | Fixed upstream in | Method | Upstream patch | In scan reports |")
            w("|---|---|---|---|---|---|---|---|---|---|")
            for r in nginx_rows:
                patch = f"[patch]({r['patch']})" if r["patch"] else "none published; take it from the fix commit"
                cve = f"[{r['id']}]({r['advisory']})" if r["advisory"] else r["id"]
                w(f"| {cve} | {r['title']} | {r['severity']} | {r['feature']}, {r['state']} | {r['reach']} | {r['vulnerable']} | "
                  f"{r['fixed_in']} | **{r['method']}** | {patch} | {r['seen']} |")
            w()
            line = ".".join(nginx_version.split(".")[:2])
            w(f"Why BACKPORT: the image must stay a replacement for nginx {line}, so moving to a newer nginx")
            w(f"release is not an option. The upstream fix is adapted to {nginx_version} and kept as a patch file.")
            w("A row marked NONE is about a feature this build does not contain. \"Reach verdict\" is the reviewed")
            w("answer to \"does this image run the vulnerable code\", from `review.tsv` (see the `triage-cves` skill).")
            w()
            ready = [r for r in nginx_rows if r["method"] == "BACKPORT" and r["patch"]]
            if ready:
                w("Backport candidates with a published upstream patch (the smallest, cleanest starting point): "
                  + ", ".join(r["id"] for r in ready) + ".")
                w()
        w("## Scanner findings" + ("" if wanted else f": top {len(chosen)} by danger and reach"))
        w()
        if plan:
            w("| CVE | Trivy / Grype | Where it lives | Reach verdict | Fix available | Method | Why |")
            w("|---|---|---|---|---|---|---|")
            for r in plan:
                kev = " (known exploited)" if r["kev"] else ""
                w(f"| {r['id']}{kev} | {r['sev']} | {r['where']} | {r['reach']} | {r['fix']} | **{r['method']}** | {r['why']} |")
            w()
        else:
            w("None selected.")
            w()
        counts = {}
        for r in plan + nginx_rows:
            counts[r["method"]] = counts.get(r["method"], 0) + 1
        w("## Summary")
        w()
        w("| Method | CVEs in this plan |")
        w("|---|---|")
        for m in sorted(counts, key=lambda m: ORDER[m]):
            w(f"| {m} | {counts[m]} |")
        w()
        w("Limits: the method comes from where the package is and whether a fixed version exists. The")
        w("script does not know whether nginx calls the vulnerable function, and it has not read any")
        w("patch. Confirm both before committing to a fix.")
    print(f"wrote {out}: " + ", ".join(f"{counts[m]} {m}" for m in sorted(counts, key=lambda m: ORDER[m])))


if __name__ == "__main__":
    sys.exit(main())
