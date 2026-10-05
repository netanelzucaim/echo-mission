#!/usr/bin/env python3
"""Write an OpenVEX document saying a CVE does not apply to packages in an image.

Usage:
    make-vex.py --cve CVE-2024-7347 --package nginx --scan-dir scans/patched \\
                --note "Fixed by build/patches/CVE-2024-7347.patch (backport of upstream commit ...)" \\
                [--status fixed|not_affected] [--justification CODE] \\
                [--author "Name <email>"] [--out vex/CVE-2024-7347.openvex.json]

Scanners match on package name and version, so a backported fix keeps being reported.
A VEX statement tells them the CVE is handled in this build. Trivy and Grype both
accept the file with --vex and drop the matching findings.

One statement is written per CVE, with one product per --package. Each product is the
package's purl (pkg:deb/<distro>/<name>@<version>), which is the form both scanners
were tested to honour. The version comes from SCAN_DIR/image/packages.tsv, so run the
scan of the image first. Name every binary package that carries the fix: a statement
for libssl3 does not cover the openssl package.

--status fixed          the vulnerable code was patched in this build (use for backports)
--status not_affected   the code is present but cannot be exploited here; requires
                        --justification, one of: component_not_present,
                        vulnerable_code_not_present, vulnerable_code_not_in_execute_path,
                        vulnerable_code_cannot_be_controlled_by_adversary,
                        inline_mitigations_already_exist

Only write a statement that is true and that you can point to evidence for.
"""
import argparse, datetime, hashlib, json, os, sys

JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present",
                  "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary",
                  "inline_mitigations_already_exist")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cve", required=True)
    ap.add_argument("--package", required=True, action="append",
                    help="binary package name; repeat for every package that carries the fix")
    ap.add_argument("--scan-dir", required=True, help="scan folder of the image (has image/packages.tsv)")
    ap.add_argument("--note", required=True, help="what was done and where the evidence is")
    ap.add_argument("--status", default="fixed", choices=("fixed", "not_affected"))
    ap.add_argument("--justification", choices=JUSTIFICATIONS)
    ap.add_argument("--distro", default="debian", help="purl namespace (default: debian)")
    ap.add_argument("--author", default=None, help='default: git config user.name <user.email>')
    ap.add_argument("--out", default=None, help="default: vex/<CVE>.openvex.json")
    a = ap.parse_args()

    if a.status == "not_affected" and not a.justification:
        ap.error("--status not_affected requires --justification")
    if a.status == "fixed" and a.justification:
        ap.error("--justification only applies to --status not_affected")

    versions = {}
    tsv = os.path.join(a.scan_dir, "image", "packages.tsv")
    if not os.path.exists(tsv):
        sys.exit(f"error: {tsv} not found; scan the image first")
    for line in open(tsv):
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2:
            versions[parts[0]] = parts[1]
    missing = [p for p in a.package if p not in versions]
    if missing:
        sys.exit(f"error: not installed in the scanned image: {', '.join(missing)}")

    author = a.author
    if not author:
        get = lambda k: os.popen(f"git config {k} 2>/dev/null").read().strip()
        author = f"{get('user.name')} <{get('user.email')}>".strip()
        if author == "<>":
            sys.exit("error: pass --author (git user.name / user.email are not set)")

    statement = {
        "vulnerability": {"name": a.cve},
        "products": [{"@id": f"pkg:deb/{a.distro}/{p}@{versions[p]}"} for p in a.package],
        "status": a.status,
    }
    if a.status == "not_affected":
        statement["justification"] = a.justification
        statement["impact_statement"] = a.note
    else:
        statement["status_notes"] = a.note

    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "",
        "author": author,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": 1,
        "statements": [statement],
    }
    digest = hashlib.sha256(json.dumps(doc["statements"], sort_keys=True).encode()).hexdigest()
    doc["@id"] = f"https://openvex.dev/docs/public/vex-{digest}"

    out = a.out or os.path.join("vex", f"{a.cve}.openvex.json")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print(f"wrote {out}: {a.cve} {a.status} for "
          + ", ".join(f"{p} {versions[p]}" for p in a.package))


if __name__ == "__main__":
    sys.exit(main())
