# Rescan and VEX (bonus)

Back to the [README](../README.md). Results: [`scans/patched/diff.md`](../scans/patched/diff.md).

The bonus asks for a VEX document for a backport-patched CVE, and for the scanner to be
re-run with it applied so the CVE disappears from the report. Our image splits that into
a deliverable, a documented reason, and an optional proof — on purpose, because of the
[scanner blind spot](scanner-blind-spot.md).

**1. The deliverable: a VEX for the backported CVE.** The backport is CVE-2026-42945
(rewrite module), so `vex/CVE-2026-42945.openvex.json` is a VEX with `status: fixed`
pointing at `build/patches/CVE-2026-42945.patch`. This is the document the bonus asks
for, and it is the formal record that the fix is in the build.

**2. Why it does not shrink the rescan — and why that is expected.** The CVE never
appears in the scan in the first place, for exactly the reason in the [scanner blind spot](scanner-blind-spot.md):
nginx is the nginx.org package, so the scanners compare it with Debian's data and do
not report its CVEs at all. A VEX can only remove a finding that exists, so a `fixed`
VEX for a backported nginx CVE has nothing to suppress. This is not a gap in the work;
it is a sharper case of the brief's own heads-up that *"scanners won't shrink your CVE
list for backported fixes"* — here they never listed it to begin with. The real
evidence that the backport works is the patch itself plus the rewrite scenario added to
the compatibility test, not a scan diff.

**3. Optional proof that the VEX mechanic works.** Because the backported CVE cannot
visibly disappear, the "re-run and watch it vanish" is demonstrated on a CVE the
scanners *do* report: `vex/CVE-2023-52355.openvex.json`, a `not_affected` statement for
libtiff6 (CVE-2023-52355). `not_affected` means the vulnerable code is present but
unreachable here — image-filter links libtiff only through libgd and asks it for
JPEG/GIF/PNG/WebP, never TIFF, and the module is not loaded by default
(justification `vulnerable_code_not_in_execute_path`). This CVE has no Debian fix, so
the base upgrade cannot remove it, which is what makes it a stable demonstration.
Verified on the baseline image on 2026-10-05: with the VEX applied, CVE-2023-52355
disappears from Trivy (dropped) and from Grype (moved to `ignoredMatches`).

So: the backport VEX is the deliverable; the foreign-nginx situation is the documented
reason it does not change the scan; the libtiff `not_affected` VEX is the optional
end-to-end proof that the mechanic works.
