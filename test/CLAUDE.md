# test/: the compatibility test

`make test` runs `compat_test.py --candidate echo-nginx:1.25-bookworm`. It starts the
original and the candidate side by side, sends both the same raw HTTP requests, and
compares status, headers and body, plus image settings, file layout, startup logs and
shutdown. It exits 1 on any mismatch. What it covers and what "working correctly" means:
`test/README.md`.

Current result: 92 checks, 91 match, 1 allowed difference, 0 mismatch.

## Rules

- **The original image is the specification.** Never relax a comparison to make the
  test pass. Either fix the image, or add the difference to `ALLOWED` in
  `compat_test.py` with a reason and record it in `docs/image-config.md`.
- `ALLOWED` holds one entry, the `maintainer` label. Keep it that way unless the owner
  decides otherwise.
- **Every new scenario needs an `expect`** (what the original must return), so two
  equally broken servers cannot "match".
- **Backported code paths get a scenario with normal input**, never attack input. The
  CVE-2026-42945 backport is covered by "rewrite capture reused after a replacement with
  args" in the custom-config group: same output as the original.
- After the test was written it was checked both ways: against the original itself (all
  match) and against a deliberately altered image (it fails). Do the same after a large
  change to the test.

## make fsdiff

`make test` only inspects the nginx paths. `make fsdiff` (`scripts/fs-diff.sh`) lists
every file in both images and fails on anything not explained by the newer Debian base.
Run it after any build change; it found the missing njs CLI and leaked proxy files.
It compares file names, not contents.
