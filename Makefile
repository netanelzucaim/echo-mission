# The patched image. Override on the command line: make test IMAGE=my-image:tag
IMAGE ?= echo-nginx:1.25-bookworm

.PHONY: scan-baseline triage test rescan

scan-baseline: ## Step 1: scan the original image with Trivy and Grype
	./scripts/scan-baseline.sh

triage: ## Step 2: merge the Trivy and Grype reports and rank by urgency
	python3 scripts/compare-scans.py scans/baseline/reports/trivy.json scans/baseline/reports/grype.json --out-dir scans/baseline

test: ## Step 5: compare the patched image with the original (exit code 1 on any mismatch)
	python3 test/compat_test.py --candidate "$(IMAGE)"

rescan: ## Step 6: scan the patched image, compare with the baseline, apply vex/*.json
	IMAGE="$(IMAGE)" ./scripts/rescan-compare.sh
