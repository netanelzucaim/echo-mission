.PHONY: scan-baseline triage rescan

scan-baseline: ## Step 1: scan the original image with Trivy and Grype
	./scripts/scan-baseline.sh

triage: ## Step 2: merge the Trivy and Grype reports and rank by urgency
	python3 scripts/compare-scans.py scans/baseline/reports/trivy.json scans/baseline/reports/grype.json --out-dir scans/baseline

rescan: ## Step 6: scan the patched image, compare with the baseline, apply vex/*.json: make rescan IMAGE=<image>
	@test -n "$(IMAGE)" || { echo 'usage: make rescan IMAGE=<patched image>'; exit 2; }
	IMAGE="$(IMAGE)" ./scripts/rescan-compare.sh
