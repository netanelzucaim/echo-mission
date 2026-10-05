.PHONY: scan-baseline triage probe

scan-baseline: ## Step 1: scan the original image with Trivy and Grype
	./scripts/scan-baseline.sh

triage: ## Step 2: merge the Trivy and Grype reports and rank by urgency
	python3 scripts/compare-scans.py scans/baseline/reports/trivy.json scans/baseline/reports/grype.json --out-dir scans/baseline

probe: ## Measure what removing packages would change: make probe REMOVE="nginx-module-image-filter"
	@test -n "$(REMOVE)" || { echo 'usage: make probe REMOVE="package [package...]"'; exit 2; }
	./scripts/probe-impact.sh $(REMOVE)
