# The patched image. Override on the command line: make test IMAGE=my-image:tag
IMAGE ?= echo-nginx:1.25-bookworm
BUILD_IMAGE ?= echo-nginx-build

.PHONY: scan-baseline triage fix-plan deb image test fsdiff rescan

scan-baseline: ## Step 1: scan the original image with Trivy and Grype
	./scripts/scan-baseline.sh

deb: ## Step 3: build the patched nginx + module .debs from source into out/
	docker build -f build/Dockerfile -t "$(BUILD_IMAGE)" build/
	rm -rf out && mkdir -p out
	cid=$$(docker create "$(BUILD_IMAGE)"); docker cp "$$cid":/out/. out/; docker rm "$$cid"
	ls -la out/

image: ## Step 4: build the final image from the .debs in out/
	docker build -f Containerfile -t "$(IMAGE)" .

triage: ## Step 2: merge the Trivy and Grype reports and rank by urgency
	python3 scripts/compare-scans.py scans/baseline/reports/trivy.json scans/baseline/reports/grype.json --out-dir scans/baseline

fix-plan: ## Step 2: propose a fix method per CVE (version bump, backport, remove) into scans/baseline/fix-plan.md
	python3 scripts/fix-method.py scans/baseline

test: ## Step 5: compare the patched image with the original (exit code 1 on any mismatch)
	python3 test/compat_test.py --candidate "$(IMAGE)"

fsdiff: ## After any build change: compare every file in the original and patched images (exit 1 on a real difference)
	IMAGE="$(IMAGE)" ./scripts/fs-diff.sh

rescan: ## Step 6: scan the patched image, compare with the baseline, apply vex/*.json
	IMAGE="$(IMAGE)" ./scripts/rescan-compare.sh
