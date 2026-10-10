.DEFAULT_GOAL := help

# Python tools run from the locked uv environment so local results match CI.
# Override with PYTHON=python to use the active interpreter instead.
PYTHON ?= uv run --frozen python

.PHONY: help demo-screenshots demo-screenshots-full demo-local framework-packs coverage-doc release-build compile lint format-check typecheck diff-check test validate validate-json validate-generated validate-brand validate-doc-images pipeline dashboard api-smoke smoke ci web-install web-dev web-typecheck web-build web-clean web-ci docker-build helm-lint helm-template terraform-fmt terraform-validate terraform-test deploy-check uv-sync uv-lock pre-commit-install pre-commit-run pip-audit npm-audit security openapi-export readme-header

help: ## List available commands without running builds or tests.
	@awk -F ':.*## ' 'BEGIN { printf "Usage: make <target>\n\n" } /^[a-zA-Z][a-zA-Z0-9_-]*:.*## / { printf "  %-24s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

test: ## Run the Python test suite.
	PYTHONPATH=src $(PYTHON) -m pytest -q

compile: ## Compile Python source, tests and tools to check syntax.
	PYTHONPATH=src $(PYTHON) -m compileall -q src tests tools

lint: ## Run Ruff checks on Python source, tests and tools.
	PYTHONPATH=src $(PYTHON) -m ruff check src tests tools

format-check: ## Check Python formatting without changing files.
	PYTHONPATH=src $(PYTHON) -m ruff format --check src tests tools

typecheck: ## Type-check the Python package with mypy.
	$(PYTHON) -m mypy

diff-check: ## Check the current diff for whitespace errors.
	git diff --check

validate: ## Validate sample evidence, connector contracts and catalogs.
	PYTHONPATH=src $(PYTHON) -m security_lakehouse.cli validate --raw data/raw/security_events.jsonl
	PYTHONPATH=src $(PYTHON) -m security_lakehouse.cli connectors validate
	PYTHONPATH=src $(PYTHON) -c "from security_lakehouse.catalog import validate_catalog; from security_lakehouse.programs import validate_program_catalog; from security_lakehouse.policy_templates import validate_policy_template_catalog; errors = validate_catalog() + validate_program_catalog() + validate_policy_template_catalog(); assert not errors, errors"
	PYTHONPATH=src $(PYTHON) -m security_lakehouse.cli catalog verify

validate-json: ## Validate checked-in schemas and JSON artifacts.
	PYTHONPATH=src $(PYTHON) tools/validate_ci_artifacts.py

validate-generated: ## Validate generated lake artifacts.
	PYTHONPATH=src $(PYTHON) tools/validate_ci_artifacts.py --generated

validate-doc-images: ## Check documentation image references and assets.
	PYTHONPATH=src $(PYTHON) tools/validate_doc_images.py

validate-brand: ## Check public documentation and images for brand consistency.
	PYTHONPATH=src $(PYTHON) tools/check_brand_compliance.py

pipeline: ## Evaluate sample evidence into build/lakehouse.
	PYTHONPATH=src $(PYTHON) -m security_lakehouse.cli pipeline run --raw data/raw/security_events.jsonl --out build/lakehouse

dashboard: ## Render the sample lake dashboard into build/dashboard.
	PYTHONPATH=src $(PYTHON) -m security_lakehouse.cli dashboard --lake build/lakehouse --out build/dashboard/index.html

api-smoke: ## Start a temporary API server and check sample lake responses.
	PYTHONPATH=src $(PYTHON) tools/api_smoke.py

# Clean first: a stale wheel left in dist/ would otherwise be verified (and
# could be uploaded) alongside the fresh one.
release-build: web-install web-build ## Build the console, wheel and source archive; verify wheel contents.
	rm -rf dist
	uv build --out-dir dist
	$(PYTHON) tools/verify_wheel.py dist/*.whl

openapi-export: ## Regenerate OpenAPI and API resource catalog documents.
	uv run grc-lake openapi --out docs/api/openapi.v1.json
	uv run python -c "import json; from security_lakehouse import api_v1; json.dump({'resources': api_v1.resource_catalog()}, open('docs/api/resource-catalog.v1.json','w'), indent=2, sort_keys=True); print('wrote docs/api/resource-catalog.v1.json')"

smoke: validate validate-json validate-doc-images validate-brand pipeline validate-generated dashboard api-smoke test ## Validate catalogs and artifacts, run the sample pipeline and test suite.

ci: diff-check compile lint format-check typecheck web-ci smoke ## Run local code, web and pipeline checks.

# --- React (Next.js) workbench targets -------------------------------------
# Lives in app/web/, builds to src/security_lakehouse/web/dist/ so the Python
# wheel ships the bundle. web-dev starts Next.js on :5173 with no API proxy;
# /api requests stay on that origin. Use demo-local for UI and API together.

web-install: ## Install locked console dependencies with npm ci.
	npm --prefix app/web ci

web-dev: ## Start Next.js UI development on port 5173; no API proxy.
	npm --prefix app/web run dev

web-typecheck: ## Type-check the console TypeScript.
	npm --prefix app/web run typecheck

web-build: ## Build the static console into the Python package.
	npm --prefix app/web run build

demo-screenshots: ## Capture demo screenshots from an already-running server.
	npm --prefix app/web run demo-screenshots

# Full pipeline: fixture + web build + ephemeral server + PNG capture (for CI/agents).
demo-screenshots-full: ## Build and serve the golden fixture, then capture demo screenshots.
	bash tools/capture_readme_screenshots.sh

# Local console with golden fixture (run on your machine — localhost is not remote-hosted).
demo-local: web-install web-build ## Build and serve the golden demo on loopback port 8787 with auth off.
	uv run grc-lake fixtures load --company golden --out build/lakehouse --rebase-times
	uv run grc-lake db upgrade --lake build/lakehouse
	@echo "Starting console at http://127.0.0.1:8787/console/dashboard/"
	uv run grc-lake serve --lake build/lakehouse --server --allow-insecure-no-auth --port 8787

web-ci: web-install web-typecheck web-build ## Install, type-check and build the console.

web-clean: ## Remove the generated console bundle and restore its placeholder.
	rm -rf src/security_lakehouse/web/dist/* src/security_lakehouse/web/dist/.* 2>/dev/null || true
	mkdir -p src/security_lakehouse/web/dist
	touch src/security_lakehouse/web/dist/.gitkeep

# --- Deploy targets -------------------------------------------------------
# Container image, Helm chart, EKS Terraform reference IaC.

docker-build: ## Build the local grc-lake:dev container image.
	docker build -t grc-lake:dev .

helm-lint: ## Lint the GRC Lake Helm chart.
	helm lint deploy/helm/grc-lake -f deploy/examples/self-hosted-values.yaml

helm-template: ## Render the Helm chart to /tmp/grc-lake-helm-render.yaml.
	helm template grc-lake deploy/helm/grc-lake -f deploy/examples/self-hosted-values.yaml > /tmp/grc-lake-helm-render.yaml
	@echo "wrote /tmp/grc-lake-helm-render.yaml ($$(wc -l < /tmp/grc-lake-helm-render.yaml) lines)"

terraform-fmt: ## Check formatting of the EKS Terraform reference.
	terraform -chdir=deploy/eks-terraform fmt -check -recursive

terraform-validate: ## Initialize without a backend and validate EKS Terraform.
	terraform -chdir=deploy/eks-terraform init -backend=false -input=false
	terraform -chdir=deploy/eks-terraform validate

terraform-test: terraform-validate ## Test deployment plans with mocked cloud providers.
	terraform -chdir=deploy/eks-terraform test

deploy-check: helm-lint helm-template terraform-fmt terraform-test ## Validate the Helm chart and EKS Terraform reference.

# --- Supply-chain + commit hooks -------------------------------------------
# uv is the recommended package manager (deterministic + locked install).
# pip still works as a fallback when uv isn't installed.

uv-sync: ## Install all Python extras from the frozen lockfile.
	uv sync --frozen --all-extras

uv-lock: ## Refresh the Python dependency lockfile.
	uv lock

framework-packs: ## Synchronize framework packs from their source manifests.
	PYTHONPATH=src $(PYTHON) -m security_lakehouse.cli frameworks sync-packs

pre-commit-install: ## Install pre-commit and commit-message hooks.
	uv run pre-commit install
	uv run pre-commit install --hook-type commit-msg

pre-commit-run: ## Run all pre-commit checks across tracked files.
	uv run pre-commit run --all-files

pip-audit: ## Audit locked Python runtime dependencies for known vulnerabilities.
	uv export --no-emit-project --format requirements-txt --no-hashes > /tmp/grc-lake-reqs.txt
	uv run pip-audit --strict -r /tmp/grc-lake-reqs.txt

npm-audit: ## Audit production npm dependencies at high severity or above.
	cd app/web && npm audit --omit=dev --audit-level=high

security: pip-audit npm-audit pre-commit-run ## Run dependency audits and pre-commit checks.

coverage-doc: ## Regenerate the framework coverage document.
	uv run python -c "from security_lakehouse.framework_coverage import render_framework_coverage_doc; open('docs/FRAMEWORK_COVERAGE.md','w').write(render_framework_coverage_doc())"
	@echo wrote docs/FRAMEWORK_COVERAGE.md

readme-header: ## Regenerate the README header graphic.
	uv run python tools/render_readme_header.py
