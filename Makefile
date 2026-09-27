.PHONY: release-build compile lint format-check diff-check test validate validate-json validate-generated validate-brand validate-doc-images pipeline dashboard api-smoke smoke ci web-install web-dev web-typecheck web-build web-clean web-ci docker-build helm-lint helm-template terraform-fmt terraform-validate deploy-check uv-sync uv-lock pre-commit-install pre-commit-run pip-audit npm-audit security openapi-export readme-header

test:
	PYTHONPATH=src python -m pytest -q

compile:
	PYTHONPATH=src python -m compileall -q src tests tools

lint:
	PYTHONPATH=src python -m ruff check src tests tools

format-check:
	PYTHONPATH=src python -m ruff format --check src tests tools

diff-check:
	git diff --check

validate:
	PYTHONPATH=src python -m security_lakehouse.cli validate --raw data/raw/security_events.jsonl
	PYTHONPATH=src python -m security_lakehouse.cli connectors validate
	PYTHONPATH=src python -c "from security_lakehouse.catalog import validate_catalog; from security_lakehouse.programs import validate_program_catalog; from security_lakehouse.policy_templates import validate_policy_template_catalog; errors = validate_catalog() + validate_program_catalog() + validate_policy_template_catalog(); assert not errors, errors"
	PYTHONPATH=src python -m security_lakehouse.cli catalog verify

validate-json:
	PYTHONPATH=src python tools/validate_ci_artifacts.py

validate-generated:
	PYTHONPATH=src python tools/validate_ci_artifacts.py --generated

validate-doc-images:
	PYTHONPATH=src python tools/validate_doc_images.py

validate-brand:
	PYTHONPATH=src python tools/check_brand_compliance.py

pipeline:
	PYTHONPATH=src python -m security_lakehouse.cli pipeline run --raw data/raw/security_events.jsonl --out build/lakehouse

dashboard:
	PYTHONPATH=src python -m security_lakehouse.cli dashboard --lake build/lakehouse --out build/dashboard/index.html

api-smoke:
	PYTHONPATH=src python tools/api_smoke.py

# Clean first: a stale wheel left in dist/ would otherwise be verified (and
# could be uploaded) alongside the fresh one.
release-build: web-install web-build
	rm -rf dist
	uv build --out-dir dist
	python tools/verify_wheel.py dist/*.whl

openapi-export:
	uv run security-lakehouse openapi --out docs/api/openapi.v1.json
	uv run python -c "import json; from security_lakehouse import api_v1; json.dump({'resources': api_v1.resource_catalog()}, open('docs/api/resource-catalog.v1.json','w'), indent=2, sort_keys=True); print('wrote docs/api/resource-catalog.v1.json')"

smoke: validate validate-json validate-doc-images validate-brand pipeline validate-generated dashboard api-smoke test

ci: diff-check compile lint format-check web-ci smoke

# --- React (Next.js) workbench targets -------------------------------------
# Lives in app/web/, builds to src/security_lakehouse/web/dist/ so the Python
# wheel ships the bundle. Dev mode proxies /api to a running `security-lakehouse serve`.

web-install:
	npm --prefix app/web ci

web-dev:
	npm --prefix app/web run dev

web-typecheck:
	npm --prefix app/web run typecheck

web-build:
	npm --prefix app/web run build

demo-screenshots:
	npm --prefix app/web run demo-screenshots

# Full pipeline: fixture + web build + ephemeral server + PNG capture (for CI/agents).
demo-screenshots-full:
	bash tools/capture_readme_screenshots.sh

# Local console with golden fixture (run on your machine — localhost is not remote-hosted).
demo-local: web-install web-build
	uv run security-lakehouse fixtures load --company golden --out build/lakehouse --rebase-times
	uv run security-lakehouse db upgrade --lake build/lakehouse
	@echo "Starting console at http://127.0.0.1:8787/console/dashboard/"
	uv run security-lakehouse serve --lake build/lakehouse --server --allow-insecure-no-auth --port 8787

web-ci: web-install web-typecheck web-build

web-clean:
	rm -rf src/security_lakehouse/web/dist/* src/security_lakehouse/web/dist/.* 2>/dev/null || true
	mkdir -p src/security_lakehouse/web/dist
	touch src/security_lakehouse/web/dist/.gitkeep

# --- Deploy targets -------------------------------------------------------
# Container image, Helm chart, EKS Terraform reference IaC.

docker-build:
	docker build -t trustops:dev .

helm-lint:
	helm lint deploy/helm/trustops

helm-template:
	helm template trustops deploy/helm/trustops > /tmp/trustops-helm-render.yaml
	@echo "wrote /tmp/trustops-helm-render.yaml ($$(wc -l < /tmp/trustops-helm-render.yaml) lines)"

terraform-fmt:
	terraform -chdir=deploy/eks-terraform fmt -check

terraform-validate:
	terraform -chdir=deploy/eks-terraform init -backend=false -input=false
	terraform -chdir=deploy/eks-terraform validate

deploy-check: helm-lint helm-template terraform-fmt terraform-validate

# --- Supply-chain + commit hooks -------------------------------------------
# uv is the recommended package manager (deterministic + locked install).
# pip still works as a fallback when uv isn't installed.

uv-sync:
	uv sync --frozen --all-extras

uv-lock:
	uv lock

framework-packs:
	PYTHONPATH=src python -m security_lakehouse.cli frameworks sync-packs

pre-commit-install:
	uv run pre-commit install
	uv run pre-commit install --hook-type commit-msg

pre-commit-run:
	uv run pre-commit run --all-files

pip-audit:
	uv export --no-emit-project --format requirements-txt --no-hashes > /tmp/trustops-reqs.txt
	uv run pip-audit --strict -r /tmp/trustops-reqs.txt

npm-audit:
	cd app/web && npm audit --omit=dev --audit-level=high

security: pip-audit npm-audit pre-commit-run

coverage-doc:
	uv run python -c "from security_lakehouse.framework_coverage import render_framework_coverage_doc; open('docs/FRAMEWORK_COVERAGE.md','w').write(render_framework_coverage_doc())"
	@echo wrote docs/FRAMEWORK_COVERAGE.md

readme-header:
	uv run python tools/render_readme_header.py
