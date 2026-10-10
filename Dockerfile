# Multi-stage Dockerfile: builds the Next.js workbench, installs the Python
# package with the workbench bundled in, ships a slim runtime image.
#
# Three stages:
#   1. web-build  — Node 22 builds the static React export into
#                   src/security_lakehouse/web/dist/
#   2. py-build   — Python 3.12 installs the package + analytics extras into a
#                   virtualenv that runtime mounts read-only (matches CI)
#   3. runtime    — Python 3.12 slim, copies the venv + lake mount points,
#                   runs `grc-lake serve` as a non-root user
#
# Build:  docker build -t grc-lake:dev .
# Run: see deploy/README.md for authenticated Compose and Kubernetes profiles.

# Base images are pinned by multi-arch index digest so a rebuild of the same
# commit gets the same bytes; Dependabot's docker ecosystem bumps tag + digest
# together. uv is copied from its official image, pinned the same way.
FROM ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 AS uv

# --- 1. React workbench ----------------------------------------------------
# The static export is the same on every architecture, so it builds on the
# build host's platform instead of under emulation.
FROM --platform=$BUILDPLATFORM node:25-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS web-build
WORKDIR /workbench
COPY app/web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY app/web/ ./
RUN npm run build

# --- 2. Python package + analytics venv -----------------------------------
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS py-build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
COPY connectors/ ./connectors/
COPY controls/ ./controls/
COPY frameworks/ ./frameworks/
COPY mappings/ ./mappings/
COPY programs/ ./programs/
COPY mockup_companies/ ./mockup_companies/
COPY policy_templates/ ./policy_templates/
COPY agent-skills/ ./agent-skills/
# Bring the static export into the package tree before install so wheel
# package-data picks it up.
COPY --from=web-build /src/security_lakehouse/web/dist/ ./src/security_lakehouse/web/dist/
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
# Dependencies come from uv.lock with their sha256 hashes, and the install
# refuses any distribution whose hash does not match. The project itself is
# then built from this source tree with --no-deps, so nothing unpinned is
# resolved at build time.
# The image binds 0.0.0.0, so it must be able to run the authenticated
# server. Without the `server` extra the CMD below silently falls back to
# local mode, which has no authentication at all.
RUN python -m venv /opt/grc-lake-venv \
  && uv export --frozen --no-dev --no-emit-project \
       --extra server --extra analytics --extra cloud --extra mcp --extra iceberg \
       --output-file /tmp/grc-lake-requirements.txt \
  && uv pip install --python /opt/grc-lake-venv/bin/python \
       --require-hashes --requirement /tmp/grc-lake-requirements.txt \
  && uv pip install --python /opt/grc-lake-venv/bin/python --no-deps \
       ".[server,analytics,cloud,mcp,iceberg]"

# --- 3. Slim runtime ------------------------------------------------------
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS runtime
LABEL org.opencontainers.image.title="GRC Lake"
LABEL org.opencontainers.image.source="https://github.com/msaad00/grc-lake"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PATH="/opt/grc-lake-venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GRC_LAKE_LAKE=/lake \
    GRC_LAKE_DATA_DIR=/opt/grc-lake-data

# Refresh PCRE2 from Debian security until the pinned base includes DSA-6530-1.
RUN apt-get update \
  && apt-get install --no-install-recommends -y tini libpcre2-8-0 \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 1100 grc-lake \
  && useradd --uid 1100 --gid 1100 --home /home/grc-lake --create-home --shell /bin/bash grc-lake \
  && mkdir -p /lake \
  && chown -R grc-lake:grc-lake /lake

COPY --from=py-build /opt/grc-lake-venv /opt/grc-lake-venv
# Ship the framework / control / connector / mapping catalogs inside the
# image so the wheel-installed Python package can find them. The env var
# GRC_LAKE_DATA_DIR (set above) tells security_lakehouse where to look.
COPY frameworks/ /opt/grc-lake-data/frameworks/
COPY controls/ /opt/grc-lake-data/controls/
COPY connectors/ /opt/grc-lake-data/connectors/
COPY mappings/ /opt/grc-lake-data/mappings/
COPY programs/ /opt/grc-lake-data/programs/
COPY mockup_companies/ /opt/grc-lake-data/mockup_companies/
COPY policy_templates/ /opt/grc-lake-data/policy_templates/
COPY agent-skills/ /opt/grc-lake-data/agent-skills/

USER grc-lake
WORKDIR /home/grc-lake
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/healthz', timeout=2)"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["grc-lake", "serve", "--server", "--lake", "/lake", "--host", "0.0.0.0", "--port", "8787"]
