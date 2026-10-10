# ClusterFuzzLite builder for the atheris targets in fuzz/.
#
# The base image ships Python, atheris, and PyInstaller (compile_python_fuzzer).
# It and uv are pinned by digest; Dependabot's docker ecosystem can bump them.
# The build_fuzzers action replaces $SRC/grc-lake with the commit under test
# before build.sh runs, so the source copied here only serves local builds.
FROM ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 AS uv

FROM gcr.io/oss-fuzz-base/base-builder-python:v1@sha256:88bcf57cb6507ccc95cb5fcc3afeece6278b24880ec483a17f044a154277f9d0
COPY --from=uv /uv /usr/local/bin/uv
# Third-party imports (the Stripe webhook target needs SQLAlchemy) come from
# uv.lock with sha256 hashes; nothing unpinned is resolved.
COPY pyproject.toml uv.lock /tmp/grc-lake-lock/
RUN uv export --frozen --no-dev --no-emit-project --extra server \
      --project /tmp/grc-lake-lock --output-file /tmp/grc-lake-requirements.txt \
  && pip3 install --no-cache-dir --require-hashes --no-deps -r /tmp/grc-lake-requirements.txt \
  && rm -rf /tmp/grc-lake-lock /tmp/grc-lake-requirements.txt
COPY . $SRC/grc-lake
WORKDIR $SRC/grc-lake
COPY .clusterfuzzlite/build.sh $SRC/
