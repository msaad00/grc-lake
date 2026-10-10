#!/bin/bash -eu
# Package every fuzz/fuzz_*.py target with its seed corpus.
#
# PyInstaller bundles project source directly from src/ (--paths). Runtime
# dependencies are already installed from uv.lock by the Dockerfile, avoiding
# an additional build-backend download at fuzz time.
for fuzzer in "$SRC"/grc-lake/fuzz/fuzz_*.py; do
  name=$(basename -s .py "$fuzzer")
  compile_python_fuzzer "$fuzzer" --paths "$SRC/grc-lake/src" --paths "$SRC/grc-lake/fuzz"
  corpus="$SRC/grc-lake/fuzz/corpus/$name"
  if [ -d "$corpus" ]; then
    (cd "$corpus" && zip -q -r "$OUT/${name}_seed_corpus.zip" .)
  fi
done
