#!/usr/bin/env bash
# Check the installed image, not the source lockfile. Optional Docker run flags
# follow the image reference (for example --platform linux/arm64).
set -euo pipefail
image="${1:?usage: check_image_dependencies.sh IMAGE [docker run options]}"
shift

docker run --rm "$@" --entrypoint /bin/sh "$image" -eu -c '
  for interpreter in /usr/local/bin/python /opt/grc-lake-venv/bin/python; do
    "$interpreter" -c "
import importlib.util
import lzma
import sqlite3
import ssl

assert importlib.util.find_spec(\"pip\") is None, \"pip must not ship in the runtime image\"
assert importlib.util.find_spec(\"ensurepip\") is None, \"ensurepip must not restore a bundled vulnerable pip\"
payload = b\"grc-lake compression smoke\" * 100
assert lzma.decompress(lzma.compress(payload)) == payload
assert sqlite3.connect(\":memory:\").execute(\"select 1\").fetchone() == (1,)
assert ssl.create_default_context().check_hostname
"
  done
  installed="$(dpkg-query -W -f="\${Version}" liblzma5)"
  dpkg --compare-versions "$installed" ge "5.8.1-1+deb13u2"
  test ! -e /usr/bin/infocmp
  elevated="$(find /usr -xdev -type f \( -perm -4000 -o -perm -2000 \) -print)"
  test -z "$elevated" || { echo "Unexpected setuid/setgid files: $elevated" >&2; exit 1; }
  echo "Runtime dependency checks passed (liblzma5 $installed)."
'
