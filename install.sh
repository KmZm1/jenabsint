#!/data/data/com.termux/files/usr/bin/bash
# JenabSint installer (Termux-first).
# Run with:  bash install.sh
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"

if [ -z "${PREFIX:-}" ]; then
  if [ -d /data/data/com.termux/files/usr ]; then
    PREFIX=/data/data/com.termux/files/usr
  else
    echo "error: PREFIX is not set and this is not Termux." >&2
    echo "set PREFIX to your install prefix, e.g. PREFIX=/usr/local bash install.sh" >&2
    exit 1
  fi
fi

BIN="$PREFIX/bin"
[ -d "$BIN" ] || { echo "error: $BIN does not exist" >&2; exit 1; }

python3 - <<'EOF'
import sys
if sys.version_info < (3, 11):
    sys.exit("error: Python 3.11+ required, found %s" % sys.version.split()[0])
print("python OK:", sys.version.split()[0])
EOF

chmod +x "$SRC/jenabsint.py"
ln -sf "$SRC/jenabsint.py" "$BIN/jenabsint"
echo "installed: $BIN/jenabsint -> $SRC/jenabsint.py"

cp "$SRC/osint.sh" "$BIN/osint"
chmod +x "$BIN/osint"
echo "installed: $BIN/osint"

echo
echo "done. start with:  jenabsint"
echo "toolchain check:   jenabsint  (menu 13 = Doctor)"
