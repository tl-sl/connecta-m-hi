#!/bin/bash
# Builds dom.oti.cat_<version>_all.ipk from control/ and data/ directories.
# Run from the repo root or any working directory.
# Override version: VERSION=1.8.0 bash build.sh
set -e

PKGNAME=dom.oti.cat
RELEASE=1
ARCH=all

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Version is read from control/control (single source of truth).
# Override only if VERSION is explicitly set in the environment.
if [ -z "$VERSION" ]; then
  VERSION=$(grep '^Version:' "$SCRIPT_DIR/control/control" | sed 's/^Version: //;s/-.*//')
fi

OUTDIR="$SCRIPT_DIR/out"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$OUTDIR"

# Ensure scripts are executable before packaging
chmod +x "$SCRIPT_DIR/control/postinst"
chmod +x "$SCRIPT_DIR/control/prerm"
chmod +x "$SCRIPT_DIR/control/postrm"
chmod +x "$SCRIPT_DIR/data/etc/init.d/dom.oti.cat"

echo "[build] control.tar.gz"
COPYFILE_DISABLE=1 tar -czf "$TMPDIR/control.tar.gz" -C "$SCRIPT_DIR/control" \
    --exclude='._*' --exclude='.DS_Store' .

echo "[build] data.tar.gz"
COPYFILE_DISABLE=1 tar -czf "$TMPDIR/data.tar.gz" -C "$SCRIPT_DIR/data" \
    --exclude='._*' --exclude='.DS_Store' .

echo "[build] debian-binary"
printf '2.0\n' > "$TMPDIR/debian-binary"

echo "[build] assembling IPK"
IPK="$OUTDIR/${PKGNAME}_${VERSION}-${RELEASE}_${ARCH}.ipk"
( cd "$TMPDIR" && ar rc "$IPK" debian-binary control.tar.gz data.tar.gz )

echo "[build] done: $IPK"
ls -lh "$IPK"
