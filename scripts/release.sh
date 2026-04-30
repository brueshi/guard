#!/bin/sh
# Build release tarballs for all supported targets into ./dist/
# Run this from the repo root before creating a GitHub Release.

set -eu

TARGETS="
aarch64-macos
x86_64-macos
x86_64-linux
aarch64-linux
"

DIST="$(pwd)/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

for target in $TARGETS; do
    [ -z "$target" ] && continue
    echo "==> building $target"
    rm -rf zig-out
    zig build -Doptimize=ReleaseFast -Dtarget="$target"

    archive="guard-$target.tar.gz"
    tar -C zig-out/bin -czf "$DIST/$archive" guard
    (cd "$DIST" && shasum -a 256 "$archive" >> "checksums.txt")
    echo "    $DIST/$archive"
done

echo
echo "==> dist contents"
ls -la "$DIST"
echo
echo "==> checksums"
cat "$DIST/checksums.txt"
