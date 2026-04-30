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
    (
        cd "$DIST"
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$archive" >> "checksums.txt"
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 "$archive" >> "checksums.txt"
        else
            echo "release.sh: no sha256 tool found (need sha256sum or shasum)" >&2
            exit 1
        fi
    )
    echo "    $DIST/$archive"
done

echo
echo "==> dist contents"
ls -la "$DIST"
echo
echo "==> checksums"
cat "$DIST/checksums.txt"
