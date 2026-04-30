#!/bin/sh
# guard installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/brueshi/guard/main/install.sh | sh
#
# Environment overrides:
#   GUARD_INSTALL_DIR  - install destination (default $HOME/.local/bin)
#   GUARD_VERSION      - release tag to install (default latest)

set -eu

REPO="brueshi/guard"
INSTALL_DIR="${GUARD_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${GUARD_VERSION:-latest}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
    darwin) os=macos ;;
    linux)  os=linux ;;
    *) echo "guard: unsupported OS: $os" >&2; exit 1 ;;
esac

arch="$(uname -m)"
case "$arch" in
    x86_64|amd64)   arch=x86_64 ;;
    arm64|aarch64)  arch=aarch64 ;;
    *) echo "guard: unsupported architecture: $arch" >&2; exit 1 ;;
esac

archive="guard-$arch-$os.tar.gz"
if [ "$VERSION" = "latest" ]; then
    url="https://github.com/$REPO/releases/latest/download/$archive"
else
    url="https://github.com/$REPO/releases/download/$VERSION/$archive"
fi

echo "guard: installing $arch-$os from $url"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if ! curl -fsSL "$url" -o "$tmp/$archive"; then
    echo "guard: download failed" >&2
    exit 1
fi

tar -xzf "$tmp/$archive" -C "$tmp"
mkdir -p "$INSTALL_DIR"
mv "$tmp/guard" "$INSTALL_DIR/guard"
chmod +x "$INSTALL_DIR/guard"

echo "guard: installed to $INSTALL_DIR/guard"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo
        echo "guard: $INSTALL_DIR is not on your PATH"
        echo "       add this to your shell profile (~/.zshrc, ~/.bashrc, etc.):"
        echo
        echo "         export PATH=\"$INSTALL_DIR:\$PATH\""
        ;;
esac
