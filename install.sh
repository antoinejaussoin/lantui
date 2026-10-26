#!/bin/sh
# Install lantui for the current Mac or Linux host.
#
#   curl -fsSL https://raw.githubusercontent.com/antoinejaussoin/lantui/main/install.sh | sh
#
# Optional environment:
#   LANTUI_REPO     GitHub repo (default: antoinejaussoin/lantui)
#   LANTUI_VERSION  Release tag, or "latest" / "nightly" (default: latest)
#   LANTUI_BINDIR   Install directory (default: ~/.local/bin)

set -eu

REPO="${LANTUI_REPO:-antoinejaussoin/lantui}"
VERSION="${LANTUI_VERSION:-latest}"
BINDIR="${LANTUI_BINDIR:-${HOME}/.local/bin}"
NAME="lantui"

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "need '$1' on PATH"
}

asset_name() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Darwin)
            case "$arch" in
                arm64 | aarch64) printf '%s-macos-arm64' "$NAME" ;;
                *) die "macOS $arch is not supported (need Apple Silicon)" ;;
            esac
            ;;
        Linux)
            case "$arch" in
                x86_64 | amd64) printf '%s-linux-x64' "$NAME" ;;
                aarch64 | arm64) printf '%s-linux-arm64' "$NAME" ;;
                *) die "Linux $arch is not supported" ;;
            esac
            ;;
        *)
            die "unsupported OS '$os' (need macOS or Linux)"
            ;;
    esac
}

download() {
    dest="$1"
    shift
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 1 -o "$dest" "$@"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$@"
    else
        die "need curl or wget"
    fi
}

release_url() {
    asset="$1"
    case "$VERSION" in
        latest)
            printf 'https://github.com/%s/releases/latest/download/%s' "$REPO" "$asset"
            ;;
        nightly)
            printf 'https://github.com/%s/releases/download/nightly/%s' "$REPO" "$asset"
            ;;
        v*)
            printf 'https://github.com/%s/releases/download/%s/%s' "$REPO" "$VERSION" "$asset"
            ;;
        *)
            printf 'https://github.com/%s/releases/download/v%s/%s' "$REPO" "$VERSION" "$asset"
            ;;
    esac
}

ASSET=$(asset_name)
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

if [ "$VERSION" = latest ]; then
    if ! download "$TMP" "$(release_url "$ASSET")"; then
        printf 'install.sh: no stable release, trying nightly\n' >&2
        VERSION=nightly
        download "$TMP" "$(release_url "$ASSET")" || die "could not download $ASSET"
    fi
else
    download "$TMP" "$(release_url "$ASSET")" || die "could not download $ASSET from $VERSION"
fi

# A failed GitHub HTML page would still be a small text file.
if grep -q '<html' "$TMP" 2>/dev/null; then
    die "download did not look like a binary (check that a GitHub release exists)"
fi

mkdir -p "$BINDIR"
install -m 755 "$TMP" "$BINDIR/$NAME"

printf 'installed %s to %s/%s\n' "$ASSET" "$BINDIR" "$NAME"

case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *)
        printf 'add this to your shell profile:\n  export PATH="%s:\$PATH"\n' "$BINDIR" >&2
        ;;
esac
