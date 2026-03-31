#!/usr/bin/env bash
set -euo pipefail

REPO="ShadowPower/sshc-rs"
BINARY="sshc"
PROXY="https://gh-proxy.org/"
MARKER="# sshc-installer"
INSTALL_DIR="${HOME}/.sshc"

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[0;33m' BLUE='\033[0;34m' NC='\033[0m'
info()    { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
error()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
success() { printf "${GREEN}[OK]${NC} %s\n" "$*"; }

# ── Platform ──────────────────────────────────────────────────────

detect_asset() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        linux)  os="linux" ;;
        darwin) os="macos" ;;
        *)      error "Unsupported OS: $os"; exit 1 ;;
    esac

    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64)  arch="arm64" ;;
        *)              error "Unsupported architecture: $arch"; exit 1 ;;
    esac

    [ "$os" = "macos" ] && arch="universal"
    echo "sshc-${os}-${arch}.tar.gz"
}

# ── Network ───────────────────────────────────────────────────────

http_get() {
    local url="$1" out="$2"
    if command -v curl &>/dev/null; then
        curl -fSL --connect-timeout 10 -o "$out" "$url" 2>/dev/null
    elif command -v wget &>/dev/null; then
        wget -q --timeout=10 -O "$out" "$url"
    else
        error "curl or wget required"; exit 1
    fi
}

http_get_body() {
    local url="$1"
    if command -v curl &>/dev/null; then curl -fSL --connect-timeout 10 "$url" 2>/dev/null
    elif command -v wget &>/dev/null; then wget -q --timeout=10 -O- "$url" 2>/dev/null; fi
}

# ── PATH ──────────────────────────────────────────────────────────

get_rc_file() {
    case "$(basename "${SHELL:-bash}")" in
        zsh)  echo "${HOME}/.zshrc" ;;
        bash) echo "${HOME}/.bashrc" ;;
        fish) echo "${HOME}/.config/fish/config.fish" ;;
        *)    echo "${HOME}/.profile" ;;
    esac
}

add_to_path() {
    case ":${PATH}:" in *":${INSTALL_DIR}:"*) return ;; esac

    local rc_file line
    rc_file="$(get_rc_file)"
    [ -f "$rc_file" ] && grep -qF "$INSTALL_DIR" "$rc_file" 2>/dev/null && return

    case "$(basename "${SHELL:-bash}")" in
        fish) line="set -gx PATH ${INSTALL_DIR} \$PATH  ${MARKER}" ;;
        *)    line="export PATH=\"${INSTALL_DIR}:\$PATH\"  ${MARKER}" ;;
    esac

    mkdir -p "$(dirname "$rc_file")"
    info "Adding ${INSTALL_DIR} to PATH (in ${rc_file})"
    # Ensure file ends with newline so we don't merge with the last line
    if [ -f "$rc_file" ] && [ -s "$rc_file" ] && [ "$(tail -c 1 "$rc_file" 2>/dev/null)" != "" ]; then
        printf '\n' >> "$rc_file"
    fi
    printf '%s\n' "$line" >> "$rc_file"
    export PATH="${INSTALL_DIR}:${PATH}"
}

remove_from_path() {
    for f in "${HOME}/.zshrc" "${HOME}/.bashrc" "${HOME}/.profile" "${HOME}/.config/fish/config.fish"; do
        if [ -f "$f" ] && grep -qF "$MARKER" "$f" 2>/dev/null; then
            info "Cleaning PATH in ${f}"
            grep -vF "$MARKER" "$f" > "${f}.tmp.$$" && mv "${f}.tmp.$$" "$f"
        fi
    done
}

# ── Install ───────────────────────────────────────────────────────

do_install() {
    local asset
    asset="$(detect_asset)"

    info "Fetching latest release..."
    local body
    body="$(http_get_body "https://api.github.com/repos/${REPO}/releases/latest")" || true
    [ -z "$body" ] && { error "Failed to reach GitHub API"; exit 1; }

    local version url
    # tr removes whitespace so grep patterns work on pretty-printed JSON
    local compact
    compact="$(echo "$body" | tr -d ' \t')"
    version="$(echo "$compact" | grep -o '"tag_name":"[^"]*"' | head -1 | cut -d'"' -f4)"
    url="$(echo "$compact" | grep -o "\"browser_download_url\":\"[^\"]*${asset}\"" | head -1 | cut -d'"' -f4)"
    [ -z "$version" ] && { error "Failed to parse version"; exit 1; }
    [ -z "$url" ]    && { error "Asset ${asset} not found"; exit 1; }

    info "Latest version: ${version}"

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    local archive="${tmp}/${asset}"
    info "Downloading ${asset}..."
    if ! http_get "$url" "$archive"; then
        warn "Retrying via proxy..."
        http_get "${PROXY}${url}" "$archive" || { error "Download failed"; exit 1; }
    fi

    tar xzf "$archive" -C "$tmp"
    chmod +x "${tmp}/${BINARY}"

    mkdir -p "$INSTALL_DIR"
    cp "${tmp}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    add_to_path

    if command -v "$BINARY" &>/dev/null; then
        success "$("$BINARY" --version 2>&1)"
    else
        success "Installed to ${INSTALL_DIR}/${BINARY}"
        warn "Restart your terminal or run: source $(get_rc_file)"
    fi
}

# ── Uninstall ─────────────────────────────────────────────────────

do_uninstall() {
    if [ -f "${INSTALL_DIR}/${BINARY}" ]; then
        rm -f "${INSTALL_DIR}/${BINARY}"
        # remove dir if empty
        rmdir "$INSTALL_DIR" 2>/dev/null || true
        success "Removed ${INSTALL_DIR}/${BINARY}"
    else
        warn "sshc is not installed."
    fi
    remove_from_path
}

# ── Main ──────────────────────────────────────────────────────────

case "${1:-}" in
    uninstall|remove) do_uninstall ;;
    "")               do_install ;;
    *)                echo "Usage: $(basename "$0") [uninstall]"; exit 1 ;;
esac
