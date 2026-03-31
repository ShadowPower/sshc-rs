#!/usr/bin/env bash
set -euo pipefail

REPO="ShadowPower/sshc-rs"
BINARY="sshc"
PROXY="https://gh-proxy.org/"
PROXY_FIRST=false
MARKER="# sshc-installer"
INSTALL_DIR="${HOME}/.sshc"

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[0;33m' BLUE='\033[0;34m' NC='\033[0m'
info()    { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
error()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
success() { printf "${GREEN}[OK]${NC} %s\n" "$*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [install|uninstall] [-p|--proxy]

  -p, --proxy    Prefer proxy for GitHub API and downloads
EOF
}

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

prefixed_proxy_url() {
    local url="$1"
    printf '%s%s' "$PROXY" "$url"
}

iter_candidate_urls() {
    local url="$1"
    if [ "${PROXY_FIRST}" = true ]; then
        printf '%s\n%s\n' "$(prefixed_proxy_url "$url")" "$url"
    else
        printf '%s\n%s\n' "$url" "$(prefixed_proxy_url "$url")"
    fi
}

http_get_any() {
    local url="$1" out="$2" candidate
    while IFS= read -r candidate; do
        if http_get "$candidate" "$out"; then
            return 0
        fi
    done < <(iter_candidate_urls "$url")
    return 1
}

http_get_body_any() {
    local url="$1" candidate body
    while IFS= read -r candidate; do
        body="$(http_get_body "$candidate" || true)"
        if [ -n "$body" ]; then
            printf '%s' "$body"
            return 0
        fi
    done < <(iter_candidate_urls "$url")
    return 1
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
            local tmp_file
            tmp_file="${f}.tmp.$$"
            grep -vF "$MARKER" "$f" > "$tmp_file" || true
            mv "$tmp_file" "$f"
        fi
    done
}

# ── Install ───────────────────────────────────────────────────────

do_install() {
    local asset
    asset="$(detect_asset)"

    info "Fetching latest release..."
    local body
    body="$(http_get_body_any "https://api.github.com/repos/${REPO}/releases/latest")" || true
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

    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "${tmp:-}"' EXIT

    local archive="${tmp}/${asset}"
    info "Downloading ${asset}..."
    if ! http_get_any "$url" "$archive"; then
        error "Download failed"
        exit 1
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

ACTION="install"
while [ $# -gt 0 ]; do
    case "$1" in
        install)          ACTION="install" ;;
        uninstall|remove) ACTION="uninstall" ;;
        -p|--proxy)       PROXY_FIRST=true ;;
        -h|--help)        usage; exit 0 ;;
        *)                usage; exit 1 ;;
    esac
    shift
done

case "$ACTION" in
    uninstall) do_uninstall ;;
    install)   do_install ;;
    *)         usage; exit 1 ;;
esac
