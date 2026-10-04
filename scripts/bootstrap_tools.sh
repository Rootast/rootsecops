#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
YARA_RULES_DIR="${YARA_RULES_DIR:-$PROJECT_ROOT/backend/var/yara_rules}"
YARA_RULE_REPOS="${YARA_RULE_REPOS:-https://github.com/Yara-Rules/rules,https://github.com/Neo23x0/signature-base}"
BOOTSTRAP_UPDATE_CLAMAV="${BOOTSTRAP_UPDATE_CLAMAV:-true}"
BOOTSTRAP_YARA_RULES="${BOOTSTRAP_YARA_RULES:-true}"
BOOTSTRAP_INSTALL_OPTIONAL="${BOOTSTRAP_INSTALL_OPTIONAL:-true}"
BOOTSTRAP_BIN_DIR="${BOOTSTRAP_BIN_DIR:-/usr/local/bin}"

log() { printf '[bootstrap] %s\n' "$*"; }
warn() { printf '[bootstrap][WARN] %s\n' "$*" >&2; }
fail() { printf '[bootstrap][ERROR] %s\n' "$*" >&2; exit 1; }

need_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
  elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    fail "This installer needs root privileges or sudo."
  fi
}

detect_os() {
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) ARCH="amd64"; HADOLINT_ARCH="x86_64"; GITLEAKS_ARCH="x64" ;;
    arm64|aarch64) ARCH="arm64"; HADOLINT_ARCH="arm64"; GITLEAKS_ARCH="arm64" ;;
    *) fail "Unsupported CPU architecture: $ARCH" ;;
  esac
  if [ "$OS" = "linux" ] && [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-linux}"
    DISTRO_LIKE="${ID_LIKE:-}"
  else
    DISTRO_ID="$OS"
    DISTRO_LIKE=""
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

apt_install() {
  need_sudo
  export DEBIAN_FRONTEND=noninteractive
  $SUDO apt-get update
  $SUDO apt-get install -y --no-install-recommends "$@"
}

brew_install() {
  have brew || fail "Homebrew is required on macOS. Install it from https://brew.sh/"
  brew update
  for package in "$@"; do
    if brew list --formula "$package" >/dev/null 2>&1; then
      log "$package already installed"
    else
      brew install "$package"
    fi
  done
}

install_base_packages() {
  if [ "$OS" = "darwin" ]; then
    brew_install git curl jq clamav yara exiftool poppler gitleaks trufflehog trivy grype syft hadolint checkov osv-scanner kics
    if ! have grant; then
      brew install anchore/grant/grant || warn "Could not install grant with brew; install it manually from https://github.com/anchore/grant"
    fi
    return
  fi

  case "$DISTRO_ID $DISTRO_LIKE" in
    *debian*|*ubuntu*)
      apt_install \
        ca-certificates curl git jq tar unzip xz-utils gnupg lsb-release \
        clamav clamav-freshclam yara libimage-exiftool-perl poppler-utils \
        python3 python3-pip pipx docker.io
      ;;
    *)
      fail "Unsupported Linux distribution: $DISTRO_ID. Install tools manually or extend this script."
      ;;
  esac
}

github_latest_tag() {
  local repo="$1"
  curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | jq -er '.tag_name'
}

install_from_tarball() {
  local name="$1" repo="$2" url="$3" member="$4"
  if have "$name"; then
    log "$name already installed: $($name --version 2>&1 | head -1 || true)"
    return
  fi
  need_sudo
  local tmp
  tmp="$(mktemp -d)"
  log "Installing $name from $repo"
  curl -fsSL "$url" -o "$tmp/$name.tar.gz" || { rm -rf "$tmp"; return 1; }
  tar -xzf "$tmp/$name.tar.gz" -C "$tmp" || { rm -rf "$tmp"; return 1; }
  $SUDO install -m 0755 "$tmp/$member" "$BOOTSTRAP_BIN_DIR/$name" || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
}

install_single_binary() {
  local name="$1" url="$2"
  if have "$name"; then
    log "$name already installed"
    return
  fi
  need_sudo
  local tmp
  tmp="$(mktemp)"
  log "Installing $name"
  curl -fsSL "$url" -o "$tmp" || { rm -f "$tmp"; return 1; }
  $SUDO install -m 0755 "$tmp" "$BOOTSTRAP_BIN_DIR/$name" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
}

install_linux_optional_tools() {
  [ "$BOOTSTRAP_INSTALL_OPTIONAL" = "true" ] || return 0

  local tag version url

  tag="$(github_latest_tag gitleaks/gitleaks || true)"
  if [ -n "$tag" ]; then
    version="${tag#v}"
    install_from_tarball "gitleaks" "gitleaks/gitleaks" \
      "https://github.com/gitleaks/gitleaks/releases/download/$tag/gitleaks_${version}_linux_${GITLEAKS_ARCH}.tar.gz" \
      "gitleaks" || warn "Gitleaks automatic install failed."
  fi

  tag="$(github_latest_tag trufflesecurity/trufflehog || true)"
  if [ -n "$tag" ]; then
    version="${tag#v}"
    install_from_tarball "trufflehog" "trufflesecurity/trufflehog" \
      "https://github.com/trufflesecurity/trufflehog/releases/download/$tag/trufflehog_${version}_linux_${ARCH}.tar.gz" \
      "trufflehog" || warn "TruffleHog automatic install failed."
  fi

  tag="$(github_latest_tag hadolint/hadolint || true)"
  if [ -n "$tag" ]; then
    install_single_binary "hadolint" \
      "https://github.com/hadolint/hadolint/releases/download/$tag/hadolint-Linux-$HADOLINT_ARCH" \
      || warn "Hadolint automatic install failed."
  fi

  if ! have checkov; then
    log "Installing checkov with pipx"
    python3 -m pipx ensurepath >/dev/null 2>&1 || true
    python3 -m pipx install checkov --include-deps || warn "Checkov automatic install failed."
    if [ -x "$HOME/.local/bin/checkov" ]; then
      need_sudo
      $SUDO ln -sf "$HOME/.local/bin/checkov" "$BOOTSTRAP_BIN_DIR/checkov"
    fi
  fi

  if ! have trivy; then
    log "Installing Trivy from Aqua Security apt repository"
    need_sudo
    curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
      | $SUDO gpg --dearmor -o /usr/share/keyrings/trivy.gpg
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
      | $SUDO tee /etc/apt/sources.list.d/trivy.list >/dev/null
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends trivy || warn "Trivy automatic install failed."
  fi

  if ! have syft; then
    curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b "$BOOTSTRAP_BIN_DIR" || warn "Syft automatic install failed."
  fi
  if ! have grype; then
    curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sh -s -- -b "$BOOTSTRAP_BIN_DIR" || warn "Grype automatic install failed."
  fi
  if ! have grant; then
    curl -fsSL https://raw.githubusercontent.com/anchore/grant/main/install.sh \
      | sh -s -- -b "$BOOTSTRAP_BIN_DIR" || warn "Grant automatic install failed."
  fi

  tag="$(github_latest_tag google/osv-scanner || true)"
  if [ -n "$tag" ]; then
    version="${tag#v}"
    url="https://github.com/google/osv-scanner/releases/download/$tag/osv-scanner_linux_${ARCH}"
    install_single_binary "osv-scanner" "$url" || warn "OSV-Scanner automatic install failed."
  fi

  tag="$(github_latest_tag Checkmarx/kics || true)"
  if [ -n "$tag" ]; then
    version="${tag#v}"
    install_from_tarball "kics" "Checkmarx/kics" \
      "https://github.com/Checkmarx/kics/releases/download/$tag/kics_${version}_linux_${ARCH}.tar.gz" \
      "kics" || warn "KICS automatic install failed."
  fi
}

update_clamav() {
  if [ "$BOOTSTRAP_UPDATE_CLAMAV" != "true" ]; then
    log "Skipping ClamAV database update"
    return
  fi
  if have freshclam; then
    log "Updating ClamAV signatures with freshclam"
    freshclam || warn "freshclam failed. On macOS you may need to initialize freshclam.conf or run with sudo."
  else
    warn "freshclam not found; ClamAV signatures were not updated."
  fi
}

update_yara_rules() {
  if [ "$BOOTSTRAP_YARA_RULES" != "true" ]; then
    log "Skipping YARA rule download"
    return
  fi
  mkdir -p "$YARA_RULES_DIR"
  IFS=',' read -r -a repos <<< "$YARA_RULE_REPOS"
  for repo in "${repos[@]}"; do
    repo="$(printf '%s' "$repo" | xargs)"
    [ -n "$repo" ] || continue
    local name dest
    name="$(basename "$repo" .git)"
    dest="$YARA_RULES_DIR/$name"
    if [ -d "$dest/.git" ]; then
      log "Updating YARA rules: $repo"
      git -C "$dest" pull --ff-only || warn "Could not update $repo"
    else
      log "Cloning YARA rules: $repo"
      git clone --depth 1 "$repo" "$dest" || warn "Could not clone $repo"
    fi
  done
}

print_summary() {
  log "Tool summary"
  for tool in git clamscan freshclam yara exiftool pdfinfo gitleaks trufflehog trivy grype syft grant osv-scanner checkov kics hadolint docker; do
    if have "$tool"; then
      printf '  %-14s %s\n' "$tool" "$(command -v "$tool")"
    else
      printf '  %-14s %s\n' "$tool" "missing"
    fi
  done
  log "YARA rules directory: $YARA_RULES_DIR"
}

main() {
  detect_os
  log "Detected OS=$OS distro=$DISTRO_ID arch=$ARCH"
  install_base_packages
  if [ "$OS" = "linux" ]; then
    install_linux_optional_tools
  fi
  update_clamav
  update_yara_rules
  print_summary
}

main "$@"
