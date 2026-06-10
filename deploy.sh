#!/usr/bin/env bash
set -euo pipefail

# ── DockSec deploy script ─────────────────────────────────────────────────────
# Automated installation of the hermes-docksec tool on Linux x86_64.
#
# WARNING — this script will make the following changes:
#   • Download trivy v0.71.0 → ~/.local/bin/trivy   (SHA256-verified)
#   • Download hadolint v2.14.0 → ~/.local/bin/hadolint   (SHA256-verified)
#   • Create a Python 3.12 venv → ~/.hermes/docksec/venv
#     and install docksec + openai into it
#   • Copy docksec_worker.py → ~/.hermes/docksec/
#   • Copy docksec_tool.py → ~/.hermes/hermes-agent/tools/
#
# It does NOT touch config.yaml or .env (credentials stay yours — see the
# manual steps printed at the end).
#
# Requirements: curl, tar, sha256sum; python3.12 or uv; Linux x86_64.
# For manual installation or other platforms, see README.md.
# Run from the repo root.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
DOCKSEC_DIR="$HERMES_HOME/docksec"
LOCAL_BIN="$HOME/.local/bin"
TRIVY_VERSION=0.71.0
HADOLINT_VERSION=2.14.0

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}▸${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
die()  { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

# ── Platform check ─────────────────────────────────────────────────────────────
[[ "$(uname -s)" == "Linux" ]]  || die "This script targets Linux. For macOS use: brew install trivy hadolint"
[[ "$(uname -m)" == "x86_64" ]] || die "This script only provides x86_64 binaries. See README for other arches."

# ── Confirm ────────────────────────────────────────────────────────────────────
echo
echo "This script will install:"
echo "  hadolint v${HADOLINT_VERSION}      → ${LOCAL_BIN}/hadolint"
echo "  trivy v${TRIVY_VERSION}         → ${LOCAL_BIN}/trivy"
echo "  Python 3.12 venv           → ${DOCKSEC_DIR}/venv  (docksec + openai)"
echo "  docksec_worker.py          → ${DOCKSEC_DIR}/"
echo "  docksec_tool.py            → ${HERMES_HOME}/hermes-agent/tools/"
echo
printf "Continue? [y/N] "
read -r REPLY
[[ "${REPLY,,}" == "y" ]] || { echo "Aborted."; exit 0; }
echo

# ── 1. Locate Python 3.12 ──────────────────────────────────────────────────────
info "Checking for Python 3.12..."
if command -v python3.12 &>/dev/null; then
    PY312="$(command -v python3.12)"
    info "Found: $PY312"
elif command -v uv &>/dev/null; then
    info "python3.12 not found — installing a managed copy via uv..."
    uv python install 3.12
    PY312="$(uv python find 3.12)"
    info "Installed: $PY312"
else
    die "python3.12 not found and uv is not available.\n  Install one:\n    python: https://www.python.org/downloads/\n    uv:     https://docs.astral.sh/uv/"
fi

# ── 2. Create the docksec venv ─────────────────────────────────────────────────
info "Creating venv at ${DOCKSEC_DIR}/venv..."
mkdir -p "$DOCKSEC_DIR"
if command -v uv &>/dev/null; then
    uv venv --python "$PY312" "${DOCKSEC_DIR}/venv"
    VIRTUAL_ENV="${DOCKSEC_DIR}/venv" uv pip install --quiet docksec openai
else
    "$PY312" -m venv "${DOCKSEC_DIR}/venv"
    "${DOCKSEC_DIR}/venv/bin/pip" install --quiet docksec openai
fi
info "Venv ready."

# ── 3. Copy worker script ──────────────────────────────────────────────────────
info "Copying docksec_worker.py → ${DOCKSEC_DIR}/"
cp "$SCRIPT_DIR/docksec_worker.py" "$DOCKSEC_DIR/docksec_worker.py"

# ── 4. Install Hadolint ────────────────────────────────────────────────────────
mkdir -p "$LOCAL_BIN"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

if command -v hadolint &>/dev/null; then
    warn "hadolint already on PATH ($(command -v hadolint)) — skipping download."
else
    info "Downloading hadolint v${HADOLINT_VERSION}..."
    curl -fsSL -o hadolint \
        "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64"
    curl -fsSL -o hadolint.sha256 \
        "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64.sha256"
    echo "$(cut -d' ' -f1 hadolint.sha256)  hadolint" | sha256sum -c - \
        || die "hadolint checksum mismatch — aborting"
    install -m 0755 hadolint "$LOCAL_BIN/hadolint"
    info "hadolint installed → $LOCAL_BIN/hadolint"
fi

# ── 5. Install Trivy ───────────────────────────────────────────────────────────
if command -v trivy &>/dev/null; then
    warn "trivy already on PATH ($(command -v trivy)) — skipping download."
else
    info "Downloading trivy v${TRIVY_VERSION}..."
    TARBALL="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    CHECKSUMS="trivy_${TRIVY_VERSION}_checksums.txt"
    curl -fsSL -O "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TARBALL}"
    curl -fsSL -O "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${CHECKSUMS}"
    grep "$TARBALL" "$CHECKSUMS" | sha256sum -c - \
        || die "trivy checksum mismatch — aborting"
    tar -xzf "$TARBALL" -C "$LOCAL_BIN" trivy
    info "trivy installed → $LOCAL_BIN/trivy"
fi

cd "$SCRIPT_DIR"

# ── 6. Copy tool into Hermes agent ────────────────────────────────────────────
AGENT_TOOLS="$HERMES_HOME/hermes-agent/tools"
if [[ -d "$AGENT_TOOLS" ]]; then
    info "Copying docksec_tool.py → $AGENT_TOOLS/"
    cp "$SCRIPT_DIR/docksec_tool.py" "$AGENT_TOOLS/docksec_tool.py"
else
    warn "Hermes agent tools dir not found at $AGENT_TOOLS — skipping."
    warn "Copy docksec_tool.py manually once hermes-agent is in place."
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Installation complete. Three manual steps remaining:"
echo
echo "  1. Ensure ~/.local/bin is on your PATH if it isn't already:"
echo "       export PATH=\"\$HOME/.local/bin:\$PATH\""
echo "       # add the above line to ~/.bashrc or ~/.zshrc to persist it"
echo
echo "  2. Set DOCKSEC_* vars in ${HERMES_HOME}/.env (see .env.example):"
echo "       DOCKSEC_LLM_BASE_URL=https://app.manifest.build/v1"
echo "       DOCKSEC_LLM_API_KEY=<your key>"
echo "       DOCKSEC_LLM_MODEL=auto"
echo "       DOCKSEC_WORKER_PYTHON=${DOCKSEC_DIR}/venv/bin/python"
echo "       DOCKSEC_WORKER_SCRIPT=${DOCKSEC_DIR}/docksec_worker.py"
echo "       DOCKSEC_EXTRA_PATH=${LOCAL_BIN}"
echo
echo "  3. Register the docksec toolset in ${HERMES_HOME}/config.yaml:"
echo "       platform_toolsets:"
echo "         telegram:"
echo "           - docksec"
echo "         cli:"
echo "           - docksec"
echo
echo "  4. Restart the Hermes gateway to pick up the new tool."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
