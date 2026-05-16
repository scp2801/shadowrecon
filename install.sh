#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════╗
# ║             ShadowRecon — Installation Script v1.1            ║
# ║             Supports: Linux, Kali, Ubuntu, Debian, Termux     ║
# ║             [FOR EDUCATIONAL USE ONLY]                        ║
# ╚═══════════════════════════════════════════════════════════════╝

# Exit immediately if a command fails (we handle errors manually below)
set -e

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
MAGENTA='\033[95m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}  [»]${RESET} $1"; }
success() { echo -e "${GREEN}  [✓]${RESET} $1"; }
warning() { echo -e "${YELLOW}  [!]${RESET} $1"; }
error()   { echo -e "${RED}  [✗]${RESET} $1" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}──── $1 ────${RESET}"; }

# ─── Banner ───────────────────────────────────────────────────────────────────
clear
echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
 ____  _               _               ____
/ ___|| |__   __ _  __| | _____      _|  _ \ ___  ___ ___  _ __
\___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |_) / _ \/ __/ _ \| '_ \
 ___) | | | | (_| | (_| | (_) \ V  V /|  _ <  __/ (_| (_) | | | |
|____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_| \_\___|\___\___/|_| |_|
BANNER
echo -e "${RESET}"
echo -e "${MAGENTA}  ShadowRecon Installer v1.1${RESET}"
echo -e "${YELLOW}  ⚠  For authorized, educational use ONLY${RESET}"
echo ""
printf '%0.s═' {1..60}; echo ""

# ─── Platform Detection ───────────────────────────────────────────────────────
step "Platform Detection"

IS_TERMUX=false
IS_LINUX=false

if [ -d "/data/data/com.termux" ] || [ -n "${TERMUX_VERSION:-}" ]; then
    IS_TERMUX=true
    success "Detected: Android Termux"
elif [ -f "/etc/os-release" ]; then
    IS_LINUX=true
    # shellcheck source=/dev/null
    . /etc/os-release
    success "Detected: Linux — ${PRETTY_NAME:-$ID}"
else
    IS_LINUX=true
    warning "Unknown platform — attempting generic Linux install"
fi

# ─── Find Python 3.8+ ─────────────────────────────────────────────────────────
step "Python Check"

PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PY_VER=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 8 ]; then
            PYTHON_CMD="$cmd"
            success "Python $PY_VER found at $(command -v $cmd)"
            break
        else
            warning "Found $cmd $PY_VER — needs 3.8+"
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    warning "Python 3.8+ not found — installing..."
    if $IS_TERMUX; then
        pkg install python -y || error "Failed to install Python via pkg"
        PYTHON_CMD="python"
    else
        sudo apt-get update -qq
        sudo apt-get install -y python3 python3-pip python3-venv || error "Failed to install Python via apt"
        PYTHON_CMD="python3"
    fi
    success "Python installed: $($PYTHON_CMD --version)"
fi

# ─── System Dependencies ──────────────────────────────────────────────────────
step "System Dependencies"

if $IS_TERMUX; then
    info "Updating Termux packages (this may take a moment)..."
    pkg update -y 2>/dev/null || true
    pkg install -y python python-pip openssl curl git 2>/dev/null || true
    success "Termux packages ready"
elif $IS_LINUX; then
    info "Updating apt package lists..."
    sudo apt-get update -qq 2>/dev/null || true
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3-pip python3-dev python3-venv \
        libssl-dev libffi-dev build-essential \
        curl git 2>/dev/null || true
    success "System packages ready"
fi

# ─── Project Directories ──────────────────────────────────────────────────────
step "Project Setup"

mkdir -p output logs config assets screenshots
success "Directories created: output/ logs/ config/ assets/ screenshots/"

# Make install script itself executable (for re-runs)
chmod +x install.sh 2>/dev/null || true

# ─── Virtual Environment (Linux only) ────────────────────────────────────────
step "Python Environment"

USE_VENV=false
VENV_DIR="$(pwd)/venv"

if ! $IS_TERMUX && [ -z "${VIRTUAL_ENV:-}" ]; then
    echo ""
    read -rp "  [?] Create a virtual environment? (recommended) [Y/n]: " CREATE_VENV
    echo ""
    if [[ "${CREATE_VENV:-y}" =~ ^[Yy]$ ]] || [ -z "$CREATE_VENV" ]; then
        USE_VENV=true
    fi
fi

if $USE_VENV; then
    info "Creating virtual environment at $VENV_DIR ..."
    "$PYTHON_CMD" -m venv "$VENV_DIR" || error "Failed to create virtual environment"

    # Activate the venv
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"

    # CRITICAL FIX: Update PYTHON_CMD and PIP_CMD to point to venv binaries
    PYTHON_CMD="$VENV_DIR/bin/python"
    PIP_CMD="$VENV_DIR/bin/pip"

    success "Virtual environment created and activated"
    warning "Next time, activate it with:  source venv/bin/activate"
    info    "Then run:  python main.py -t example.com --all"
else
    # No venv — find the best pip
    PIP_CMD=""
    for pcmd in pip3 pip; do
        if command -v "$pcmd" &>/dev/null; then
            PIP_CMD="$pcmd"
            break
        fi
    done
    # Fallback: use python -m pip
    if [ -z "$PIP_CMD" ]; then
        PIP_CMD="$PYTHON_CMD -m pip"
    fi
    info "Using system pip: $PIP_CMD"
fi

# Pip flags for Termux (needed on newer Android/Termux to bypass pip restrictions)
PIP_FLAGS=""
if $IS_TERMUX; then
    PIP_FLAGS="--break-system-packages"
fi

# ─── Install Python Dependencies ──────────────────────────────────────────────
step "Python Dependencies"

info "Running: $PIP_CMD install -r requirements.txt $PIP_FLAGS"
echo ""

# CRITICAL FIX: Do NOT pipe pip through grep — it hides the real exit code.
# Run pip directly and let it print normally so errors are visible.
if ! $PIP_CMD install -r requirements.txt $PIP_FLAGS; then
    echo ""
    error "pip install failed — see errors above.
    Try manually:  $PIP_CMD install dnspython python-whois requests $PIP_FLAGS"
fi

echo ""
success "Python dependencies installed"

# Verify key packages actually imported correctly
info "Verifying package imports..."
"$PYTHON_CMD" -c "import dns.resolver; import whois; import requests; print('  All packages verified')" 2>/dev/null && \
    success "dnspython, python-whois, requests — all OK" || \
    warning "Some packages may be missing — tool will still work with reduced features"

# ─── File Permissions ─────────────────────────────────────────────────────────
step "File Permissions"

chmod +x main.py
success "main.py is executable"

# ─── Verify Installation ──────────────────────────────────────────────────────
step "Verification"

info "Running: $PYTHON_CMD main.py --version"
echo ""

# CRITICAL FIX: Run python with explicit path and capture output+exitcode correctly
if "$PYTHON_CMD" main.py --version; then
    echo ""
    printf '%0.s═' {1..60}; echo ""
    echo ""
    echo -e "${GREEN}${BOLD}  ShadowRecon installed successfully!${RESET}"
    echo ""
    echo -e "${CYAN}  Quick Start Commands:${RESET}"
    echo ""
    if $USE_VENV; then
        echo -e "  ${BOLD}# Activate venv each new session:${RESET}"
        echo -e "  ${YELLOW}source venv/bin/activate${RESET}"
        echo ""
    fi
    echo -e "  ${BOLD}# Full scan (all modules):${RESET}"
    echo -e "  python main.py -t example.com --all"
    echo ""
    echo -e "  ${BOLD}# Common combinations:${RESET}"
    echo -e "  python main.py -t example.com --whois --dns --geo"
    echo -e "  python main.py -t example.com --ports --port-range 1-1024"
    echo -e "  python main.py -t example.com --subdomains --sub-threads 100"
    echo -e "  python main.py -t example.com --secheaders --tech"
    echo -e "  python main.py -t example.com --all --output report --format both"
    echo ""
    echo -e "  ${BOLD}# Help:${RESET}"
    echo -e "  python main.py --help"
    echo ""
    echo -e "${YELLOW}  ⚠  Only scan systems you OWN or have EXPLICIT permission to test.${RESET}"
    echo ""
    printf '%0.s═' {1..60}; echo ""
else
    PYERR=$("$PYTHON_CMD" main.py --version 2>&1 || true)
    echo ""
    echo -e "${RED}  [✗] Verification failed. Python error:${RESET}"
    echo -e "${YELLOW}      $PYERR${RESET}"
    echo ""
    echo -e "${CYAN}  Troubleshooting steps:${RESET}"
    echo ""
    echo -e "  1. ${BOLD}Activate the venv first (if you chose venv):${RESET}"
    echo -e "     source venv/bin/activate"
    echo ""
    echo -e "  2. ${BOLD}Install missing packages manually:${RESET}"
    echo -e "     $PIP_CMD install dnspython python-whois requests $PIP_FLAGS"
    echo ""
    echo -e "  3. ${BOLD}Check Python version:${RESET}"
    echo -e "     $PYTHON_CMD --version   (must be 3.8+)"
    echo ""
    echo -e "  4. ${BOLD}Run python directly to see full error:${RESET}"
    echo -e "     $PYTHON_CMD main.py --version"
    echo ""
    exit 1
fi
