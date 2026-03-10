#!/usr/bin/env bash
# OneClickScan V2 - ติดตั้ง tools ทั้งหมดบน Ubuntu
# Tools: katana, subfinder, httpx, nuclei, nmap, whatweb, gobuster,
#        hydra, sqlmap, xsstrike, commix, davtest (curl-based)
set -e

INSTALL_DIR="${INSTALL_DIR:-$HOME/tools}"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR" "$BIN_DIR"

echo "[*] Updating APT..."
sudo apt update

echo "[*] Installing base packages..."
sudo apt install -y \
  git curl wget build-essential \
  nmap whatweb gobuster hydra \
  python3 python3-venv python3-pip \
  libssl-dev libffi-dev

# ─── Go (required for ProjectDiscovery tools) ──────────────────────────────
echo "[*] Checking Go..."
if ! command -v go >/dev/null 2>&1; then
  GO_VERSION="1.22.5"
  echo "  Installing Go ${GO_VERSION}..."
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
  export PATH="$PATH:/usr/local/go/bin"
  grep -qxF 'export PATH=$PATH:/usr/local/go/bin' "$HOME/.bashrc" 2>/dev/null \
    || echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
else
  echo "  Go already installed: $(go version)"
fi

export PATH="$PATH:/usr/local/go/bin"
if [ -z "${GOPATH:-}" ]; then
  export GOPATH="$HOME/go"
  export PATH="$PATH:$GOPATH/bin"
  grep -qxF 'export GOPATH=$HOME/go' "$HOME/.bashrc" 2>/dev/null \
    || { echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
         echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.bashrc"; }
fi

# ─── ProjectDiscovery tools (Go) ───────────────────────────────────────────
echo "[*] Installing ProjectDiscovery tools (katana, subfinder, httpx, nuclei)..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[*] Updating nuclei templates..."
"$GOPATH/bin/nuclei" -update-templates -silent 2>/dev/null || true

# ─── sqlmap ────────────────────────────────────────────────────────────────
echo "[*] Installing sqlmap..."
if [ ! -d "$INSTALL_DIR/sqlmap" ]; then
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$INSTALL_DIR/sqlmap"
else
  git -C "$INSTALL_DIR/sqlmap" pull --ff-only 2>/dev/null || true
fi
chmod +x "$INSTALL_DIR/sqlmap/sqlmap.py"
ln -sf "$INSTALL_DIR/sqlmap/sqlmap.py" "$BIN_DIR/sqlmap" 2>/dev/null || true

# ─── XSStrike ──────────────────────────────────────────────────────────────
echo "[*] Installing XSStrike..."
if [ ! -d "$INSTALL_DIR/XSStrike" ]; then
  git clone --depth 1 https://github.com/s0md3v/XSStrike.git "$INSTALL_DIR/XSStrike"
  pip3 install --user -r "$INSTALL_DIR/XSStrike/requirements.txt" 2>/dev/null || true
else
  git -C "$INSTALL_DIR/XSStrike" pull --ff-only 2>/dev/null || true
fi
chmod +x "$INSTALL_DIR/XSStrike/xsstrike.py"
ln -sf "$INSTALL_DIR/XSStrike/xsstrike.py" "$BIN_DIR/xsstrike" 2>/dev/null || true

# ─── commix ────────────────────────────────────────────────────────────────
echo "[*] Installing commix..."
if [ ! -d "$INSTALL_DIR/commix" ]; then
  git clone --depth 1 https://github.com/commixproject/commix.git "$INSTALL_DIR/commix"
else
  git -C "$INSTALL_DIR/commix" pull --ff-only 2>/dev/null || true
fi
chmod +x "$INSTALL_DIR/commix/commix.py"
ln -sf "$INSTALL_DIR/commix/commix.py" "$BIN_DIR/commix" 2>/dev/null || true

# ─── SecLists (wordlists) ──────────────────────────────────────────────────
echo "[*] Installing SecLists (wordlists)..."
SECLISTS_DIR="$(dirname "$(readlink -f "$0")")/SecLists"
if [ ! -d "$SECLISTS_DIR" ]; then
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR"
else
  echo "  SecLists already present at $SECLISTS_DIR"
fi

# ─── Python venv + deps ────────────────────────────────────────────────────
echo "[*] Setting up Python virtual environment..."
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
if [ ! -d "$SCRIPT_DIR/venv" ]; then
  python3 -m venv "$SCRIPT_DIR/venv"
fi
"$SCRIPT_DIR/venv/bin/pip" install --upgrade pip -q
"$SCRIPT_DIR/venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" -q
# install playwright browsers
"$SCRIPT_DIR/venv/bin/playwright" install chromium 2>/dev/null || true

# ─── PATH ──────────────────────────────────────────────────────────────────
if ! echo "$PATH" | grep -q "$BIN_DIR"; then
  echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.bashrc"
  export PATH="$BIN_DIR:$PATH"
fi

echo ""
echo "══════════════════════════════════════════════════════"
echo "[*] Installation complete. Tools summary:"
echo "══════════════════════════════════════════════════════"
echo "  Go tools  : katana, subfinder, httpx, nuclei  (\$GOPATH/bin)"
echo "  apt       : nmap, whatweb, gobuster, hydra"
echo "  git/symlink: sqlmap, xsstrike, commix          ($BIN_DIR)"
echo "  wordlists : SecLists                           ($SECLISTS_DIR)"
echo "  python    : venv + requirements.txt"
echo ""
echo "ถ้าเพิ่งติดตั้ง Go หรือ GOPATH: รัน 'source ~/.bashrc' หรือเปิด terminal ใหม่"
echo ""
echo "ตรวจสอบ:"
echo "  katana -version && nuclei -version && subfinder -version && httpx -version"
echo "  sqlmap --version && xsstrike -h && commix --version"
