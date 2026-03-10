#!/usr/bin/env bash
# OneClickScan V2 - ติดตั้ง tools ทั้งหมดบน Ubuntu
# Tools: katana, nmap, whatweb, gobuster, subfinder, httpx, sqlmap, xsstrike, hydra, commix
set -e

INSTALL_DIR="${INSTALL_DIR:-$HOME/tools}"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR" "$BIN_DIR"

echo "[*] Updating APT..."
sudo apt update

echo "[*] Installing base packages (nmap, whatweb, gobuster, hydra)..."
sudo apt install -y \
  git curl wget build-essential \
  nmap whatweb gobuster hydra \
  python3 python3-venv python3-pip

# --- Go (for ProjectDiscovery tools) ---
echo "[*] Installing Go..."
if ! command -v go >/dev/null 2>&1; then
  GO_VERSION="1.22.5"
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
  export PATH="$PATH:/usr/local/go/bin"
  if ! grep -q '/usr/local/go/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
  fi
else
  echo "  Go already installed: $(go version)"
fi

export PATH="$PATH:/usr/local/go/bin"
if [ -z "${GOPATH:-}" ]; then
  export GOPATH="$HOME/go"
  export PATH="$PATH:$GOPATH/bin"
  if ! grep -q 'GOPATH=' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
    echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.bashrc"
  fi
fi

# --- ProjectDiscovery (Go) ---
echo "[*] Installing ProjectDiscovery tools (katana, subfinder, httpx)..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# --- sqlmap ---
echo "[*] Installing sqlmap..."
if [ ! -d "$INSTALL_DIR/sqlmap" ]; then
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$INSTALL_DIR/sqlmap"
fi
chmod +x "$INSTALL_DIR/sqlmap/sqlmap.py"
ln -sf "$INSTALL_DIR/sqlmap/sqlmap.py" "$BIN_DIR/sqlmap" 2>/dev/null || true

# --- XSStrike ---
echo "[*] Installing XSStrike..."
if [ ! -d "$INSTALL_DIR/XSStrike" ]; then
  git clone --depth 1 https://github.com/s0md3v/XSStrike.git "$INSTALL_DIR/XSStrike"
  pip3 install --user -r "$INSTALL_DIR/XSStrike/requirements.txt" 2>/dev/null || true
fi
chmod +x "$INSTALL_DIR/XSStrike/xsstrike.py"
ln -sf "$INSTALL_DIR/XSStrike/xsstrike.py" "$BIN_DIR/xsstrike" 2>/dev/null || true

# --- commix ---
echo "[*] Installing commix..."
if [ ! -d "$INSTALL_DIR/commix" ]; then
  git clone --depth 1 https://github.com/commixproject/commix.git "$INSTALL_DIR/commix"
fi
chmod +x "$INSTALL_DIR/commix/commix.py"
ln -sf "$INSTALL_DIR/commix/commix.py" "$BIN_DIR/commix" 2>/dev/null || true

# --- PATH ---
if ! echo "$PATH" | grep -q "$BIN_DIR"; then
  echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.bashrc"
  export PATH="$BIN_DIR:$PATH"
fi

echo ""
echo "[*] Done. Installed tools:"
echo "  - katana, subfinder, httpx (Go, in \$GOPATH/bin)"
echo "  - nmap, whatweb, gobuster, hydra (apt)"
echo "  - sqlmap, xsstrike, commix (in $INSTALL_DIR, symlinks in $BIN_DIR)"
echo ""
echo "ถ้าเพิ่งติดตั้ง Go หรือ GOPATH: รัน 'source ~/.bashrc' หรือเปิด terminal ใหม่"
echo "ตรวจสอบ: katana -version && sqlmap --version && xsstrike -h && commix --version"
