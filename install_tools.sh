#!/usr/bin/env bash
set -e

echo "[*] Updating APT and installing base packages..."
sudo apt update
sudo apt install -y \
  git curl wget build-essential \
  nmap whatweb gobuster \
  python3 python3-venv python3-pip

echo "[*] Installing Go (ถ้ามีแล้วจะข้าม)..."
if ! command -v go >/dev/null 2>&1; then
  GO_VERSION="1.22.5"
  wget "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
  if ! grep -q "export PATH=\$PATH:/usr/local/go/bin" "$HOME/.bashrc"; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
  fi
  export PATH=$PATH:/usr/local/go/bin
else
  echo "[*] Go already installed: $(go version)"
fi

# ตั้ง GOPATH (ถ้ายังไม่มี)
if [ -z "$GOPATH" ]; then
  if ! grep -q "export GOPATH=\$HOME/go" "$HOME/.bashrc"; then
    echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
    echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.bashrc"
  fi
  export GOPATH="$HOME/go"
  export PATH="$PATH:$GOPATH/bin"
fi

echo "[*] Installing ProjectDiscovery tools with go install..."

echo "  - Installing katana..."
go install github.com/projectdiscovery/katana/cmd/katana@latest

echo "  - Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "  - Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[*] Done."
echo "ให้รัน 'source ~/.bashrc' หรือเปิด shell ใหม่ก่อนใช้งาน tools เหล่านี้."