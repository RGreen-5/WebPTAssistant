#!/bin/bash
set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_info() {
    echo -e "${YELLOW}[+] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

if [[ $EUID -ne 0 ]]; then
    print_error "Run this script with sudo"
    echo "Example: sudo bash setup.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(eval echo "~$REAL_USER")"

print_header "WebPT Assistant Minimal Setup"

print_header "Repairing package state"
dpkg --configure -a || true
apt-get -f install -y || true
print_success "Package state repaired"

print_header "Installing required system packages"
apt-get update -y
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    docker.io \
    docker-compose \
    git \
    curl
print_success "System packages installed"

print_header "Installing Python libraries"
python3 -m pip install --upgrade pip --break-system-packages --root-user-action=ignore
python3 -m pip install \
    requests \
    python-owasp-zap-v2.4 \
    rich \
    python-dateutil \
    --break-system-packages \
    --root-user-action=ignore
print_success "Python libraries installed"

print_header "Installing local Searchsploit files"
if [[ ! -d /opt/exploitdb/.git ]]; then
    rm -rf /opt/exploitdb
    git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
    print_success "ExploitDB repository cloned to /opt/exploitdb"
else
    git -C /opt/exploitdb pull --ff-only || true
    print_success "ExploitDB repository updated"
fi

if [[ ! -f /usr/local/bin/searchsploit ]]; then
    cat > /usr/local/bin/searchsploit <<'EOF'
#!/bin/bash
python3 /opt/exploitdb/searchsploit "$@"
EOF
    chmod +x /usr/local/bin/searchsploit
    print_success "searchsploit wrapper created"
else
    print_success "searchsploit wrapper already exists"
fi

print_header "Docker permissions"
usermod -aG docker "$REAL_USER" || true
print_success "Added $REAL_USER to docker group"

print_header "Verification"
python3 --version
nmap --version | head -1
docker --version
docker-compose --version
searchsploit --help >/dev/null 2>&1 && echo "searchsploit OK"
print_success "Verification complete"

print_header "Setup Complete"
echo "Log out and back in before using Docker without sudo."
echo "Then run:"
echo "cd ~/webpt"
echo "./run_docker.sh"
echo "./webpt scan --target http://TARGET/"
