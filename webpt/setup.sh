#!/bin/bash

################################################################################
# WebPT Assistant - Installation Script for Kali Linux
#
# SIMPLE VERSION - Just installs what we need from Kali repos
# No Docker repo nonsense that breaks things
#
# Usage: sudo bash install_dependencies.sh
#
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    print_info "Run: sudo bash install_dependencies.sh"
    exit 1
fi

print_header "WebPT Tool - Kali Linux Installation"

# Step 1: Update
print_header "Step 1: Updating Package Manager"
apt-get update -y
apt-get upgrade -y
print_success "System updated"

# Step 2: Install system packages
print_header "Step 2: Installing System Tools"

PACKAGES=(
    "python3"
    "python3-pip"
    "python3-dev"
    "python3-venv"
    "nmap"
    "sqlmap"
    "git"
    "curl"
    "wget"
    "docker.io"
    "docker-compose"
)

for package in "${PACKAGES[@]}"; do
    print_info "Installing: $package"
    apt-get install -y "$package"
    print_success "$package installed"
done

# Step 3: Install Python packages
print_header "Step 3: Installing Python Libraries"

print_info "Upgrading pip..."
python3 -m pip install --upgrade pip --break-system-packages --root-user-action=ignore
print_success "pip upgraded"

python3 -m pip install requests rich python-dateutil --break-system-packages --root-user-action=ignore
print_success "Python libraries installed"

# Step 4: Verify installations
print_header "Step 4: Verifying Everything"

python3 --version
nmap --version | head -1
sqlmap --version | head -1
docker --version
docker-compose --version
print_success "All tools verified"

# Step 5: Add user to docker group
print_header "Step 5: Docker Permissions"

if [ -n "$SUDO_USER" ]; then
    usermod -aG docker "$SUDO_USER"
    print_success "Added $SUDO_USER to docker group"
fi

# Done
print_header "Installation Complete!"
echo ""
echo "✓ All dependencies installed!"
echo ""
echo "⚠️  IMPORTANT NEXT STEPS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. LOG OUT of Kali completely"
echo "   Type: exit (or close terminal and logout)"
echo ""
echo "2. LOG BACK IN to Kali"
echo ""
echo "3. Verify Docker works:"
echo "   docker ps"
echo ""
echo "4. Start your containers:"
echo "   cd ~/webpt"
echo "   docker-compose up -d"
echo ""
echo "5. Run your scan:"
echo "   PYTHONPATH=. python -m scripts.cli scan --target http://172.17.0.3"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_success "You're all set!"
