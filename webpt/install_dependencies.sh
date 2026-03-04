#!/bin/bash

################################################################################
# WebPT Assistant - Complete Installation Script
#
# This script installs ALL dependencies needed to run your web application
# penetration testing tool on a fresh Linux (Debian/Ubuntu/Kali) system.
#
# Usage: bash install_dependencies.sh
#
# What it installs:
# - System packages (nmap, sqlmap, python3, etc.)
# - Python packages (zapv2, requests, rich, etc.)
# - OWASP ZAP (optional, for running locally)
#
################################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
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
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use: sudo bash install_dependencies.sh)"
        exit 1
    fi
    print_success "Running as root"
}

# Update package manager
update_packages() {
    print_header "Step 1: Updating Package Manager"
    apt-get update -y
    apt-get upgrade -y
    print_success "Package manager updated"
}

# Install system dependencies
install_system_deps() {
    print_header "Step 2: Installing System Dependencies"
    
    # Required packages
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
        "build-essential"
        "libssl-dev"
        "libffi-dev"
    )
    
    for package in "${PACKAGES[@]}"; do
        if dpkg -l | grep -q "^ii  $package"; then
            print_success "$package is already installed"
        else
            print_info "Installing $package..."
            apt-get install -y "$package"
            print_success "$package installed"
        fi
    done
}

# Install Python dependencies
install_python_deps() {
    print_header "Step 3: Installing Python Dependencies"
    
    # Upgrade pip
    print_info "Upgrading pip..."
    python3 -m pip install --upgrade pip setuptools wheel
    print_success "pip upgraded"
    
    # Required Python packages
    PYTHON_PACKAGES=(
        "zapv2==0.0.20"
        "requests>=2.28.0"
        "rich>=13.0.0"
        "python-dateutil>=2.8.0"
    )
    
    for package in "${PYTHON_PACKAGES[@]}"; do
        print_info "Installing Python package: $package"
        python3 -m pip install "$package"
        print_success "$package installed"
    done
}

# Verify installations
verify_installations() {
    print_header "Step 4: Verifying Installations"
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        print_success "Python installed: $PYTHON_VERSION"
    else
        print_error "Python3 not found!"
        exit 1
    fi
    
    # Check Nmap
    if command -v nmap &> /dev/null; then
        NMAP_VERSION=$(nmap --version | head -1)
        print_success "Nmap installed: $NMAP_VERSION"
    else
        print_error "Nmap not found!"
        exit 1
    fi
    
    # Check SQLMap
    if command -v sqlmap &> /dev/null; then
        print_success "SQLMap installed"
    else
        print_error "SQLMap not found!"
        exit 1
    fi
    
    # Check Python packages
    print_info "Verifying Python packages..."
    python3 -c "import zapv2; print('✓ zapv2')"
    python3 -c "import requests; print('✓ requests')"
    python3 -c "import rich; print('✓ rich')"
    print_success "All Python packages verified"
}

# Optional: Install OWASP ZAP from Debian repository
install_owasp_zap_repo() {
    print_header "Step 5: Installing OWASP ZAP (from repository)"
    
    apt-get install -y zaproxy
    print_success "OWASP ZAP installed from repository"
}

# Optional: Install OWASP ZAP manually (latest version)
install_owasp_zap_manual() {
    print_header "Step 5: Installing OWASP ZAP (manual - latest version)"
    
    print_info "Downloading OWASP ZAP..."
    
    # Create ZAP directory
    mkdir -p /opt/zaproxy
    cd /opt/zaproxy
    
    # Download latest ZAP
    # Note: You may need to update the URL if a newer version is available
    ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz"
    
    if command -v wget &> /dev/null; then
        wget -q "$ZAP_URL" -O zaproxy.tar.gz
    else
        curl -L "$ZAP_URL" -o zaproxy.tar.gz
    fi
    
    tar -xzf zaproxy.tar.gz
    rm zaproxy.tar.gz
    
    # Create symbolic link
    ln -sf /opt/zaproxy/ZAP_2.14.0/zap.sh /usr/local/bin/zaproxy
    
    print_success "OWASP ZAP installed manually"
}

# Create verification script
create_verification_script() {
    print_header "Step 6: Creating Verification Script"
    
    cat > /tmp/verify_webpt.py << 'EOF'
#!/usr/bin/env python3
"""
Quick verification script to test all dependencies
"""
import sys

print("\n" + "="*50)
print("WebPT Tool - Dependency Verification")
print("="*50 + "\n")

checks = {
    "Python 3": lambda: sys.version.split()[0],
    "zapv2": lambda: __import__('zapv2').__version__,
    "requests": lambda: __import__('requests').__version__,
    "rich": lambda: __import__('rich').__version__,
}

import subprocess

# Check system commands
system_checks = {
    "nmap": "nmap --version | head -1",
    "sqlmap": "sqlmap --version",
}

passed = 0
failed = 0

print("Python Packages:")
print("-" * 50)
for name, check in checks.items():
    try:
        version = check()
        print(f"✓ {name:20s} {version}")
        passed += 1
    except Exception as e:
        print(f"✗ {name:20s} {str(e)}")
        failed += 1

print("\nSystem Commands:")
print("-" * 50)
for name, cmd in system_checks.items():
    try:
        result = subprocess.check_output(cmd, shell=True, text=True).strip()
        print(f"✓ {name:20s} {result.split(chr(10))[0][:40]}")
        passed += 1
    except Exception as e:
        print(f"✗ {name:20s} {str(e)}")
        failed += 1

print("\n" + "="*50)
print(f"Results: {passed} passed, {failed} failed")
print("="*50 + "\n")

if failed == 0:
    print("✓ All dependencies installed correctly!")
    sys.exit(0)
else:
    print("✗ Some dependencies are missing!")
    sys.exit(1)
EOF
    
    chmod +x /tmp/verify_webpt.py
    python3 /tmp/verify_webpt.py
}

# Main menu
show_menu() {
    echo ""
    print_header "Installation Options"
    echo "1) Install all with ZAP from repository (RECOMMENDED - faster)"
    echo "2) Install all with ZAP manual (latest version - slower)"
    echo "3) Install without ZAP (for headless/remote usage)"
    echo "4) Exit"
    echo ""
}

# Main installation flow
main() {
    print_header "WebPT Tool - Dependency Installation"
    print_info "This script will install all required dependencies"
    echo ""
    
    # Always do these
    check_root
    update_packages
    install_system_deps
    install_python_deps
    verify_installations
    
    # Ask about ZAP
    while true; do
        show_menu
        read -p "Select option (1-4): " choice
        
        case $choice in
            1)
                install_owasp_zap_repo
                break
                ;;
            2)
                install_owasp_zap_manual
                break
                ;;
            3)
                print_info "Skipping OWASP ZAP installation"
                echo "Note: You'll need to run ZAP in Docker or install it manually"
                break
                ;;
            4)
                print_info "Exiting installation"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please select 1-4."
                ;;
        esac
    done
    
    # Verify everything
    create_verification_script
    
    # Final summary
    print_header "Installation Complete!"
    echo ""
    echo "Your system is ready to run the WebPT tool."
    echo ""
    echo "Next steps:"
    echo "1. Copy your WebPT tool files to a directory"
    echo "2. Make sure ZAP is running (if using Docker):"
    echo "   docker run -u zap -p 8080:8080 -t owasp/zap2docker-stable"
    echo "3. Run a scan:"
    echo "   PYTHONPATH=. python -m scripts.cli scan --target http://target.com"
    echo ""
    print_success "Installation successful!"
}

# Run main
main
