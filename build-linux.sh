#!/bin/bash

# CortexDB Linux Build Script
# Run this script on a Linux system to build CortexDB

echo "=== Building CortexDB for Linux ==="

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

# Update Rust to latest stable
echo "Updating Rust toolchain..."
rustup update stable

# Install required system dependencies
echo "Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    # Ubuntu/Debian
    sudo apt-get update
    sudo apt-get install -y build-essential pkg-config libssl-dev
elif command -v yum &> /dev/null; then
    # CentOS/RHEL/Fedora
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y pkgconf openssl-devel
elif command -v pacman &> /dev/null; then
    # Arch Linux
    sudo pacman -S --noconfirm base-devel openssl pkg-config
fi

# Build the project
echo "Building CortexDB..."
cargo build --release

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo "📁 Binary location: target/release/cortexdb"
    echo "📊 Binary size: $(du -h target/release/cortexdb | cut -f1)"
    
    # Create distribution directory
    mkdir -p dist
    cp target/release/cortexdb dist/
    cp -r data dist/ 2>/dev/null || echo "⚠️  No data directory found"
    
    echo ""
    echo "=== Installation Instructions ==="
    echo "1. Copy the 'cortexdb' binary to your desired location:"
    echo "   sudo cp dist/cortexdb /usr/local/bin/"
    echo ""
    echo "2. Make it executable:"
    echo "   sudo chmod +x /usr/local/bin/cortexdb"
    echo ""
    echo "3. Create a systemd service (optional):"
    echo "   sudo nano /etc/systemd/system/cortexdb.service"
    echo ""
    echo "4. Run CortexDB:"
    echo "   ./cortexdb"
    echo ""
else
    echo "❌ Build failed!"
    exit 1
fi
