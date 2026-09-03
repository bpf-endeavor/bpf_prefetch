#!/bin/bash
# Install workload generator tools into others/workload-gen/
# This script clones and builds DPDK-based traffic generators

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKLOAD_GEN_DIR="$REPO_ROOT/others/workload-gen"
PATCHES_DIR="$REPO_ROOT/patches/workload-gen"

echo "Installing workload generator tools..."
echo "Target directory: $WORKLOAD_GEN_DIR"

# Create target directory
mkdir -p "$WORKLOAD_GEN_DIR"

# ===== Install dpdk-client-server =====
# URL provided: https://github.com/fshahinfar1/dpdk-client-server
echo "Cloning dpdk-client-server..."
if [ -d "$WORKLOAD_GEN_DIR/dpdk-client-server" ]; then
    echo "dpdk-client-server already exists, skipping clone"
else
    git clone https://github.com/fshahinfar1/dpdk-client-server.git "$WORKLOAD_GEN_DIR/dpdk-client-server"
fi

# Apply patches if they exist
if [ -d "$PATCHES_DIR" ]; then
    echo "Applying patches to dpdk-client-server..."
    for patch in "$PATCHES_DIR"/*.patch; do
        if [ -f "$patch" ]; then
            echo "Applying $(basename "$patch")..."
            (cd "$WORKLOAD_GEN_DIR/dpdk-client-server" && patch -p1 < "$patch")
        fi
    done
fi

# Build dpdk-client-server
echo "Building dpdk-client-server..."
cd "$WORKLOAD_GEN_DIR/dpdk-client-server"
make build || {
    echo "Building dpdk-client-server. Check dependencies:"
    echo "  - DPDK development files"
    echo "  - libdpdk-dev or similar"
    echo "  - Standard build tools (gcc, make)"
    exit 1
}

echo "dpdk-client-server built successfully"
echo "Binary location: $WORKLOAD_GEN_DIR/dpdk-client-server/build/app"

# ===== Install mutilate (memcached workload generator) =====
# Required for: BMC experiment with Facebook workload (Figure 6)
# URL provided: https://github.com/fshahinfar1/mutilate
echo "Installing mutilate (memcached workload generator)..."
if [ ! -d "$WORKLOAD_GEN_DIR/mutilate" ]; then
    git clone https://github.com/fshahinfar1/mutilate.git "$WORKLOAD_GEN_DIR/mutilate"
    cd "$WORKLOAD_GEN_DIR/mutilate"
    make || {
        echo "Warning: mutilate build failed. Check dependencies (libevent-dev, etc.)"
        echo "Continuing with other generators..."
    }
else
    echo "mutilate already installed"
fi

# ===== Optional: Install dpdk-burst-replay =====
# URL provided: https://github.com/fshahinfar1/dpdk-burst-replay
echo "Skipping dpdk-burst-replay installation (uncomment below if needed)"
# if [ ! -d "$WORKLOAD_GEN_DIR/dpdk-burst-replay" ]; then
#     echo "Cloning dpdk-burst-replay..."
#     git clone https://github.com/fshahinfar1/dpdk-burst-replay.git "$WORKLOAD_GEN_DIR/dpdk-burst-replay"
#     cd "$WORKLOAD_GEN_DIR/dpdk-burst-replay"
#     make || echo "Warning: dpdk-burst-replay build failed"
# fi

echo ""
echo "Workload generator installation complete!"
echo "Results stored in: $WORKLOAD_GEN_DIR/"
