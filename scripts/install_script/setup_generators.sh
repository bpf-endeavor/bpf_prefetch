#!/usr/bin/env bash
#
# Generator-only CloudLab setup for bpf_prefetch experiments.
#
# Installs:
#   - DPDK 23.11
#   - fshahinfar1/dpdk-client-server        (Katran)
#   - fshahinfar1/mutilate                  (BMC)
#   - fshahinfar1/dpdk-burst-replay         (LPM)
#   - bpf-endeavor/bpf_prefetch             (generator-side scripts / PCAP gen)
#
# Expected CloudLab experiment network:
#   DUT:       192.168.1.1
#   Generator: 192.168.1.2
#

set -euo pipefail

DPDK_VERSION="23.11"
GEN_DIR="$HOME/gen"
DEV_DIR="$HOME/dev"

DPDK_CLIENT_SERVER_REPO="https://github.com/fshahinfar1/dpdk-client-server.git"
MUTILATE_REPO="https://github.com/fshahinfar1/mutilate.git"
BURST_REPLAY_REPO="https://github.com/fshahinfar1/dpdk-burst-replay.git"
BPF_PREFETCH_REPO="https://github.com/bpf-endeavor/bpf_prefetch.git"

BURST_REPLAY_BRANCH="multicore-txrate"

###############################################################################
# Helpers
###############################################################################

log()
{
    echo
    echo "================================================================"
    echo "$*"
    echo "================================================================"
}

clone_if_missing()
{
    local repo="$1"
    local dst="$2"

    if [ -d "$dst/.git" ]; then
        echo "Already cloned: $dst"
        return
    fi

    git clone "$repo" "$dst"
}

###############################################################################
# Packages
###############################################################################

install_packages()
{
    log "Installing generator dependencies"

    sudo apt update

    sudo apt install -y \
        build-essential \
        git \
        wget \
        curl \
        ca-certificates \
        pkg-config \
        pciutils \
        ethtool \
        jq \
        cmake \
        meson \
        ninja-build \
        python3 \
        python3-pip \
        python3-pyelftools \
        libnuma-dev \
        libpcap-dev \
        libudev-dev \
        libnl-3-dev \
        libnl-route-3-dev \
        rdma-core \
        libibverbs-dev \
        librdmacm-dev \
        scons \
        libevent-dev \
        gengetopt \
        libzmq3-dev \
        autoconf \
        automake \
        libtool

    python3 -m pip install --user scapy
}

###############################################################################
# CloudLab NIC discovery
###############################################################################

configure_network_env()
{
    log "Discovering CloudLab experiment interface"

    # Look for an interface with a 192.168.x.x experiment address.
    NET_IFACE="$(
        ip -o -4 addr show \
        | awk '$4 ~ /^192\.168\./ {print $2; exit}'
    )"

    if [ -z "${NET_IFACE:-}" ]; then
        echo "ERROR: could not find an interface with a 192.168.x.x address."
        echo
        ip -br addr
        exit 1
    fi

    NET_PCI="$(
        ethtool -i "$NET_IFACE" 2>/dev/null \
        | awk '/bus-info:/ {print $2}' \
        | sed 's/^0000://'
    )"

    if [ -z "${NET_PCI:-}" ]; then
        echo "ERROR: could not determine PCI address for $NET_IFACE"
        exit 1
    fi

    NET_MAC="$(cat /sys/class/net/"$NET_IFACE"/address)"
    NET_IP="$(ip -o -4 addr show dev "$NET_IFACE" | awk '{print $4}')"

    echo "NET_IFACE = $NET_IFACE"
    echo "NET_PCI   = $NET_PCI"
    echo "NET_MAC   = $NET_MAC"
    echo "NET_IP    = $NET_IP"

    # Replace old definitions if this script is re-run.
    sed -i \
        -e '/^export NET_IFACE=/d' \
        -e '/^export NET_PCI=/d' \
        -e '/^export NET_MAC=/d' \
        "$HOME/.bashrc"

    {
        echo
        echo "# bpf_prefetch CloudLab generator"
        echo "export NET_IFACE=\"$NET_IFACE\""
        echo "export NET_PCI=\"$NET_PCI\""
        echo "export NET_MAC=\"$NET_MAC\""
    } >> "$HOME/.bashrc"

    export NET_IFACE NET_PCI NET_MAC
}

###############################################################################
# Hugepages
###############################################################################

configure_hugepages()
{
    log "Configuring hugepages"

    # DPDK only needs a reasonable hugepage pool for these generators.
    # Use 2 MB pages so that we do not require a GRUB change/reboot.
    local wanted=2048

    sudo sysctl -w vm.nr_hugepages="$wanted"

    if ! mountpoint -q /dev/hugepages; then
        sudo mkdir -p /dev/hugepages
        sudo mount -t hugetlbfs nodev /dev/hugepages
    fi

    grep -E 'HugePages|Hugepagesize' /proc/meminfo
}

###############################################################################
# Mellanox OFED installation
###############################################################################

function install_ofed {
	mkdir -p $HOME/dev/
	cd $HOME/dev/
	# OFED
	sudo lshw | grep mlx5 &> /dev/null
	has_mlx5=$?
	if [ $has_mlx5 -eq 0 ]; then
		echo This machine uses MLX5 driver
		source /etc/lsb-release
		if [ -z "$DISTRIB_ID" -o "$DISTRIB_ID" != "Ubuntu" ]; then
			echo "Failed to install the Mellanox OFED. Expected Ubuntu distribution."
			return 1
		fi
		ubuntu_release=$DISTRIB_RELEASE
		tar_name="MLNX_OFED_LINUX-23.10-1.1.9.0-ubuntu$ubuntu_release-x86_64"
		cd $HOME/gen/
		wget "https://content.mellanox.com/ofed/MLNX_OFED-23.10-1.1.9.0/MLNX_OFED_LINUX-23.10-1.1.9.0-ubuntu$ubuntu_release-x86_64.tgz"
		tar -xf "./$tar_name.tgz"
		cd $tar_name/
		yes | sudo ./mlnxofedinstall --dkms --dpdk
		echo You will need to reboot
	fi
}


###############################################################################
# DPDK
###############################################################################

install_dpdk()
{

    install_ofed
    log "Installing DPDK $DPDK_VERSION"

    # If a usable DPDK is already installed, don't rebuild it.
    if pkg-config --exists libdpdk; then
        echo "DPDK already installed:"
        pkg-config --modversion libdpdk
        return
    fi

    mkdir -p "$DEV_DIR"
    cd "$DEV_DIR"

    local tar="dpdk-${DPDK_VERSION}.tar.xz"
    local dir="dpdk-${DPDK_VERSION}"

    if [ ! -f "$tar" ]; then
        wget "https://fast.dpdk.org/rel/$tar"
    fi

    if [ ! -d "$dir" ]; then
        tar -xf "$tar"
    fi

    cd "$dir"

    if [ ! -d build ]; then
        meson setup build
    fi

    ninja -C build
    sudo meson install -C build
    sudo ldconfig

    echo
    echo "Installed DPDK:"
    pkg-config --modversion libdpdk
}

###############################################################################
# Katran generator
###############################################################################

install_dpdk_client_server()
{
    log "Installing Katran workload generator"

    mkdir -p "$GEN_DIR"

    local dst="$GEN_DIR/dpdk-client-server"

    clone_if_missing "$DPDK_CLIENT_SERVER_REPO" "$dst"

    cd "$dst"
    make -j"$(nproc)"

    test -x build/client_tcp_timestamp

    echo "Built:"
    echo "  $dst/build/client_tcp_timestamp"
}

###############################################################################
# BMC generator
###############################################################################

install_mutilate()
{
    log "Installing BMC workload generator"

    mkdir -p "$GEN_DIR"

    local dst="$GEN_DIR/mutilate"

    clone_if_missing "$MUTILATE_REPO" "$dst"

    cd "$dst"
    scons -j"$(nproc)"

    test -x ./mutilate
    test -x ./mutilateudp

    echo "Built:"
    echo "  $dst/mutilate"
    echo "  $dst/mutilateudp"
}

###############################################################################
# LPM generator
###############################################################################

install_dpdk_burst_replay()
{
    log "Installing LPM DPDK burst replay"

    mkdir -p "$GEN_DIR"

    local dst="$GEN_DIR/dpdk-burst-replay"

    clone_if_missing "$BURST_REPLAY_REPO" "$dst"

    cd "$dst"
    git fetch origin
    git checkout "$BURST_REPLAY_BRANCH"

    git submodule update --init --recursive

    mkdir -p build
    cd build

    cmake ..
    make -j"$(nproc)"
    sudo make install

    echo "Built dpdk-burst-replay under:"
    echo "  $dst/build/"
}

###############################################################################
# bpf_prefetch generator-side scripts
###############################################################################

install_bpf_prefetch_scripts()
{
    log "Fetching bpf_prefetch scripts"

    mkdir -p "$GEN_DIR"

    local dst="$GEN_DIR/bpf_prefetch"

    clone_if_missing "$BPF_PREFETCH_REPO" "$dst"

    echo "Generator-side scripts available at:"
    echo "  $dst/scripts/bmc/"
    echo "  $dst/motivation/bax_lpm/scripts/"
}

###############################################################################
# Final checks
###############################################################################

show_summary()
{
    log "Generator setup complete"

    echo "Network:"
    echo "  NET_IFACE=$NET_IFACE"
    echo "  NET_PCI=$NET_PCI"
    echo "  NET_MAC=$NET_MAC"

    echo
    echo "Katran:"
    echo "  $GEN_DIR/dpdk-client-server/build/client_tcp_timestamp"

    echo
    echo "BMC:"
    echo "  $GEN_DIR/mutilate/mutilate"
    echo "  $GEN_DIR/mutilate/mutilateudp"

    echo
    echo "LPM:"
    echo "  $GEN_DIR/dpdk-burst-replay/build/"
    echo "  $GEN_DIR/bpf_prefetch/motivation/bax_lpm/scripts/gen_pcap.py"

    echo
    echo "Run:"
    echo "  source ~/.bashrc"
}




###############################################################################
# Main
###############################################################################

main()
{
    install_packages

    mkdir -p "$GEN_DIR" "$DEV_DIR"

    configure_network_env
    configure_hugepages
    install_dpdk

    install_dpdk_client_server
    install_mutilate
    install_dpdk_burst_replay
    install_bpf_prefetch_scripts

    show_summary
}

main "$@"
