#!/usr/bin/env bash
# =============================================================================
# scripts/user_setup_machines.sh
#
# Automated CloudLab machine setup for bpf_prefetch artifact evaluation.
#
# What this script does:
#   1. Reads your cloudlab_config.sh (fill it in before running this).
#   2. SSHes into DUT and Generator, clones the repository on each.
#   3. Generates a passwordless SSH keypair on DUT and on Generator (if one
#      doesn't already exist), cross-installs the public keys, and scans
#      each machine's host-key fingerprint into the other's known_hosts,
#      so DUT and Generator can SSH directly into each other without any
#      interactive prompts.
#   4. Discovers the experiment NIC (192.168.x.x) on each machine.
#   5. Builds and pushes config.sh (repo root) to both machines so each
#      knows the other's experiment-network MAC/IP/interface.
#   6. Launches `make setup_dut`        on DUT       (runs in background).
#   7. Launches `make setup_generators` on Generator (runs in background).
#   8. Tails both log files so you can follow progress.
#
# Usage:
#   bash scripts/user_setup_machines.sh
#
# Prerequisite:
#   - Fill in cloudlab_config.sh at the repository root.
#   - Your SSH key must already be accepted by CloudLab
#     (usually ~/.ssh/id_rsa or the key you registered).
# =============================================================================

set -euo pipefail

# ── Locate repository root & config ──────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
USER_CONFIG="$REPO_ROOT/cloudlab_config.sh"

if [ ! -f "$USER_CONFIG" ]; then
    echo "ERROR: $USER_CONFIG not found."
    echo "Copy it from the repository root and fill in your CloudLab details."
    exit 1
fi

# shellcheck source=/dev/null
source "$USER_CONFIG"

# ── Validate required fields ──────────────────────────────────────────────────
for var in DUT_HOST DUT_USER GEN_HOST GEN_USER REPO_URL REPO_DIR; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: '$var' is empty in $USER_CONFIG. Please fill it in."
        exit 1
    fi
done

# ── SSH helper ────────────────────────────────────────────────────────────────
# Builds an SSH command with optional key and common options.
_ssh_opts=(-o StrictHostKeyChecking=no -o ConnectTimeout=30 -o BatchMode=yes)
if [ -n "${SSH_KEY:-}" ]; then
    # expand tilde
    SSH_KEY="${SSH_KEY/#\~/$HOME}"
    _ssh_opts+=(-i "$SSH_KEY")
fi

run_ssh() {
    # run_ssh USER HOST "command"
    local user="$1" host="$2"
    shift 2
    ssh "${_ssh_opts[@]}" "${user}@${host}" "$@"
}

run_scp() {
    # run_scp src USER HOST:dest
    local src="$1" user="$2" host="$3" dest="$4"
    local scp_opts=(-o StrictHostKeyChecking=no -o ConnectTimeout=30)
    if [ -n "${SSH_KEY:-}" ]; then
        scp_opts+=(-i "$SSH_KEY")
    fi
    scp "${scp_opts[@]}" "$src" "${user}@${host}:${dest}"
}

log() {
    echo
    echo "============================================================"
    echo "  $*"
    echo "============================================================"
}

# ── Step 1: Connectivity check ───────────────────────────────────────────────
log "Checking SSH connectivity"

echo -n "  DUT  ($DUT_USER@$DUT_HOST) ... "
run_ssh "$DUT_USER" "$DUT_HOST" "echo OK"

echo -n "  GEN  ($GEN_USER@$GEN_HOST) ... "
run_ssh "$GEN_USER" "$GEN_HOST" "echo OK"

# ── Step 2: Clone repo on both machines ──────────────────────────────────────
log "Cloning repository on DUT and Generator"

clone_repo_cmd=$(cat <<'EOCMD'
set -e
REPO_URL="__REPO_URL__"
REPO_DIR="__REPO_DIR__"
if [ -d "$HOME/$REPO_DIR/.git" ]; then
    echo "Repository already cloned at $HOME/$REPO_DIR"
else
    git clone "$REPO_URL" "$HOME/$REPO_DIR"
    echo "Cloned $REPO_URL -> $HOME/$REPO_DIR"
fi
EOCMD
)

dut_clone_cmd="${clone_repo_cmd//__REPO_URL__/$REPO_URL}"
dut_clone_cmd="${dut_clone_cmd//__REPO_DIR__/$REPO_DIR}"

echo "  Cloning on DUT ..."
run_ssh "$DUT_USER" "$DUT_HOST" bash -s <<< "$dut_clone_cmd"

echo "  Cloning on Generator ..."
run_ssh "$GEN_USER" "$GEN_HOST" bash -s <<< "$dut_clone_cmd"

# ── Step 3: Cross-install SSH keys so DUT and Generator can SSH to each other ──
#
# Neither machine has SSH access to the other yet, so we can't use
# ssh-copy-id directly between them. Instead we generate a keypair on each
# machine, read the public keys back to this (the user's) machine, and then
# push each public key into the other machine's authorized_keys.
log "Setting up mutual SSH access between DUT and Generator"

keygen_cmd='
set -e
mkdir -p ~/.ssh
chmod 700 ~/.ssh
if [ ! -f ~/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 -q
fi
cat ~/.ssh/id_ed25519.pub
'

echo "  Generating keypair on DUT ..."
DUT_PUBKEY=$(run_ssh "$DUT_USER" "$DUT_HOST" bash -s <<< "$keygen_cmd")

echo "  Generating keypair on Generator ..."
GEN_PUBKEY=$(run_ssh "$GEN_USER" "$GEN_HOST" bash -s <<< "$keygen_cmd")

append_pubkey_cmd=$(cat <<'EOCMD'
set -e
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
PUBKEY='__PUBKEY__'
grep -qxF "$PUBKEY" ~/.ssh/authorized_keys || echo "$PUBKEY" >> ~/.ssh/authorized_keys
EOCMD
)

echo "  Installing Generator's public key on DUT ..."
run_ssh "$DUT_USER" "$DUT_HOST" bash -s <<< "${append_pubkey_cmd//__PUBKEY__/$GEN_PUBKEY}"

echo "  Installing DUT's public key on Generator ..."
run_ssh "$GEN_USER" "$GEN_HOST" bash -s <<< "${append_pubkey_cmd//__PUBKEY__/$DUT_PUBKEY}"

# Pre-populate known_hosts on each side with the other's host key, so the
# first real SSH between DUT and Generator doesn't block on an interactive
# "are you sure you want to continue connecting?" fingerprint prompt.
keyscan_cmd=$(cat <<'EOCMD'
set -e
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/known_hosts
chmod 600 ~/.ssh/known_hosts
TARGET='__TARGET_HOST__'
ssh-keygen -F "$TARGET" -f ~/.ssh/known_hosts >/dev/null 2>&1 \
    || ssh-keyscan -H "$TARGET" >> ~/.ssh/known_hosts 2>/dev/null
EOCMD
)

echo "  Scanning Generator's host key from DUT ..."
run_ssh "$DUT_USER" "$DUT_HOST" bash -s <<< "${keyscan_cmd//__TARGET_HOST__/$GEN_HOST}"

echo "  Scanning DUT's host key from Generator ..."
run_ssh "$GEN_USER" "$GEN_HOST" bash -s <<< "${keyscan_cmd//__TARGET_HOST__/$DUT_HOST}"

echo "  Verifying DUT -> Generator SSH ... "
run_ssh "$DUT_USER" "$DUT_HOST" \
    "ssh -o BatchMode=yes -o ConnectTimeout=30 -i ~/.ssh/id_ed25519 ${GEN_USER}@${GEN_HOST} echo OK"

echo "  Verifying Generator -> DUT SSH ... "
run_ssh "$GEN_USER" "$GEN_HOST" \
    "ssh -o BatchMode=yes -o ConnectTimeout=30 -i ~/.ssh/id_ed25519 ${DUT_USER}@${DUT_HOST} echo OK"

# ── Step 4: Discover experiment NICs ─────────────────────────────────────────
log "Discovering experiment NICs (192.168.x.x) on each machine"

# Command run on each remote machine to discover the experiment NIC.
# Outputs: IFACE MAC EXPERIMENT_IP  (space-separated, one line)
NIC_DISCOVERY_CMD='
set -e
IFACE=$(ip -o -4 addr show | awk '"'"'$4 ~ /^192\.168\./ {print $2; exit}'"'"')
if [ -z "$IFACE" ]; then
    echo "ERROR: no 192.168.x.x interface found" >&2
    echo
    ip -br addr >&2
    exit 1
fi
MAC=$(cat /sys/class/net/"$IFACE"/address)
IP=$(ip -o -4 addr show dev "$IFACE" | awk '"'"'{split($4,a,"/"); print a[1]}'"'"')
echo "$IFACE $MAC $IP"
'

echo -n "  DUT experiment NIC  ... "
DUT_NIC_INFO=$(run_ssh "$DUT_USER" "$DUT_HOST" bash -s <<< "$NIC_DISCOVERY_CMD")
DUT_NET_IFACE=$(echo "$DUT_NIC_INFO" | awk '{print $1}')
DUT_MAC_ADDR=$(echo  "$DUT_NIC_INFO" | awk '{print $2}')
DUT_EXP_IP=$(echo   "$DUT_NIC_INFO" | awk '{print $3}')
echo "iface=$DUT_NET_IFACE  mac=$DUT_MAC_ADDR  exp_ip=$DUT_EXP_IP"

echo -n "  Generator experiment NIC  ... "
GEN_NIC_INFO=$(run_ssh "$GEN_USER" "$GEN_HOST" bash -s <<< "$NIC_DISCOVERY_CMD")
GEN_NET_IFACE=$(echo "$GEN_NIC_INFO" | awk '{print $1}')
GEN_MAC_ADDR=$(echo  "$GEN_NIC_INFO" | awk '{print $2}')
GEN_EXP_IP=$(echo   "$GEN_NIC_INFO" | awk '{print $3}')
echo "iface=$GEN_NET_IFACE  mac=$GEN_MAC_ADDR  exp_ip=$GEN_EXP_IP"

# ── Step 5: Build and push config.sh ─────────────────────────────────────────
#
# config.sh is read by experiment scripts on both machines.
# Fields (from the file's own comments):
#   DUT_SERVER   – control-interface IP/hostname of the DUT  (used by gen to SSH in)
#   DUT_USER     – SSH username for DUT
#   GEN_EXP_IP   – experiment IP of the generator  (192.168.1.2)
#   DUT_NET_IFACE– name of the experiment NIC on DUT
#   DUT_MAC_ADDR – MAC of the experiment NIC on DUT
#
log "Building config.sh and pushing to both machines"

TMP_CONFIG=$(mktemp /tmp/bpf_prefetch_config_XXXXXX.sh)
trap 'rm -f "$TMP_CONFIG"' EXIT

cat > "$TMP_CONFIG" <<EOF
#!/usr/bin/env bash
# config.sh – auto-generated by scripts/user_setup_machines.sh
# Do not edit by hand; re-run the setup script to regenerate.

DUT_SERVER="$DUT_HOST"         # control-interface hostname/IP of DUT
DUT_USER="$DUT_USER"           # SSH username for DUT
GEN_EXP_IP="$GEN_EXP_IP"      # experiment IP of the generator (192.168.1.2)
DUT_NET_IFACE="$DUT_NET_IFACE" # experiment NIC name on DUT
DUT_MAC_ADDR="$DUT_MAC_ADDR"   # MAC of DUT's experiment NIC

# Extra fields (available for convenience in experiment scripts)
GEN_SERVER="$GEN_HOST"         # control-interface hostname/IP of generator
GEN_USER="$GEN_USER"           # SSH username for generator
GEN_NET_IFACE="$GEN_NET_IFACE" # experiment NIC name on generator
GEN_MAC_ADDR="$GEN_MAC_ADDR"   # MAC of generator's experiment NIC
DUT_EXP_IP="$DUT_EXP_IP"      # experiment IP of DUT (192.168.1.1)
EOF

echo "  Pushing config.sh to DUT ..."
run_scp "$TMP_CONFIG" "$DUT_USER" "$DUT_HOST" "\$HOME/$REPO_DIR/config.sh"

echo "  Pushing config.sh to Generator ..."
run_scp "$TMP_CONFIG" "$GEN_USER" "$GEN_HOST" "\$HOME/$REPO_DIR/config.sh"

echo "  Done."
echo ""
echo "  Generated config.sh:"
cat "$TMP_CONFIG"

# ── Step 6: Launch setup on both machines ────────────────────────────────────
log "Launching make setup_dut on DUT (background)"
DUT_LOG="\$HOME/bpf_prefetch_setup_dut.log"
run_ssh "$DUT_USER" "$DUT_HOST" bash -s <<EOF
nohup bash -c 'cd \$HOME/$REPO_DIR && make setup_dut' > $DUT_LOG 2>&1 &
echo "PID=\$!"
echo "Log:  $DUT_LOG"
EOF

log "Launching make setup_generators on Generator (background)"
GEN_LOG="\$HOME/bpf_prefetch_setup_gen.log"
run_ssh "$GEN_USER" "$GEN_HOST" bash -s <<EOF
nohup bash -c 'cd \$HOME/$REPO_DIR && make setup_generators' > $GEN_LOG 2>&1 &
echo "PID=\$!"
echo "Log:  $GEN_LOG"
EOF

# ── Summary ───────────────────────────────────────────────────────────────────
log "Setup launched – summary"
cat <<SUMMARY
  DUT       : $DUT_USER@$DUT_HOST
  Generator : $GEN_USER@$GEN_HOST

  Experiment network:
    DUT       iface=$DUT_NET_IFACE   mac=$DUT_MAC_ADDR   ip=$DUT_EXP_IP
    Generator iface=$GEN_NET_IFACE   mac=$GEN_MAC_ADDR   ip=$GEN_EXP_IP

  Both machines are now running their setup scripts in the background.

  Follow progress:
    DUT      → ssh $DUT_USER@$DUT_HOST "tail -f ~/bpf_prefetch_setup_dut.log"
    Generator→ ssh $GEN_USER@$GEN_HOST "tail -f ~/bpf_prefetch_setup_gen.log"

  NOTE: setup_dut compiles a custom kernel; it takes 1-2 hours and will
  trigger a reboot mid-way (the script resumes automatically via crontab).
  setup_generators needs a reboot after Mellanox OFED install (also
  automatic via crontab).

  Once both setups report DONE, continue with ARTIFACT.md instructions.
SUMMARY
