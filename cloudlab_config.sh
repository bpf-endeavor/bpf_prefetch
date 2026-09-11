#!/usr/bin/env bash
# =============================================================================
# cloudlab_config.sh  –  CloudLab machine configuration
#
# Fill in the values below, then run:
#   bash scripts/user_setup_machines.sh
#
# Convention (matches ARTIFACT.md):
#   Node 0 = DUT  (Device Under Test)  – runs the Beeswax / bpf_prefetch code
#   Node 1 = Generator                 – sends traffic to DUT
#
# Find the SSH addresses in the CloudLab experiment page under
# "List View" → click a node → "SSH command" (e.g. ssh alice@clnode123.utah.cloudlab.us)
# =============================================================================

# ── DUT (Node 0) ─────────────────────────────────────────────────────────────
DUT_HOST=""          # SSH hostname or IP for DUT control interface
                     #   e.g. "clnode042.utah.cloudlab.us"
DUT_USER=""          # Your CloudLab username  e.g. "alice"

# ── Generator (Node 1) ───────────────────────────────────────────────────────
GEN_HOST=""          # SSH hostname or IP for generator control interface
                     #   e.g. "clnode043.utah.cloudlab.us"
GEN_USER=""          # Your CloudLab username (usually the same as DUT_USER)

# ── SSH key (optional) ───────────────────────────────────────────────────────
# Leave empty to use your SSH agent or default ~/.ssh/id_rsa key.
SSH_KEY=""           # e.g. "~/.ssh/cloudlab_key"

# ── Repository ───────────────────────────────────────────────────────────────
REPO_URL="https://github.com/bpf-endeavor/bpf_prefetch.git"
REPO_DIR="bpf_prefetch"   # directory name cloned on the remote machines
