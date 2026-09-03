#!/bin/bash
# Katran Experiment Runner
# Orchestrates Katran load-balancer experiments with workload analysis
# Usage: bash run_katran.sh
# Requires: scripts/config/katran.conf configured

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="$REPO_ROOT/scripts/config/experiments.conf"

# Source configuration
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Configuration file not found: $CONFIG_FILE"
    echo "Run: cp scripts/config/experiments.conf.template scripts/config/experiments.conf"
    exit 1
fi
source "$CONFIG_FILE"

# Check if Katran is enabled
if [ "$KATRAN_ENABLED" != "true" ]; then
    echo "Katran experiment is not enabled in $CONFIG_FILE"
    exit 1
fi

# Use unified variables
DUT_IP="$DUT_CONTROL_IP"
RESULT_DIR="$RESULT_BASE_DIR/katran"
EXP_DURATION="$KATRAN_DURATION"
PACKET_RATE="$KATRAN_RATE"
FLOW_COUNTS=("${KATRAN_FLOW_COUNTS[@]}")
ZIPF_PARAMETERS=("${KATRAN_ZIPF_PARAMS[@]}")
KATRAN_MODES=("${KATRAN_MODES[@]}")
CPU_CORE="$KATRAN_CPU_CORE"
EXPERIMENT_IP="$DUT_EXPERIMENT_IP"
EXPERIMENT_MAC="$DUT_EXPERIMENT_MAC"
EXPERIMENT_NIC="$DUT_NET_IFACE"

# ===== SETUP & VALIDATION =====

# Validate required configuration
for VAR in DUT_IP DUT_USER DUT_SSH_KEY DUT_REPO_LOCATION EXPERIMENT_IP GEN_EXPERIMENT_IP GEN_NET_PCI CPU_CORE; do
    if [ -z "${!VAR}" ]; then
        echo "Error: $VAR not configured in $CONFIG_FILE"
        exit 1
    fi
done

# Validate SSH key exists
if [ ! -f "$DUT_SSH_KEY" ]; then
    echo "Error: SSH key not found at $DUT_SSH_KEY"
    exit 1
fi

echo "=========================================="
echo "Katran Experiment Configuration"
echo "=========================================="
echo "DUT Control IP: $DUT_IP"
echo "DUT User: $DUT_USER"
echo "Experiment Duration: $EXP_DURATION seconds"
echo "Modes: ${KATRAN_MODES[@]}"
echo "Flow Counts: ${FLOW_COUNTS[@]}"
echo "Zipf Parameters: ${ZIPF_PARAMETERS[@]}"
echo "Result Directory: $RESULT_DIR"
echo ""

# Validate SSH connectivity
echo "Validating SSH connectivity to DUT ($DUT_IP)..."
if ! ssh -i "$DUT_SSH_KEY" -o ConnectTimeout=5 "$DUT_USER@$DUT_IP" "echo 'SSH OK'" > /dev/null 2>&1; then
    echo "Error: Cannot connect to DUT via SSH"
    echo "Check:"
    echo "  1. DUT_CONTROL_IP is correct in $CONFIG_FILE"
    echo "  2. DUT_SSH_KEY exists: $DUT_SSH_KEY"
    echo "  3. SSH keys are configured (authorized_keys on DUT)"
    exit 1
fi
echo "SSH connectivity OK"
echo ""

# Create output directory
mkdir -p "$RESULT_DIR"
echo "Results will be stored in: $RESULT_DIR"

# ===== EXPERIMENT EXECUTION =====

echo "Starting Katran workload analysis..."
echo "This will test multiple flow counts and Zipf distributions."
echo "Total runs: ${#KATRAN_MODES[@]} modes × ${#FLOW_COUNTS[@]} flows × ${#ZIPF_PARAMETERS[@]} zipf params"
echo ""

TOTAL_RUNS=$(( ${#KATRAN_MODES[@]} * ${#FLOW_COUNTS[@]} * ${#ZIPF_PARAMETERS[@]} ))
CURRENT_RUN=0

EXPERIMENT_LOG="$RESULT_DIR/experiment.log"
echo "Experiment started: $(date)" > "$EXPERIMENT_LOG"
echo "Configuration: $CONFIG_FILE" >> "$EXPERIMENT_LOG"
echo "" >> "$EXPERIMENT_LOG"

for MODE in "${KATRAN_MODES[@]}"; do
    MODE_DIR="$RESULT_DIR/$MODE"
    mkdir -p "$MODE_DIR"

    echo "===== Testing $MODE mode ====="

    for FLOW_COUNT in "${FLOW_COUNTS[@]}"; do
        for ZIPF_PARAM in "${ZIPF_PARAMETERS[@]}"; do
            CURRENT_RUN=$((CURRENT_RUN + 1))
            RUN_TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
            RUN_DIR="$MODE_DIR/$RUN_TIMESTAMP"
            mkdir -p "$RUN_DIR"

            echo "[$CURRENT_RUN/$TOTAL_RUNS] Running: MODE=$MODE FLOWS=$FLOW_COUNT ZIPF=$ZIPF_PARAM"

            # Save configuration for this run
            cat > "$RUN_DIR/run_config.txt" << EOF
Timestamp: $RUN_TIMESTAMP
Mode: $MODE
Flow Count: $FLOW_COUNT
Zipf Parameter: $ZIPF_PARAM
DUT Control IP: $DUT_CONTROL_IP
Generator IP: $GEN_EXPERIMENT_IP
Generator PCI: $GEN_NET_PCI
Duration: $EXP_DURATION seconds
Packet Rate: $PACKET_RATE
CPU Core: $CPU_CORE
DUT Repo: $DUT_REPO_LOCATION
EOF

            # Start Katran server on DUT via SSH (control plane NIC)
            echo "  Starting Katran ($MODE) on DUT..."
            ssh -i "$DUT_SSH_KEY" -o ConnectTimeout=10 "$DUT_USER@$DUT_IP" \
                "cd $DUT_REPO_LOCATION/scripts/katran && export NET_IFACE=$KATRAN_EXPERIMENT_NIC && ./run_katran.sh --$MODE --lru-routing" \
                &> "$RUN_DIR/server.log" &
            SERVER_PID=$!
            sleep 20  # Wait for server to start

            # Calculate number of source IPs and ports from flow count
            case $FLOW_COUNT in
                1) IPS=1 ;;
                10) IPS=10 ;;
                100) IPS=100 ;;
                1000) IPS=1000 ;;
                10000) IPS=1000 ;;
                100000) IPS=1000 ;;
                1000000) IPS=1000 ;;
                2000000) IPS=2000 ;;
                4000000) IPS=4000 ;;
                6000000) IPS=6000 ;;
                8000000) IPS=8000 ;;
                *) IPS=1000 ;;
            esac
            PORTS=$((FLOW_COUNT / IPS))

            # Collect perf before traffic
            echo "  Collecting baseline perf metrics..."
            ssh -i "$DUT_SSH_KEY" "$DUT_USER@$DUT_IP" \
                "bash $DUT_REPO_LOCATION/scripts/measure_cache_miss.sh $CPU_CORE" \
                &> "$RUN_DIR/perf_before.txt" || true

            # Generate traffic via dpdk-client-server
            echo "  Generating traffic ($FLOW_COUNT flows, Zipf=$ZIPF_PARAM)..."
            DPDK_GEN="$REPO_ROOT/others/workload-gen/dpdk-client-server/build/client_tcp_timestamp"

            if [ ! -f "$DPDK_GEN" ]; then
                echo "  Warning: DPDK generator not found at $DPDK_GEN" | tee -a "$RUN_DIR/run.log"
            else
                sudo "$DPDK_GEN" \
                    -a "$GEN_NET_PCI" --lcores "0@(2,4),1@(6,8)" -- \
                    --num-queue 2 \
                    --client \
                    --ip-local "$GEN_EXPERIMENT_IP" \
                    --ip-dest "$KATRAN_EXPERIMENT_IP" \
                    --duration "$EXP_DURATION" --rate "$PACKET_RATE" \
                    --no-arp "$KATRAN_EXPERIMENT_MAC" \
                    --zipf-client-addr "$FLOW_COUNT/$PORTS/$ZIPF_PARAM" \
                    &> "$RUN_DIR/traffic_gen.log"
            fi

            sleep 5  # Wait for results to settle

            # Collect perf after traffic
            echo "  Collecting post-traffic perf metrics..."
            ssh -i "$DUT_SSH_KEY" "$DUT_USER@$DUT_IP" \
                "bash $DUT_REPO_LOCATION/scripts/measure_cache_miss.sh $CPU_CORE" \
                &> "$RUN_DIR/perf_after.txt" || true

            # Stop Katran server
            echo "  Stopping Katran..."
            ssh -i "$DUT_SSH_KEY" "$DUT_USER@$DUT_IP" \
                "pkill -INT run_katran.sh; sleep 2; pkill katran_server" \
                &> /dev/null || true
            wait $SERVER_PID 2>/dev/null || true

            # Collect throughput from traffic generator log
            if [ -f "$RUN_DIR/traffic_gen.log" ]; then
                grep -E "^Throughput|^Total packets" "$RUN_DIR/traffic_gen.log" > "$RUN_DIR/throughput.txt" || true
            fi

            # Log completion
            {
                echo "Mode: $MODE"
                echo "Flows: $FLOW_COUNT"
                echo "Zipf: $ZIPF_PARAM"
                echo "Status: COMPLETED"
                echo "Results: $RUN_DIR"
            } > "$RUN_DIR/run.log"

            echo "  ✓ Results saved"
            echo "[$RUN_TIMESTAMP] MODE=$MODE FLOWS=$FLOW_COUNT ZIPF=$ZIPF_PARAM - COMPLETED" >> "$EXPERIMENT_LOG"
        done
    done
done

echo ""
echo "=========================================="
echo "Katran experiment complete!"
echo "=========================================="
echo "Results stored in: $RESULT_DIR"
echo "Experiment log: $EXPERIMENT_LOG"
echo ""
echo "Next steps:"
echo "  1. Verify results in $RESULT_DIR"
echo "  2. Run analysis: scripts/katran/workload_analysis_scripts/clean_exp_results.py"
echo "  3. Compare with reference results in: docs/case_study/katran/"
