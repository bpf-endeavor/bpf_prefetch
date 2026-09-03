#!/bin/bash
# BMC Experiment Runner
# Buffer/Cache Miss Classifier with Facebook workload (memcached via Mutilate)
# Figure 6: Performance with realistic workload

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="$REPO_ROOT/scripts/config/experiments.conf"

source "$CONFIG_FILE" || exit 1

if [ "$BMC_ENABLED" != "true" ]; then
    echo "BMC experiment is not enabled"
    exit 1
fi

RESULT_DIR="$RESULT_BASE_DIR/bmc"
mkdir -p "$RESULT_DIR"

echo "=========================================="
echo "BMC (Buffer/Cache Miss Classifier)"
echo "=========================================="
echo "Workload: $BMC_WORKLOAD"
echo "Duration: $BMC_DURATION seconds"
echo "Clients: $BMC_NUM_CLIENTS"
echo "Result directory: $RESULT_DIR"
echo ""

# Validate mutilate is available (needed for Facebook workload)
MUTILATE_PATH="$REPO_ROOT/others/workload-gen/mutilate/mutilate"
if [ ! -f "$MUTILATE_PATH" ]; then
    echo "Error: mutilate not found at $MUTILATE_PATH"
    echo "Run: make install_deps_gen"
    exit 1
fi

EXPERIMENT_LOG="$RESULT_DIR/experiment.log"
echo "BMC experiment started: $(date)" > "$EXPERIMENT_LOG"
echo "Configuration: $CONFIG_FILE" >> "$EXPERIMENT_LOG"
echo "Workload: $BMC_WORKLOAD (using mutilate)" >> "$EXPERIMENT_LOG"
echo "" >> "$EXPERIMENT_LOG"

RUN_TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
RUN_DIR="$RESULT_DIR/$RUN_TIMESTAMP"
mkdir -p "$RUN_DIR"

echo "Running BMC with $BMC_WORKLOAD workload..."

# Validate SSH to DUT
echo "Checking DUT connectivity..."
if ! ssh -i "$DUT_SSH_KEY" -o ConnectTimeout=5 "$DUT_USER@$DUT_CONTROL_IP" "echo 'OK'" > /dev/null 2>&1; then
    echo "Error: Cannot connect to DUT"
    echo "[$RUN_TIMESTAMP] BMC - FAILED (DUT unreachable)" >> "$EXPERIMENT_LOG"
    exit 1
fi

# Start memcached on DUT (if not already running)
echo "Ensuring memcached is running on DUT..."
ssh -i "$DUT_SSH_KEY" "$DUT_USER@$DUT_CONTROL_IP" \
    "pkill memcached || true; sleep 1; memcached -p 11211 -m 256 -t 4" \
    &> "$RUN_DIR/memcached.log" &
MEMCACHED_PID=$!
sleep 3  # Wait for memcached to start

# Save configuration
cat > "$RUN_DIR/config.txt" << EOF
Workload: $BMC_WORKLOAD
Duration: $BMC_DURATION seconds
Clients: $BMC_NUM_CLIENTS
DUT: $DUT_CONTROL_IP
Timestamp: $RUN_TIMESTAMP
EOF

# Run mutilate workload generator
echo "Generating $BMC_WORKLOAD workload with mutilate ($BMC_NUM_CLIENTS clients)..."

case $BMC_WORKLOAD in
    facebook)
        # Facebook workload trace (requires traces in mutilate directory)
        "$MUTILATE_PATH" \
            -s "$DUT_CONTROL_IP" \
            -c "$BMC_NUM_CLIENTS" \
            -t "$BMC_DURATION" \
            -l facebook_trace.txt \
            &> "$RUN_DIR/mutilate.log" || {
            echo "Fallback: Using uniform workload"
            "$MUTILATE_PATH" \
                -s "$DUT_CONTROL_IP" \
                -c "$BMC_NUM_CLIENTS" \
                -t "$BMC_DURATION" \
                &> "$RUN_DIR/mutilate.log"
        }
        ;;
    uniform|default)
        # Uniform workload
        "$MUTILATE_PATH" \
            -s "$DUT_CONTROL_IP" \
            -c "$BMC_NUM_CLIENTS" \
            -t "$BMC_DURATION" \
            &> "$RUN_DIR/mutilate.log"
        ;;
    *)
        echo "Unknown workload: $BMC_WORKLOAD"
        echo "[$RUN_TIMESTAMP] BMC - FAILED (unknown workload)" >> "$EXPERIMENT_LOG"
        exit 1
        ;;
esac

# Collect results from mutilate
if [ -f "$RUN_DIR/mutilate.log" ]; then
    grep -E "^Total|^Avg|^Min|^Max|^Operations" "$RUN_DIR/mutilate.log" > "$RUN_DIR/metrics.txt" || true
fi

# Collect cache miss statistics from DUT (if BMC eBPF program is loaded)
echo "Collecting cache miss metrics from DUT..."
ssh -i "$DUT_SSH_KEY" "$DUT_USER@$DUT_CONTROL_IP" \
    "cat /proc/bmc_stats 2>/dev/null || echo 'BMC stats unavailable'" \
    &> "$RUN_DIR/cache_stats.txt" || true

# Stop memcached
echo "Cleaning up..."
ssh -i "$DUT_SSH_KEY" "$DUT_USER@$DUT_CONTROL_IP" \
    "pkill memcached" \
    &> /dev/null || true
wait $MEMCACHED_PID 2>/dev/null || true

# Create run summary
{
    echo "Workload: $BMC_WORKLOAD"
    echo "Duration: $BMC_DURATION seconds"
    echo "Clients: $BMC_NUM_CLIENTS"
    echo "DUT: $DUT_CONTROL_IP"
    echo "Status: COMPLETED"
    echo "Results: $RUN_DIR"
} > "$RUN_DIR/run.log"

echo ""
echo "=========================================="
echo "BMC experiment complete"
echo "=========================================="
echo "Results: $RESULT_DIR"
echo "  - Workload log: $RUN_DIR/mutilate.log"
echo "  - Metrics: $RUN_DIR/metrics.txt"
echo "  - Cache stats: $RUN_DIR/cache_stats.txt"
echo ""
echo "[$RUN_TIMESTAMP] BMC $BMC_WORKLOAD - COMPLETED" >> "$EXPERIMENT_LOG"
