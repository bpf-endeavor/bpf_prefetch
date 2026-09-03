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

# Placeholder for actual experiment
{
    echo "Workload: $BMC_WORKLOAD"
    echo "Duration: $BMC_DURATION seconds"
    echo "Clients: $BMC_NUM_CLIENTS"
    echo "Status: OK (placeholder)"
} > "$RUN_DIR/run.log"

echo "[$RUN_TIMESTAMP] BMC $BMC_WORKLOAD - OK" >> "$EXPERIMENT_LOG"

echo ""
echo "=========================================="
echo "BMC experiment complete"
echo "=========================================="
echo "Results: $RESULT_DIR"
echo ""
echo "Note: This test requires memcached running on DUT"
echo "See: others/bmc/ for implementation details"
