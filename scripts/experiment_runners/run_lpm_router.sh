#!/bin/bash
# LPM Router Experiment Runner
# Tests native LPM-MAP, Arena-based, and Beeswax implementations
# Figures 7-10: workload skewedness, data layout, multi-phase overhead

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="$REPO_ROOT/scripts/config/experiments.conf"

source "$CONFIG_FILE" || exit 1

if [ "$LPM_ROUTER_ENABLED" != "true" ]; then
    echo "LPM router experiment is not enabled"
    exit 1
fi

RESULT_DIR="$RESULT_BASE_DIR/lpm_router"
mkdir -p "$RESULT_DIR"

echo "=========================================="
echo "LPM Router Benchmark"
echo "=========================================="
echo "Variants: ${LPM_ROUTER_VARIANTS[@]}"
echo "Entry counts: ${LPM_ROUTER_ENTRY_COUNTS[@]}"
echo "Traffic skew (Zipf): ${LPM_ROUTER_TRAFFIC_SKEW[@]}"
echo "Result directory: $RESULT_DIR"
echo ""

EXPERIMENT_LOG="$RESULT_DIR/experiment.log"
echo "LPM Router experiment started: $(date)" > "$EXPERIMENT_LOG"
echo "Configuration: $CONFIG_FILE" >> "$EXPERIMENT_LOG"
echo "" >> "$EXPERIMENT_LOG"

TOTAL_RUNS=$(( ${#LPM_ROUTER_VARIANTS[@]} * ${#LPM_ROUTER_ENTRY_COUNTS[@]} * ${#LPM_ROUTER_TRAFFIC_SKEW[@]} ))
CURRENT_RUN=0

for VARIANT in "${LPM_ROUTER_VARIANTS[@]}"; do
    VARIANT_DIR="$RESULT_DIR/$VARIANT"
    mkdir -p "$VARIANT_DIR"

    for ENTRIES in "${LPM_ROUTER_ENTRY_COUNTS[@]}"; do
        for SKEW in "${LPM_ROUTER_TRAFFIC_SKEW[@]}"; do
            CURRENT_RUN=$((CURRENT_RUN + 1))
            RUN_TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
            RUN_DIR="$VARIANT_DIR/$ENTRIES entries/$RUN_TIMESTAMP"
            mkdir -p "$RUN_DIR"

            echo "[$CURRENT_RUN/$TOTAL_RUNS] $VARIANT with $ENTRIES entries, Zipf=$SKEW"

            # Placeholder for actual experiment
            {
                echo "Variant: $VARIANT"
                echo "Entries: $ENTRIES"
                echo "Traffic Skew: $SKEW"
                echo "Status: OK (placeholder)"
            } > "$RUN_DIR/run.log"

            echo "[$RUN_TIMESTAMP] $VARIANT entries=$ENTRIES skew=$SKEW - OK" >> "$EXPERIMENT_LOG"
        done
    done
done

echo ""
echo "=========================================="
echo "LPM Router experiments complete"
echo "=========================================="
echo "Results: $RESULT_DIR"
