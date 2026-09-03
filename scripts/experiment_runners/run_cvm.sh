#!/bin/bash
# CVM Experiment Runner
# Context/Vector Map with Beeswax optimization
# Figures 13-15: throughput improvement, batch size effects, active batch analysis

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="$REPO_ROOT/scripts/config/experiments.conf"

source "$CONFIG_FILE" || exit 1

if [ "$CVM_ENABLED" != "true" ]; then
    echo "CVM experiment is not enabled"
    exit 1
fi

RESULT_DIR="$RESULT_BASE_DIR/cvm"
mkdir -p "$RESULT_DIR"

echo "=========================================="
echo "CVM (Context/Vector Map) Experiments"
echo "=========================================="
echo "Variants: ${CVM_VARIANTS[@]}"
echo "Batch sizes: ${CVM_BATCH_SIZES[@]}"
echo "Items: $CVM_NUM_ITEMS"
echo "Operations: $CVM_OPERATIONS"
echo "Result directory: $RESULT_DIR"
echo ""

EXPERIMENT_LOG="$RESULT_DIR/experiment.log"
echo "CVM experiment started: $(date)" > "$EXPERIMENT_LOG"
echo "Configuration: $CONFIG_FILE" >> "$EXPERIMENT_LOG"
echo "" >> "$EXPERIMENT_LOG"

TOTAL_RUNS=$(( ${#CVM_VARIANTS[@]} * ${#CVM_BATCH_SIZES[@]} ))
CURRENT_RUN=0

for VARIANT in "${CVM_VARIANTS[@]}"; do
    VARIANT_DIR="$RESULT_DIR/$VARIANT"
    mkdir -p "$VARIANT_DIR"

    for BATCH_SIZE in "${CVM_BATCH_SIZES[@]}"; do
        CURRENT_RUN=$((CURRENT_RUN + 1))
        RUN_TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
        RUN_DIR="$VARIANT_DIR/batch_$BATCH_SIZE/$RUN_TIMESTAMP"
        mkdir -p "$RUN_DIR"

        echo "[$CURRENT_RUN/$TOTAL_RUNS] $VARIANT with batch size $BATCH_SIZE"

        # Placeholder for actual experiment
        {
            echo "Variant: $VARIANT"
            echo "Batch Size: $BATCH_SIZE"
            echo "Items: $CVM_NUM_ITEMS"
            echo "Operations: $CVM_OPERATIONS"
            echo "Status: OK (placeholder)"
        } > "$RUN_DIR/run.log"

        echo "[$RUN_TIMESTAMP] $VARIANT batch=$BATCH_SIZE - OK" >> "$EXPERIMENT_LOG"
    done
done

echo ""
echo "=========================================="
echo "CVM experiments complete"
echo "=========================================="
echo "Results: $RESULT_DIR"
echo ""
echo "Analysis:"
echo "  - Figure 13: Compare native vs beeswax throughput"
echo "  - Figure 14: Batch size impact on throughput"
echo "  - Figure 15: Active batch size distribution during execution"
