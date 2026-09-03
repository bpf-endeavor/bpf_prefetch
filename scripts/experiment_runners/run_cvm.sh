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

        # Save configuration
        cat > "$RUN_DIR/config.txt" << EOF
Variant: $VARIANT
Batch Size: $BATCH_SIZE
Items: $CVM_NUM_ITEMS
Operations: $CVM_OPERATIONS
Timestamp: $RUN_TIMESTAMP
EOF

        # Locate CVM implementation
        CVM_DIR="$REPO_ROOT/motivation"
        CVM_IMPL=""
        case $VARIANT in
            native)
                CVM_IMPL="$CVM_DIR/arena_cvm"
                ;;
            beeswax)
                CVM_IMPL="$CVM_DIR/bax_cvm"
                ;;
        esac

        if [ ! -d "$CVM_IMPL" ]; then
            echo "  Warning: $VARIANT CVM not found at $CVM_IMPL"
            echo "[$RUN_TIMESTAMP] $VARIANT batch=$BATCH_SIZE - SKIPPED" >> "$EXPERIMENT_LOG"
            continue
        fi

        # Build if needed
        if [ ! -f "$CVM_IMPL/build/load" ]; then
            echo "  Building $VARIANT CVM..."
            (cd "$CVM_IMPL" && make clean && make) || {
                echo "  Build failed"
                echo "[$RUN_TIMESTAMP] $VARIANT batch=$BATCH_SIZE - FAILED (build)" >> "$EXPERIMENT_LOG"
                continue
            }
        fi

        # Run experiment
        echo "  Running $VARIANT with batch size $BATCH_SIZE..."
        {
            timeout 300 "$CVM_IMPL/build/load" \
                --items "$CVM_NUM_ITEMS" \
                --operations "$CVM_OPERATIONS" \
                --batch-size "$BATCH_SIZE" \
                2>&1 || echo "timeout or error"
        } > "$RUN_DIR/output.txt" 2>&1

        # Extract metrics
        if grep -q "Throughput\|MOPS" "$RUN_DIR/output.txt"; then
            grep -E "Throughput|MOPS|Latency|Batch" "$RUN_DIR/output.txt" > "$RUN_DIR/metrics.txt" || true
        fi

        # Extract active batch size distribution (for Figure 15)
        if grep -q "Active batch" "$RUN_DIR/output.txt"; then
            grep -E "Active batch" "$RUN_DIR/output.txt" > "$RUN_DIR/batch_distribution.txt" || true
        fi

        # Create run summary
        {
            echo "Variant: $VARIANT"
            echo "Batch Size: $BATCH_SIZE"
            echo "Items: $CVM_NUM_ITEMS"
            echo "Operations: $CVM_OPERATIONS"
            echo "Status: COMPLETED"
            echo "Results: $RUN_DIR"
        } > "$RUN_DIR/run.log"

        echo "  ✓ Completed"
        echo "[$RUN_TIMESTAMP] $VARIANT batch=$BATCH_SIZE - COMPLETED" >> "$EXPERIMENT_LOG"
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
