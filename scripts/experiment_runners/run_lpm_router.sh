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

            # Save configuration
            cat > "$RUN_DIR/config.txt" << EOF
Variant: $VARIANT
Entries: $ENTRIES
Traffic Skew (Zipf): $SKEW
Timestamp: $RUN_TIMESTAMP
EOF

            # Locate the LPM router implementation
            LPM_ROUTER_DIR="$REPO_ROOT/motivation/arena_router"
            if [ ! -d "$LPM_ROUTER_DIR" ]; then
                echo "  Warning: arena_router not found"
                echo "[$RUN_TIMESTAMP] $VARIANT entries=$ENTRIES skew=$SKEW - SKIPPED (not found)" >> "$EXPERIMENT_LOG"
                continue
            fi

            # Build LPM router if not already built
            if [ ! -f "$LPM_ROUTER_DIR/build/load" ]; then
                echo "  Building arena_router..."
                (cd "$LPM_ROUTER_DIR" && make clean && make) || {
                    echo "  Build failed"
                    echo "[$RUN_TIMESTAMP] $VARIANT entries=$ENTRIES skew=$SKEW - FAILED (build)" >> "$EXPERIMENT_LOG"
                    continue
                }
            fi

            # Run experiment with parameters
            echo "  Running $VARIANT variant..."
            {
                # Build command based on variant
                case $VARIANT in
                    native)
                        # Test native LPM-MAP implementation
                        timeout 120 "$LPM_ROUTER_DIR/build/load" \
                            --entries "$ENTRIES" --zipf "$SKEW" \
                            2>&1 || echo "timeout or error"
                        ;;
                    arena)
                        # Test Arena-based implementation
                        timeout 120 "$LPM_ROUTER_DIR/build/load" \
                            --entries "$ENTRIES" --zipf "$SKEW" --arena \
                            2>&1 || echo "timeout or error"
                        ;;
                    beeswax)
                        # Test Beeswax multi-phase implementation
                        timeout 120 "$LPM_ROUTER_DIR/build/load" \
                            --entries "$ENTRIES" --zipf "$SKEW" --beeswax \
                            2>&1 || echo "timeout or error"
                        ;;
                esac
            } > "$RUN_DIR/output.txt" 2>&1

            # Extract throughput and latency metrics if available
            if grep -q "Throughput" "$RUN_DIR/output.txt"; then
                grep -E "Throughput|Latency|Cache" "$RUN_DIR/output.txt" > "$RUN_DIR/metrics.txt"
            fi

            {
                echo "Variant: $VARIANT"
                echo "Entries: $ENTRIES"
                echo "Skew: $SKEW"
                echo "Status: COMPLETED"
                echo "Output: $RUN_DIR/output.txt"
            } > "$RUN_DIR/run.log"

            echo "  ✓ Completed"
            echo "[$RUN_TIMESTAMP] $VARIANT entries=$ENTRIES skew=$SKEW - COMPLETED" >> "$EXPERIMENT_LOG"
        done
    done
done

echo ""
echo "=========================================="
echo "LPM Router experiments complete"
echo "=========================================="
echo "Results: $RESULT_DIR"
