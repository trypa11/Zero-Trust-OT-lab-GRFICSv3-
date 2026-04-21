#!/bin/bash
# Run attack scenarios 10 times with unique report IDs
# ====================================================

set -e

NUM_RUNS=10
RESULTS_DIR="results/logs/test_runs_$(date +%Y%m%d_%H%M%S)"

echo "=========================================="
echo "  ZERO-TRUST OT LAB - 10 RUN STABILITY TEST"
echo "=========================================="
echo ""
echo "[*] Creating results directory: $RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

for i in $(seq 1 $NUM_RUNS); do
    echo ""
    echo "========== RUN $i / $NUM_RUNS =========="
    echo "[*] $(date '+%Y-%m-%d %H:%M:%S') - Starting attack scenario iteration..."

    # Clear previous attack logs
    > results/metrics/attack_results.txt

    # Run attack automation (capture to both results log AND attack_results.txt)
    echo "[*] Running attack scenarios..."
    bash attack_logic/attack_automation.sh 2>&1 | tee "$RESULTS_DIR/run_${i}_attack_output.log" results/metrics/attack_results.txt

    # Generate report with unique ID
    echo "[*] Generating report with ID $i..."
    python3 scripts/calculate_dissertation_metrics.py $i > "$RESULTS_DIR/run_${i}_metrics_output.log" 2>&1

    # Copy report to results directory
    REPORT_FILE=$(ls -t results/metrics/dissertation_metrics_report_*.txt 2>/dev/null | head -1)
    if [ -f "$REPORT_FILE" ]; then
        cp "$REPORT_FILE" "$RESULTS_DIR/"
        echo "[+] Report saved: $RESULTS_DIR/$REPORT_FILE"
    else
        echo "[!] WARNING: No report file generated for run $i"
    fi

    # Brief pause between runs
    if [ $i -lt $NUM_RUNS ]; then
        echo "[*] Waiting 10s before next run..."
        sleep 10
    fi
done

echo ""
echo "=========================================="
echo "  ALL 10 RUNS COMPLETED"
echo "=========================================="
echo ""
echo "[*] Results saved to: $RESULTS_DIR"
echo "[*] Report files:"
ls -lh "$RESULTS_DIR"/dissertation_metrics_report_*.txt 2>/dev/null | awk '{print "    " $9 " (" $5 ")"}'

echo ""
echo "[*] Summary statistics:"
REPORT_COUNT=$(find "$RESULTS_DIR" -name "dissertation_metrics_report_*.txt" | wc -l)
echo "    Total reports generated: $REPORT_COUNT / $NUM_RUNS"

if [ $REPORT_COUNT -eq $NUM_RUNS ]; then
    echo "[+] SUCCESS: All $NUM_RUNS iterations completed successfully!"
else
    echo "[!] WARNING: Only $REPORT_COUNT / $NUM_RUNS reports generated"
fi

echo ""
echo "[*] Next steps:"
echo "    - Review reports in: $RESULTS_DIR"
echo "    - Compare metrics across runs for stability analysis"
echo "    - Archive results: tar czf ${RESULTS_DIR}.tar.gz $RESULTS_DIR"
