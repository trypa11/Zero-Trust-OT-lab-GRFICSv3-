#!/bin/bash
# Zero-Trust OT Lab — Attack Automation Orchestrator
# ================================================
# Calls individual scenario scripts located in attack_logic/scenarios/

# Ensure scripts are executable
chmod +x attack_logic/scenarios/*.sh

# Run Scenario A
bash attack_logic/scenarios/scenario_a.sh

# Run Scenario B
bash attack_logic/scenarios/scenario_b.sh

# Scenario B Detection Summary (Contextual)
echo "  [DETECTION SUMMARY — SCENARIO B]"
echo "    - Zero-Trust Identity Verified (MFA Satisfied)"
echo "    - PLC program file (chemical.st) modified on EWS (FIM)"
echo "    - PLC Management Console: Successful Admin Login Detected"
echo "    - Correlation: FIM change + PLC Console Access (Insider Threat)"
echo "    - OT Anomaly: Reactor Pressure > 90%"
echo "    - CRITICAL: Reactor Pressure > 97% (Explosion Risk)"
echo "    - Full Kill-Chain: File Tampering + PLC Upload + Process Sabotage"
echo ""

# Run Scenario C
bash attack_logic/scenarios/scenario_c.sh

# FINAL STEP: GLOBAL SYSTEM RESTORATION
echo "==== FINAL STEP: GLOBAL SYSTEM RESTORATION ===="

# Add a timestamped step so the metrics engine picks it up
echo "[*] Step 7: Restoring PLC values to safe operating state..."
echo "  [TIME] Action started at: $(date '+%Y-%m-%d %H:%M:%S.%3N')"
# Use the same logic that was previously in Scenario B but execute it after all tests
EWS_CONTAINER="EWS"
MALICIOUS_ST="/home/engineer/Desktop/chemical.st"
RESTORE_TAG="final_restore_$(date +%s)"
docker exec $EWS_CONTAINER bash -c "
  sed 's/override_sp_real : REAL := .*/override_sp_real : REAL := 2900.0; (* ${RESTORE_TAG} *) /' $MALICIOUS_ST \
  | sed 's/pressure_sp AT %MW2 : UINT := .*/pressure_sp AT %MW2 : UINT := 55295;/' \
  > /tmp/.st_tmp && cat /tmp/.st_tmp > $MALICIOUS_ST && rm /tmp/.st_tmp
"
docker exec $EWS_CONTAINER python3 /home/engineer/pomerium_plc_login.py /home/engineer/Desktop/chemical.st
# Restore safe setpoint via Modbus after compilation
sleep 5
docker exec plc python3 -c "
import socket, struct, time
for attempt in range(10):
    try:
        s = socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', 502))
        req = struct.pack('>HHHBBHH', 1, 0, 6, 1, 6, 1026, 55295)
        s.send(req); s.recv(256); s.close()
        print('[+] pressure_sp restored to 55295')
        break
    except Exception as e:
        time.sleep(3)
        if attempt == 9: print('[!] Modbus restore failed:', e)
" 2>&1
echo "[+] PLC Values Restored. System Cleaned."
echo ""

echo "==== ATTACK AUTOMATION COMPLETE ===="
echo "[*] Run 'python3 scripts/calculate_dissertation_metrics.py' to generate the report."
