#!/bin/bash

# Configuration
KALI_IP="192.168.100.100" 
ROUTER_IP="192.168.0.1" 
KEYCLOAK_URL="http://192.168.100.20:8080"
PLC_IP="192.168.95.2"

log_time() {
    echo "  [TIME] Action started at: $(date '+%Y-%m-%d %H:%M:%S.%3N')"
}

echo "==== SCENARIO A: Network & Protocol Reconnaissance Audit ===="
echo "[*] Step 1: Auditing Enterprise Zone (SIEM & Identity)..."
log_time
# Probing Wazuh Manager, Dashboard, and Keycloak
nmap -Pn -p 443,8080,1514,1515,55000 192.168.100.50 192.168.100.51 192.168.100.20 
echo ""

echo "[*] Step 2: Auditing IDMZ Zone (Proxies & Gateways)..."
log_time
nmap -Pn -p 80,443,8080 192.168.90.21 192.168.90.22
echo ""

echo "[*] Step 3: Auditing Level 3 Ops Connectivity (EWS)..."
log_time
nmap -Pn -p 22,80,443,3389 192.168.97.5
echo ""

echo "[*] Step 3: Auditing Level 2 Supervisory Connectivity (HMI)..."
log_time
nmap -Pn -p 22,80,443,3389,8080 192.168.96.10
echo ""

echo "[*] Step 4: Auditing Level 1/0 Control Connectivity (PLC)..."
log_time
nmap -Pn -p 22,80,443,502,8080 192.168.95.2
echo ""

echo "[*] Step 5: Launching Mdbget (Modbus Scan) to extract PLC registers..."
log_time
python3 /home/kali/Desktop/attack_suite.py --scan --count 5 --delay 0.5
echo "[+] Audit and Reconnaissance complete. Verify that 'Filtered' results correspond to SIEM 'FW DROP' logs."
echo ""

echo "==== SCENARIO B: Sabotage via False Data Injection (FDI) ===="
echo "[*] Step 1: Threat attempts direct Modbus write to PLC..."
log_time
python3 /home/kali/Desktop/attack_suite.py --fdi --val 32000
echo "[+] Sabotage complete. Check Wazuh for rules 100026, 100027, 100028."
echo ""

echo "==== SCENARIO C: Defense Evasion & Lateral Movement ===="
echo "[*] Step 1: User authenticates to Guacamole normally (simulate connection start)..."
# We can't perfectly simulate a guacd connection setup via simple curl without authenticating successfully
# but we can log that we are moving to Step 2.
echo "[*] Step 2: Internal threat modifies PLC code on EWS (simulate FIM alert)..."
# Wait, this script runs *inside* the Kali container! I cannot run docker commands here.
echo "  [!] Note: You must run the EWS modification from the host machine or use SSH from Kali if configured."
echo "  [!] To manually trigger FIM, run this on the host: docker exec EWS bash -c 'echo \"malicious\" >> /home/engineer/Desktop/chemical.st'"
echo "[*] Step 3: Threat attempts direct Modbus write to PLC..."
log_time
python3 /home/kali/Desktop/attack_suite.py --fdi --val 32000
echo "[+] Lateral Movement complete. Check Wazuh for rules 100200, Syscheck (FIM) and Modbus rules."
echo ""

echo "==== SCENARIO D: Identity Brute Force ===="
echo "[*] Simulating Keycloak brute force attack..."
log_time
# Simulating via hydra (assuming it's installed or using curl loops)
for i in {1..8}; do
    curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -d "client_id=admin-cli" -d "username=admin" -d "password=wrongpass$i" -d "grant_type=password" > /dev/null
done
echo "[+] Keycloak Brute Force complete. Check Wazuh for rules 100502, 100520, 100521."
echo ""
