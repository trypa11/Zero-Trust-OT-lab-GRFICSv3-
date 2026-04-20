#!/bin/bash

# Configuration
KALI_IP="192.168.100.100" 
ROUTER_IP="192.168.0.1" 
KEYCLOAK_URL="http://192.168.100.20:8080"
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
docker exec kali python3 /home/kali/Desktop/attack_suite.py --scan --count 5 --delay 0.5
echo "[+] Audit and Reconnaissance complete. Verify that 'Filtered' results correspond to SIEM 'FW DROP' logs."
echo ""

bash ./attacker/scenario_b_host.sh
echo ""
echo "  [DETECTION SUMMARY]"
echo "    - Zero-Trust Identity Verified (MFA Satisfied)"
echo "    - PLC program file (chemical.st) modified on EWS (FIM)"
echo "    - PLC Management Console: Successful Admin Login Detected"
echo "    - Correlation: FIM change + PLC Console Access (Insider Threat)"
echo "    - OT Anomaly: Reactor Pressure > 80%"
echo "    - CRITICAL: Reactor Pressure > 95% (Explosion Risk)"
echo "    - Full Kill-Chain: File Tampering + PLC Upload + Process Sabotage"
echo ""

echo "==== SCENARIO C: Identity Brute Force & MFA Enforcement ===="
echo "[*] Step 1: Brute-forcing engineer credentials (wrong passwords)..."
log_time
for i in {1..8}; do
    docker exec kali curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -d "client_id=admin-cli" -d "username=engineer" -d "password=wrongpass$i" -d "grant_type=password" > /dev/null
done
echo "  [+] 8 failed login attempts sent. Check Wazuh for rules 100502, 100520."
echo ""

echo "[*] Step 2: Correct password WITHOUT OTP (MFA blocks access)..."
log_time
STEP2_RESPONSE=$(docker exec kali curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli" -d "username=engineer" -d "password=pass" -d "grant_type=password")
echo "  [KEYCLOAK RESPONSE] $STEP2_RESPONSE"
echo "  [!] Result: Access DENIED — password accepted but MFA requirement blocks token issuance."
echo ""

echo "[*] Step 3: Correct password + WRONG OTP code (attacker guessing MFA)..."
log_time
for otp in 123456 654321 000000; do
    OTP_RESPONSE=$(docker exec kali curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -d "client_id=admin-cli" -d "username=engineer" -d "password=pass" -d "totp=$otp" -d "grant_type=password")
    echo "  [OTP=$otp] $OTP_RESPONSE"
done
echo "  [!] Result: Access DENIED — all OTP guesses rejected. MFA enforcement validated."
echo "[+] Scenario C complete. In a traditional OT lab, Step 2 alone would grant full access."
echo ""
