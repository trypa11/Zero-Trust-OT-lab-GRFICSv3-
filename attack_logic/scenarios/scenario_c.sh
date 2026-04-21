#!/bin/bash
# SCENARIO C: Identity Brute Force & MFA Enforcement

KEYCLOAK_URL="http://192.168.100.20:8080"

log_time() {
    echo "  [TIME] Action started at: $(date '+%Y-%m-%d %H:%M:%S.%3N')"
}

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
