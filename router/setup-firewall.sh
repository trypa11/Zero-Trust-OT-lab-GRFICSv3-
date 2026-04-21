#!/usr/bin/env bash
# setup-firewall.sh - True Zero Trust Firewall with Dynamic Interface Detection

set -euo pipefail

CONFIG_PATH="/etc/firewall/config.json"
RULES_PATH="/etc/firewall/rules"

echo "Detecting network interfaces based on subnets..."

# Helper to find interface by subnet
find_if() {
    ip -4 addr show | grep "$1" | awk '{print $NF}' | head -n 1
}

IF_SUPERVISORY=$(find_if '192.168.96.')
IF_ENTERPRISE=$(find_if '192.168.100.')
IF_IDMZ=$(find_if '192.168.90.')
IF_CONTROL=$(find_if '192.168.95.')
IF_MANOPS=$(find_if '192.168.97.')

echo "Mapping: Supervisory=$IF_SUPERVISORY, Enterprise=$IF_ENTERPRISE, IDMZ=$IF_IDMZ, Control=$IF_CONTROL, ManOps=$IF_MANOPS"

# Ensure gateway IPs exist (Manual identity takeover)
[[ -n "$IF_SUPERVISORY" ]] && ip addr add 192.168.96.1/24 dev "$IF_SUPERVISORY" 2>/dev/null || true
[[ -n "$IF_ENTERPRISE" ]] && ip addr add 192.168.100.1/24 dev "$IF_ENTERPRISE" 2>/dev/null || true
[[ -n "$IF_IDMZ" ]] && ip addr add 192.168.90.1/24 dev "$IF_IDMZ" 2>/dev/null || true
[[ -n "$IF_CONTROL" ]] && ip addr add 192.168.95.1/24 dev "$IF_CONTROL" 2>/dev/null || true
[[ -n "$IF_MANOPS" ]] && ip addr add 192.168.97.1/24 dev "$IF_MANOPS" 2>/dev/null || true


# Always regenerate rules to ensure correctness after topology changes
echo "Initializing True Zero Trust firewall configuration..."
mkdir -p /etc/firewall

# Static IP definitions (Restored to original baseline)
HMI_IP="192.168.96.10"
SIM_IP="192.168.95.10"
EWS_IP="192.168.97.5"
PLC_IP="192.168.95.2"
WAZUH_MNGR="192.168.100.51"
WAZUH_DASH="192.168.100.50"
KEYCLOAK_IP="192.168.100.20"
POMERIUM_IP="192.168.90.21"
GUAC_WEB_IP="192.168.90.22"
GUACD_IP="192.168.90.23"
GUAC_DB_IP="192.168.90.24"
KALI_IP="192.168.100.100"
CALDERA_IP="192.168.100.101"

cat <<EOF > "$CONFIG_PATH"
{
  "rules": [
    { "iface_in": "$IF_SUPERVISORY", "iface_out": "$IF_ENTERPRISE", "src": "192.168.96.0/24", "dst": "$WAZUH_MNGR", "proto": "tcp", "dport": "1514", "action": "ACCEPT" },
    { "iface_in": "$IF_MANOPS", "iface_out": "$IF_ENTERPRISE", "src": "192.168.97.0/24", "dst": "$WAZUH_MNGR", "proto": "tcp", "dport": "1514", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_ENTERPRISE", "src": "192.168.90.0/24", "dst": "$WAZUH_MNGR", "proto": "tcp", "dport": "1514", "action": "ACCEPT" },
    { "iface_in": "$IF_SUPERVISORY", "iface_out": "$IF_ENTERPRISE", "src": "192.168.96.0/24", "dst": "$WAZUH_MNGR", "proto": "tcp", "dport": "1515", "action": "ACCEPT" },
    { "iface_in": "$IF_MANOPS", "iface_out": "$IF_ENTERPRISE", "src": "192.168.97.0/24", "dst": "$WAZUH_MNGR", "proto": "tcp", "dport": "1515", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_ENTERPRISE", "src": "192.168.90.0/24", "dst": "$WAZUH_MNGR", "proto": "tcp", "dport": "1515", "action": "ACCEPT" },
    { "iface_in": "$IF_SUPERVISORY", "iface_out": "$IF_CONTROL", "src": "$HMI_IP", "dst": "$PLC_IP", "proto": "tcp", "dport": "502", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_SUPERVISORY", "src": "$POMERIUM_IP", "dst": "$HMI_IP", "proto": "tcp", "dport": "8080", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_CONTROL", "src": "$POMERIUM_IP", "dst": "$PLC_IP", "proto": "tcp", "dport": "8080", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_ENTERPRISE", "src": "$POMERIUM_IP", "dst": "$KEYCLOAK_IP", "proto": "tcp", "dport": "8080", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_CONTROL", "src": "$POMERIUM_IP", "dst": "$SIM_IP", "proto": "tcp", "dport": "80", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_IDMZ", "src": "$POMERIUM_IP", "dst": "$GUAC_WEB_IP", "proto": "tcp", "dport": "8080", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_IDMZ", "src": "$GUAC_WEB_IP", "dst": "$GUACD_IP", "proto": "tcp", "dport": "4822", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_IDMZ", "src": "$GUAC_WEB_IP", "dst": "$GUAC_DB_IP", "proto": "tcp", "dport": "5432", "action": "ACCEPT" },
    { "iface_in": "$IF_MANOPS", "iface_out": "$IF_IDMZ", "src": "$EWS_IP", "dst": "$POMERIUM_IP", "proto": "tcp", "dport": "443", "action": "ACCEPT" },
    { "iface_in": "$IF_MANOPS", "iface_out": "$IF_ENTERPRISE", "src": "$EWS_IP", "dst": "$KEYCLOAK_IP", "proto": "tcp", "dport": "8080", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_MANOPS", "src": "$GUACD_IP", "dst": "$EWS_IP", "proto": "tcp", "dport": "5900", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_MANOPS", "src": "$GUACD_IP", "dst": "$EWS_IP", "proto": "tcp", "dport": "22", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_MANOPS", "src": "$GUACD_IP", "dst": "$EWS_IP", "proto": "tcp", "dport": "3389", "action": "ACCEPT" },
    { "iface_in": "$IF_IDMZ", "iface_out": "$IF_ENTERPRISE", "src": "$GUAC_WEB_IP", "dst": "$WAZUH_MNGR", "proto": "udp", "dport": "514", "action": "ACCEPT" }
  ],
  "auth": { "username": "${ROUTER_ADMIN_USER}", "password": "${ROUTER_ADMIN_PASSWORD}" }
}
EOF

echo "Generating iptables rules..."
cat <<EOF > "$RULES_PATH"
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOGDROP - [0:0]
-A LOGDROP -m limit --limit 6/minute --limit-burst 2 -j NFLOG --nflog-group 1 --nflog-prefix "FW DROP: " 
-A LOGDROP -j DROP
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i $IF_SUPERVISORY -o $IF_ENTERPRISE -p tcp -s 192.168.96.0/24 -d $WAZUH_MNGR --dport 1514 -j ACCEPT
-A FORWARD -i $IF_MANOPS -o $IF_ENTERPRISE -p tcp -s 192.168.97.0/24 -d $WAZUH_MNGR --dport 1514 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_ENTERPRISE -p tcp -s 192.168.90.0/24 -d $WAZUH_MNGR --dport 1514 -j ACCEPT
-A FORWARD -i $IF_SUPERVISORY -o $IF_ENTERPRISE -p tcp -s 192.168.96.0/24 -d $WAZUH_MNGR --dport 1515 -j ACCEPT
-A FORWARD -i $IF_MANOPS -o $IF_ENTERPRISE -p tcp -s 192.168.97.0/24 -d $WAZUH_MNGR --dport 1515 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_ENTERPRISE -p tcp -s 192.168.90.0/24 -d $WAZUH_MNGR --dport 1515 -j ACCEPT
-A FORWARD -i $IF_SUPERVISORY -o $IF_CONTROL -p tcp -s $HMI_IP -d $PLC_IP --dport 502 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_SUPERVISORY -p tcp -s $POMERIUM_IP -d $HMI_IP --dport 8080 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_CONTROL -p tcp -s $POMERIUM_IP -d $PLC_IP --dport 8080 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_ENTERPRISE -p tcp -s $POMERIUM_IP -d $KEYCLOAK_IP --dport 8080 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_CONTROL -p tcp -s $POMERIUM_IP -d $SIM_IP --dport 80 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_IDMZ -p tcp -s $POMERIUM_IP -d $GUAC_WEB_IP --dport 8080 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_IDMZ -p tcp -s $GUAC_WEB_IP -d $GUACD_IP --dport 4822 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_IDMZ -p tcp -s $GUAC_WEB_IP -d $GUAC_DB_IP --dport 5432 -j ACCEPT
-A FORWARD -i $IF_MANOPS -o $IF_IDMZ -p tcp -s $EWS_IP -d $POMERIUM_IP --dport 443 -j ACCEPT
-A FORWARD -i $IF_ENTERPRISE -o $IF_IDMZ -p tcp -s 192.168.100.0/24 -d $POMERIUM_IP --dport 443 -j ACCEPT
-A FORWARD -i $IF_MANOPS -o $IF_ENTERPRISE -p tcp -s $EWS_IP -d $KEYCLOAK_IP --dport 8080 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_MANOPS -p tcp -s $GUACD_IP -d $EWS_IP --dport 5900 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_MANOPS -p tcp -s $GUACD_IP -d $EWS_IP --dport 22 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_MANOPS -p tcp -s $GUACD_IP -d $EWS_IP --dport 3389 -j ACCEPT
-A FORWARD -i $IF_IDMZ -o $IF_ENTERPRISE -p udp -s $GUAC_WEB_IP -d $WAZUH_MNGR --dport 514 -j ACCEPT
-A FORWARD -j LOGDROP
COMMIT
EOF

iptables-restore < "$RULES_PATH"

# SNAT for EWS→Keycloak: Keycloak's default route is the Docker bridge, so replies
# would bypass the router asymmetrically. MASQUERADE makes Keycloak see connections
# from the router's enterprise-net IP, ensuring symmetric return through the router.
iptables -t nat -A POSTROUTING -s "$EWS_IP" -d "$KEYCLOAK_IP" -o "$IF_ENTERPRISE" -j MASQUERADE

echo "Zero Trust Firewall initialized with dynamic mappings."
