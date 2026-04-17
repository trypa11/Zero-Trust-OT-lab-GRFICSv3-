#!/bin/bash
set -e

# Detect interfaces and create Suricata af-packet config
cat << 'EOT' > /tmp/suricata-af-packet.yaml
af-packet:
EOT

# Detect all internal interfaces (typically eth1-eth5 in this lab)
# We exclude eth0 as it is usually the management bridge
ID=1
for IFACE in $(ls /sys/class/net | grep "^eth" | grep -v "eth0"); do
    if [ -n "$IFACE" ] && [ "$IFACE" != "lo" ]; then
        # Each interface gets its own UNIQUE cluster-id to avoid kernel fanout errors
        cat << EOF >> /tmp/suricata-af-packet.yaml
  - interface: $IFACE
    cluster-id: $ID
    defrag: yes
EOF
        ID=$((ID + 1))
    fi
done

# Replace the af-packet section in suricata.yaml
sed -i '/# DYNAMIC_CONFIG_START/,$d' /etc/suricata/suricata.yaml
echo "# DYNAMIC_CONFIG_START" >> /etc/suricata/suricata.yaml
cat /tmp/suricata-af-packet.yaml >> /etc/suricata/suricata.yaml

# Initialize Zero Trust Firewall rules
/setup-firewall.sh

# Configure Wazuh Agent to monitor Suricata , Firewall JSON logs and Keycloak logs
if [ -f "/var/ossec/etc/ossec.conf" ] && ! grep -q "/var/log/suricata/eve.json" /var/ossec/etc/ossec.conf; then
cat << 'EOT' >> /var/ossec/etc/ossec.conf

<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/ulog/netfilter_log.json</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/keycloak/keycloak.log</location>
  </localfile>
</ossec_config>
EOT
fi

# Start Wazuh Agent
if [ -x "/var/ossec/bin/wazuh-control" ]; then
    /var/ossec/bin/wazuh-control start
fi

# Show interfaces (for troubleshooting)
ip -c addr
ip route show

# Keep container running and provide a shell via exec
exec "$@"
