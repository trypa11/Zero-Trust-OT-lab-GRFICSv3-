#!/bin/bash
set -e

# Setup VNC password if not present
mkdir -p /home/${USERNAME}/.vnc
if [ ! -f /home/${USERNAME}/.vnc/passwd ]; then
  echo "${VNC_PASSWORD}" | x11vnc -storepasswd - /home/${USERNAME}/.vnc/passwd
  chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}/.vnc
fi

# Set default gateway to the Zero-Trust Router
for i in {1..5}; do
  ip route replace 192.168.0.0/16 via 192.168.97.200 && break || sleep 2
done

# Add host entries for Pomerium services
echo "192.168.90.21 authenticate.localhost.pomerium.io nexterm.localhost.pomerium.io hmi.localhost.pomerium.io plc.localhost.pomerium.io simulation.localhost.pomerium.io router.localhost.pomerium.io" >> /etc/hosts
echo "192.168.100.20 keycloak.localhost.pomerium.io" >> /etc/hosts


# Start Wazuh Agent
/var/ossec/bin/wazuh-control start

# Setup SSH runtime directory
mkdir -p /run/sshd

exec "$@"
