#!/bin/bash
set -e

VNC_PASS="${VNC_PASSWORD:-changeme}"
VNC_PASS_FILE="/etc/x11vnc.pass"

# Always overwrite with the proper format
x11vnc -storepasswd "${VNC_PASS}" "${VNC_PASS_FILE}" >/dev/null 2>&1
chmod 600 "${VNC_PASS_FILE}"
# ensure /opt/noVNC/utils/novnc_proxy exists; otherwise use websockify
if [ ! -x /opt/noVNC/utils/novnc_proxy ]; then
  # try to install websockify script entry point
  if [ -f /opt/noVNC/utils/websockify/run ]; then
    ln -s /opt/noVNC/utils/websockify/run /opt/noVNC/utils/novnc_proxy || true
  fi
fi

# Export display and resolution (allow override)
export DISPLAY=${DISPLAY:-:1}
export RESOLUTION=${RESOLUTION:-1280x720}

# Debug info
echo "Current Network State:"
ifconfig
route -n

# Wait for network interface to be ready before adding route
for i in {1..10}; do
  INTERFACE=$(ifconfig | grep -B 1 "192.168.100" | head -n 1 | awk '{print $1}' | tr -d ':')
  if [ -n "$INTERFACE" ]; then
    echo "Found enterprise interface: $INTERFACE"
    if route add -net 192.168.0.0/16 gw 192.168.100.200 dev "$INTERFACE" 2>/dev/null; then
      echo "Successfully added route to OT network on $INTERFACE."
      break
    fi
  fi
  echo "Waiting for 192.168.100.200 reachable on enterprise interface... ($i/10)"
  sleep 2
done

# Start supervisord (the default CMD will run supervisord, but start.sh can exec it)
exec "$@"
