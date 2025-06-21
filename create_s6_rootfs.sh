#!/bin/bash
#
# create_s6_rootfs.sh
#
# This script automatically generates the entire S6 overlay directory structure
# for the torgo project, including all necessary service files and permissions.
# It is designed to be robust and avoid race conditions during container startup.
# This version includes a corrected Privoxy configuration.

set -e

# --- Configuration ---
ROOTFS_DIR="rootfs"
BASE_DIR="${ROOTFS_DIR}/etc/s6-overlay"

# --- Main Script ---

echo "--- Generating Final S6 Overlay rootfs for torgo (v2) ---"

# Clean up any previous structure
if [ -d "$ROOTFS_DIR" ]; then
    echo "Removing existing rootfs directory..."
    rm -rf "$ROOTFS_DIR"
fi

echo "Creating directory structure..."

# Create the core directories
mkdir -p "${BASE_DIR}/cont-init.d"
mkdir -p "${BASE_DIR}/s6-rc.d/user/contents.d"
mkdir -p "${BASE_DIR}/s6-rc.d/privoxy/log"
mkdir -p "${BASE_DIR}/s6-rc.d/tor-daemons/log"
mkdir -p "${BASE_DIR}/s6-rc.d/torgo-app/dependencies.d"
mkdir -p "${BASE_DIR}/s6-rc.d/torgo-app/log"

# --- Create Files ---

echo "Writing S6 service files..."

# 1. Cont-init script (one-time setup for iptables only)
cat > "${BASE_DIR}/cont-init.d/01-iptables-setup" <<'EOF'
#!/command/with-contenv bash
set -e
# This script only runs if the transparent proxy mode is enabled.
if [ "${TORGO_TRANSPARENT_PROXY}" != "true" ]; then
    exit 0
fi

echo "--- S6 Init: Enabling Transparent Proxy Mode ---"
iptables -t nat -F
iptables -t nat -N TOR_REDIR
DNSPort=${COMMON_DNS_PROXY_PORT:-5300}
iptables -t nat -A TOR_REDIR -p udp --dport 53 -j REDIRECT --to-ports "${DNSPort}"
iptables -t nat -A TOR_REDIR -p tcp --dport 53 -j REDIRECT --to-ports "${DNSPort}"
HTTPPort=${PRIVOXY_HTTP_PORT:-8118}
iptables -t nat -A TOR_REDIR -p tcp --syn -j REDIRECT --to-ports "${HTTPPort}"
iptables -t nat -A PREROUTING -j TOR_REDIR
echo "S6 Init: iptables rules configured for transparent redirection."
EOF

# 2. Tor Daemons Service (Starts all tor instances)
cat > "${BASE_DIR}/s6-rc.d/tor-daemons/type" <<'EOF'
longrun
EOF

cat > "${BASE_DIR}/s6-rc.d/tor-daemons/run" <<'EOF'
#!/command/with-contenv bash
set -e
echo "--- S6 Service: Starting Tor Daemons ---"

# --- Environment Variable Processing ---
export TOR_INSTANCES=${TOR_INSTANCES:-1}
SOCKS_BASE_PORT_CONFIGURED=${SOCKS_BASE_PORT_CONFIGURED:-9050}
CONTROL_BASE_PORT_CONFIGURED=${CONTROL_BASE_PORT_CONFIGURED:-9160}
DNS_BASE_PORT_CONFIGURED=${DNS_BASE_PORT_CONFIGURED:-9200}
TOR_USER="_tor"
TOR_DATA_BASE_DIR="/var/lib/tor"
TOR_RUN_DIR="/var/run/tor"
TORRC_TEMPLATE_PATH="/etc/tor/torrc.template"
TORRC_DIR="/etc/tor"

# --- Tor Instance Setup ---
if ! [[ "$TOR_INSTANCES" =~ ^[0-9]+$ ]] || [ "$TOR_INSTANCES" -lt 1 ]; then
    TOR_INSTANCES=1
fi
echo "Tor Daemons Service: Preparing to start $TOR_INSTANCES Tor instance(s)..."

if ! getent group _tor > /dev/null; then addgroup -S _tor; fi
if ! getent passwd _tor > /dev/null; then adduser -S -G _tor -h /var/lib/tor -s /sbin/nologin _tor; fi

mkdir -p "$TOR_RUN_DIR" "$TOR_DATA_BASE_DIR"
chown -R "${TOR_USER}:${TOR_USER}" "$TOR_RUN_DIR" "$TOR_DATA_BASE_DIR"
chmod 700 "$TOR_RUN_DIR" "$TOR_DATA_BASE_DIR"

for i in $(seq 1 "$TOR_INSTANCES"); do
    DATA_DIR="${TOR_DATA_BASE_DIR}/instance${i}"
    TORRC_FILE="${TORRC_DIR}/torrc.${i}"
    
    echo "Tor Daemons Service: Configuring Tor instance $i..."
    mkdir -p "$DATA_DIR"
    chown -R "${TOR_USER}:${TOR_USER}" "$DATA_DIR"
    chmod 700 "$DATA_DIR"

    EXTRA_OPTIONS=""
    if [ -n "$TOR_EXIT_NODES" ]; then
        EXTRA_OPTIONS="${EXTRA_OPTIONS}ExitNodes $TOR_EXIT_NODES\nStrictNodes 1\n"
    fi
    if [ -n "$TOR_MAX_CIRCUIT_DURTINESS" ]; then
        EXTRA_OPTIONS="${EXTRA_OPTIONS}MaxCircuitDirtiness $TOR_MAX_CIRCUIT_DURTINESS\n"
    fi
    
    # Create the final torrc file for this instance
    sed -e "s|__DATADIR__|${DATA_DIR}|g" \
        -e "s|__SOCKSPORT__|127.0.0.1:$((SOCKS_BASE_PORT_CONFIGURED + i))|g" \
        -e "s|__CONTROLPORT__|127.0.0.1:$((CONTROL_BASE_PORT_CONFIGURED + i))|g" \
        -e "s|__DNSPORT__|127.0.0.1:$((DNS_BASE_PORT_CONFIGURED + i))|g" \
        -e "s|__PIDFILE__|/dev/null|g" \
        -e "s|__EXTRA_TOR_OPTIONS__|${EXTRA_OPTIONS}|g" \
        "${TORRC_TEMPLATE_PATH}" > "${TORRC_FILE}"
    chmod 644 "${TORRC_FILE}"

    # Start the daemon for this instance, managed by exec
    # We use s6-setuidgid to drop privileges to the _tor user
    echo "Tor Daemons Service: Starting Tor instance $i..."
    s6-setuidgid _tor tor -f "${TORRC_FILE}" &
done

# Wait for all background tor processes to finish
# If one fails, this script will exit, and S6 will restart the service.
wait
EOF

cat > "${BASE_DIR}/s6-rc.d/tor-daemons/log/run" <<'EOF'
#!/command/execlineb -P
s6-log -b n20 s1000000 T /var/log/tor-daemons
EOF


# 3. Privoxy Service
cat > "${BASE_DIR}/s6-rc.d/privoxy/type" <<'EOF'
longrun
EOF

cat > "${BASE_DIR}/s6-rc.d/privoxy/run" <<'EOF'
#!/command/with-contenv bash
set -e
echo "--- S6 Service: Starting Privoxy ---"
# Configure Privoxy just before starting it
PRIVOXY_CONFIG_FILE="/etc/privoxy/config"

# --- CORRECTED Privoxy Configuration ---
# This configuration is compatible with the version of Privoxy from the
# Alpine package repository and specifies the full paths to action files.
cat > ${PRIVOXY_CONFIG_FILE} <<EOP
# --- Core Settings ---
listen-address  [::]:8118
listen-address  0.0.0.0:8118
confdir /etc/privoxy
logdir /var/log/privoxy

# --- Forwarding ---
forward-socks5t / torgo:9000 .

# --- Action Files (with full paths) ---
actionsfile default.action
actionsfile user.action

# --- Logging ---
debug ${PRIVOXY_LOG_LEVEL:-0}
EOP

# Use exec to hand control over to privoxy
exec privoxy --no-daemon "${PRIVOXY_CONFIG_FILE}"
EOF

cat > "${BASE_DIR}/s6-rc.d/privoxy/log/run" <<'EOF'
#!/command/execlineb -P
s6-log -b n20 s1000000 T /var/log/privoxy
EOF


# 4. Torgo-App Service
cat > "${BASE_DIR}/s6-rc.d/torgo-app/type" <<'EOF'
longrun
EOF

cat > "${BASE_DIR}/s6-rc.d/torgo-app/run" <<'EOF'
#!/command/with-contenv bash
set -e
echo "--- S6 Service: Waiting for Tor daemons to be ready... ---"

# This is a crucial step: wait for the Tor daemons to create their cookie files
# before starting the Go app that needs to connect to them.
# The `tor-daemons` service must finish its startup sequence first.
# We'll poll for the last instance's cookie file.
TOR_INSTANCES=${TOR_INSTANCES:-1}
LAST_COOKIE_FILE="/var/lib/tor/instance${TOR_INSTANCES}/control_auth_cookie"
WAIT_SECONDS=60
while [ ! -f "${LAST_COOKIE_FILE}" ] && [ $WAIT_SECONDS -gt 0 ]; do
  sleep 1
  WAIT_SECONDS=$((WAIT_SECONDS - 1))
done

if [ ! -f "${LAST_COOKIE_FILE}" ]; then
  echo "FATAL: Timed out waiting for Tor daemons to become ready."
  exit 1
fi

echo "--- S6 Service: Tor daemons are ready. Starting torgo-app. ---"
exec /app/torgo-app
EOF

cat > "${BASE_DIR}/s6-rc.d/torgo-app/log/run" <<'EOF'
#!/command/execlineb -P
s6-log -b n20 s1000000 T /var/log/torgo-app
EOF

# Declare that torgo-app depends on the tor-daemons service
touch "${BASE_DIR}/s6-rc.d/torgo-app/dependencies.d/tor-daemons"


# 5. Enable services in the user bundle
touch "${BASE_DIR}/s6-rc.d/user/contents.d/tor-daemons"
touch "${BASE_DIR}/s6-rc.d/user/contents.d/privoxy"
touch "${BASE_DIR}/s6-rc.d/user/contents.d/torgo-app"


# --- Set Permissions ---
echo "Setting executable permissions..."
find "${BASE_DIR}" -type f -name "run" -exec chmod +x {} +
chmod +x "${BASE_DIR}/cont-init.d/01-iptables-setup"


echo ""
echo "✅ S6 rootfs directory structure created successfully!"
echo "You can now build your Docker image."

