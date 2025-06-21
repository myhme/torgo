#!/bin/bash
#
# create_s6_rootfs.sh
#
# This script automatically generates the entire S6 overlay directory structure
# for the torgo project, including all necessary service files and permissions.
# Run this script from the root of the torgo project directory.

set -e

# --- Configuration ---
ROOTFS_DIR="rootfs"
BASE_DIR="${ROOTFS_DIR}/etc/s6-overlay"

# --- Main Script ---

echo "--- Generating S6 Overlay rootfs for torgo ---"

# Clean up any previous structure to ensure a fresh start
if [ -d "$ROOTFS_DIR" ]; then
    echo "Removing existing rootfs directory..."
    rm -rf "$ROOTFS_DIR"
fi

echo "Creating directory structure..."

# Create the core directories
mkdir -p "${BASE_DIR}/cont-init.d"
mkdir -p "${BASE_DIR}/s6-rc.d/user/contents.d"
mkdir -p "${BASE_DIR}/s6-rc.d/privoxy/dependencies.d"
mkdir -p "${BASE_DIR}/s6-rc.d/privoxy/log"
mkdir -p "${BASE_DIR}/s6-rc.d/torgo-app/dependencies.d"
mkdir -p "${BASE_DIR}/s6-rc.d/torgo-app/log"

# --- Create Files ---

echo "Writing S6 service files..."

# 1. Cont-init script (one-time setup)
cat > "${BASE_DIR}/cont-init.d/01-tor-setup" <<'EOF'
#!/command/with-contenv bash
# S6 Overlay Initializer Script for torgo

set -e
set -o pipefail

echo "--- S6 Init: Preparing torgo environment ---"

# --- Function to Setup Transparent Proxy ---
setup_transparent_proxy() {
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
}

# --- Environment Variable Processing ---
export TOR_INSTANCES=${TOR_INSTANCES:-1}
SOCKS_BASE_PORT_CONFIGURED=${SOCKS_BASE_PORT_CONFIGURED:-9050}
CONTROL_BASE_PORT_CONFIGURED=${CONTROL_BASE_PORT_CONFIGURED:-9160}
DNS_BASE_PORT_CONFIGURED=${DNS_BASE_PORT_CONFIGURED:-9200}
TOR_USER="_tor"
TOR_GROUP="_tor"
TOR_DATA_BASE_DIR="/var/lib/tor"
TOR_RUN_DIR="/var/run/tor"
TORRC_TEMPLATE_PATH="/etc/tor/torrc.template"
TORRC_DIR="/etc/tor"

# --- Transparent Proxy Activation ---
if [ "${TORGO_TRANSPARENT_PROXY}" = "true" ]; then
    setup_transparent_proxy
fi

# --- Privoxy Dynamic Configuration ---
echo "--- S6 Init: Configuring Privoxy ---"
PRIVOXY_TEMPLATE_PATH="/etc/privoxy/privoxy.conf.template"
PRIVOXY_CONFIG_FILE="/etc/privoxy/config"
cp "${PRIVOXY_TEMPLATE_PATH}" "${PRIVOXY_CONFIG_FILE}"
sed -i "s|__LOG_LEVEL__|${PRIVOXY_LOG_LEVEL:-0}|g" "${PRIVOXY_CONFIG_FILE}"

# --- Tor Instance Setup ---
if ! [[ "$TOR_INSTANCES" =~ ^[0-9]+$ ]] || [ "$TOR_INSTANCES" -lt 1 ]; then
    echo "Warning: Invalid TOR_INSTANCES value: '$TOR_INSTANCES'. Defaulting to 1."
    TOR_INSTANCES=1
fi
echo "--- S6 Init: Preparing to start $TOR_INSTANCES Tor instance(s) ---"

if ! getent group _tor > /dev/null; then addgroup -S _tor; fi
if ! getent passwd _tor > /dev/null; then adduser -S -G _tor -h /var/lib/tor -s /sbin/nologin _tor; fi

mkdir -p "$TOR_RUN_DIR" "$TOR_DATA_BASE_DIR"
chown -R "${TOR_USER}:${TOR_GROUP}" "$TOR_RUN_DIR" "$TOR_DATA_BASE_DIR"
chmod 700 "$TOR_RUN_DIR" "$TOR_DATA_BASE_DIR"

for i in $(seq 1 "$TOR_INSTANCES"); do
    INSTANCE_NAME="instance${i}"
    DATA_DIR="${TOR_DATA_BASE_DIR}/${INSTANCE_NAME}"
    PID_FILE="${TOR_RUN_DIR}/tor.${INSTANCE_NAME}.pid"
    TORRC_FILE="${TORRC_DIR}/torrc.${INSTANCE_NAME}"
    CURRENT_SOCKS_PORT=$((SOCKS_BASE_PORT_CONFIGURED + i))
    CURRENT_CONTROL_PORT=$((CONTROL_BASE_PORT_CONFIGURED + i))
    CURRENT_DNS_PORT=$((DNS_BASE_PORT_CONFIGURED + i))

    echo "S6 Init: Setting up Tor instance $i..."
    mkdir -p "$DATA_DIR"
    chown -R "${TOR_USER}:${TOR_GROUP}" "$DATA_DIR"
    chmod 700 "$DATA_DIR"

    EXTRA_OPTIONS=""
    if [ -n "$TOR_EXIT_NODES" ]; then
        EXTRA_OPTIONS="${EXTRA_OPTIONS}ExitNodes $TOR_EXIT_NODES\nStrictNodes 1\n"
    fi
    if [ -n "$TOR_MAX_CIRCUIT_DURTINESS" ]; then
        EXTRA_OPTIONS="${EXTRA_OPTIONS}MaxCircuitDirtiness $TOR_MAX_CIRCUIT_DURTINESS\n"
    fi
    
    TMP_TEMPLATE=$(mktemp)
    sed "s|__EXTRA_TOR_OPTIONS__|${EXTRA_OPTIONS}|g" "${TORRC_TEMPLATE_PATH}" > "${TMP_TEMPLATE}"
    
    sed -e "s|__DATADIR__|${DATA_DIR}|g" \
        -e "s|__SOCKSPORT__|127.0.0.1:${CURRENT_SOCKS_PORT}|g" \
        -e "s|__CONTROLPORT__|127.0.0.1:${CURRENT_CONTROL_PORT}|g" \
        -e "s|__DNSPORT__|127.0.0.1:${CURRENT_DNS_PORT}|g" \
        -e "s|__PIDFILE__|${PID_FILE}|g" \
        "${TMP_TEMPLATE}" > "${TORRC_FILE}"
    rm "${TMP_TEMPLATE}"
    chmod 644 "${TORRC_FILE}"

    if su-exec "${TOR_USER}" tor -f "$TORRC_FILE" --verify-config; then
        echo "S6 Init: Starting Tor instance $i in background..."
        su-exec "${TOR_USER}" tor -f "$TORRC_FILE" &
    else
        echo "FATAL: Configuration verification failed for Tor instance $i."
        exit 1
    fi
done

echo "--- S6 Init: Waiting for all Tor instances to initialize cookies... ---"
ALL_COOKIES_READY=0; WAIT_ATTEMPTS=0; MAX_WAIT_ATTEMPTS=120
while [ "${ALL_COOKIES_READY}" -eq 0 ] && [ "${WAIT_ATTEMPTS}" -lt "${MAX_WAIT_ATTEMPTS}" ]; do
    ALL_COOKIES_READY=1
    for i in $(seq 1 "$TOR_INSTANCES"); do
        if [ ! -f "${TOR_DATA_BASE_DIR}/instance${i}/control_auth_cookie" ]; then
            ALL_COOKIES_READY=0; break
        fi
    done
    if [ "${ALL_COOKIES_READY}" -eq 0 ]; then
        sleep 1; WAIT_ATTEMPTS=$((WAIT_ATTEMPTS + 1))
    fi
done

if [ "${ALL_COOKIES_READY}" -eq 0 ]; then
    echo "FATAL: Not all Tor control cookies were found after ${MAX_WAIT_ATTEMPTS} seconds."
    exit 1
fi

echo "--- S6 Init: Environment setup complete. Handing over to S6 service manager. ---"
EOF

# 2. Privoxy Service
cat > "${BASE_DIR}/s6-rc.d/privoxy/type" <<'EOF'
longrun
EOF

cat > "${BASE_DIR}/s6-rc.d/privoxy/run" <<'EOF'
#!/command/with-contenv bash
# S6 run script for the Privoxy service
echo "--- S6 Service: Starting Privoxy ---"
exec privoxy --no-daemon /etc/privoxy/config
EOF

cat > "${BASE_DIR}/s6-rc.d/privoxy/log/run" <<'EOF'
#!/command/execlineb -P
# Standard S6 logging script for the Privoxy service.
s6-log -b n20 s1000000 T /var/log/privoxy
EOF

touch "${BASE_DIR}/s6-rc.d/privoxy/dependencies.d/base"

# 3. Torgo-App Service
cat > "${BASE_DIR}/s6-rc.d/torgo-app/type" <<'EOF'
longrun
EOF

cat > "${BASE_DIR}/s6-rc.d/torgo-app/run" <<'EOF'
#!/command/with-contenv bash
# S6 run script for the main torgo Go application
echo "--- S6 Service: Starting torgo-app ---"
exec /app/torgo-app
EOF

cat > "${BASE_DIR}/s6-rc.d/torgo-app/log/run" <<'EOF'
#!/command/execlineb -P
# Standard S6 logging script for the torgo-app service.
s6-log -b n20 s1000000 T /var/log/torgo-app
EOF

touch "${BASE_DIR}/s6-rc.d/torgo-app/dependencies.d/base"

# 4. Enable services in the user bundle
touch "${BASE_DIR}/s6-rc.d/user/contents.d/privoxy"
touch "${BASE_DIR}/s6-rc.d/user/contents.d/torgo-app"


# --- Set Permissions ---
echo "Setting executable permissions..."
chmod +x "${BASE_DIR}/cont-init.d/01-tor-setup"
chmod +x "${BASE_DIR}/s6-rc.d/privoxy/run"
chmod +x "${BASE_DIR}/s6-rc.d/privoxy/log/run"
chmod +x "${BASE_DIR}/s6-rc.d/torgo-app/run"
chmod +x "${BASE_DIR}/s6-rc.d/torgo-app/log/run"


echo ""
echo "✅ S6 rootfs directory structure created successfully!"
echo "You can now build your Docker image."

