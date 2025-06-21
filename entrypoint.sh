#!/bin/bash
set -e
set -o pipefail

echo "--- Torgo Entrypoint Starting ---"

# --- Function to Setup Transparent Proxy ---
setup_transparent_proxy() {
    echo "--- Enabling Transparent Proxy Mode ---"
    # Flush existing rules
    iptables -t nat -F
    
    # Create a new chain for Tor redirection
    iptables -t nat -N TOR_REDIR
    
    # --- Redirect DNS ---
    # Redirect all DNS requests (TCP/UDP port 53) to torgo's internal DNS proxy
    DNSPort=${COMMON_DNS_PROXY_PORT:-5300}
    iptables -t nat -A TOR_REDIR -p udp --dport 53 -j REDIRECT --to-ports "${DNSPort}"
    iptables -t nat -A TOR_REDIR -p tcp --dport 53 -j REDIRECT --to-ports "${DNSPort}"
    
    # --- Redirect TCP traffic ---
    # Redirect all other TCP traffic to the Privoxy HTTP proxy, which then sends it to Tor.
    # Privoxy is used because it can handle converting HTTP requests to SOCKS5.
    HTTPPort=${PRIVOXY_HTTP_PORT:-8118}
    iptables -t nat -A TOR_REDIR -p tcp --syn -j REDIRECT --to-ports "${HTTPPort}"

    # Apply the TOR_REDIR chain to all outgoing traffic from this network namespace
    # This captures traffic from containers using 'network_mode: service:torgo'
    iptables -t nat -A PREROUTING -j TOR_REDIR
    
    echo "iptables rules configured for transparent redirection."
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
echo "--- Configuring Privoxy ---"
PRIVOXY_TEMPLATE_PATH="/etc/privoxy/privoxy.conf.template"
PRIVOXY_CONFIG_FILE="/etc/privoxy/config"
cp "${PRIVOXY_TEMPLATE_PATH}" "${PRIVOXY_CONFIG_FILE}"
sed -i "s|__LOG_LEVEL__|${PRIVOXY_LOG_LEVEL:-0}|g" "${PRIVOXY_CONFIG_FILE}"
echo "Privoxy log level set to: ${PRIVOXY_LOG_LEVEL:-0}"


# --- Tor Instance Setup ---
if ! [[ "$TOR_INSTANCES" =~ ^[0-9]+$ ]] || [ "$TOR_INSTANCES" -lt 1 ]; then
    echo "Warning: Invalid TOR_INSTANCES value: '$TOR_INSTANCES'. Defaulting to 1."
    TOR_INSTANCES=1
fi
echo "--- Preparing to start $TOR_INSTANCES Tor instance(s) ---"
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

    echo "Setting up Tor instance $i..."
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
        echo "Starting Tor instance $i..."
        su-exec "${TOR_USER}" tor -f "$TORRC_FILE" &
    else
        echo "FATAL: Configuration verification failed for Tor instance $i."
        exit 1
    fi
done

echo "--- Waiting for all Tor instances to initialize... ---"
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
echo "--- All Tor instances appear ready. ---"

echo "--- Starting Privoxy in the background ---"
privoxy --no-daemon "$PRIVOXY_CONFIG_FILE" &
sleep 1

echo "--- Starting Go 'torgo' application (main process) ---"
exec /app/torgo-app