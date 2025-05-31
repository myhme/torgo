#!/bin/bash
# Entrypoint script for torgo: Starts Tor instances, Privoxy, and the torgo Go application.
# Uses bash for easier scripting.

set -e # Exit immediately if a command exits with a non-zero status.
set -o pipefail # Causes pipelines to fail if any command fails

echo "--- Torgo Entrypoint Starting ---"

# --- Configuration Defaults ---
SOCKS_BASE_PORT_DEFAULT=9050
CONTROL_BASE_PORT_DEFAULT=9160
DNS_BASE_PORT_DEFAULT=9200 # For individual Tor instance's DNSPort

TOR_USER="_tor"
TOR_GROUP="_tor"
TOR_DATA_BASE_DIR="/var/lib/tor"
TOR_RUN_DIR="/var/run/tor"
TORRC_TEMPLATE="/etc/tor/torrc.template"
TORRC_DIR="/etc/tor"

PRIVOXY_CONFIG_FILE="/etc/privoxy/config"

# --- Environment Variable Processing for Torgo App & Tor Setup ---
# These are primarily for the Go application, read via os.Getenv.
# Defaults are set in config.LoadConfig() in Go if not provided here.
# Exporting them makes them available to the Go app.
export TOR_INSTANCES=${TOR_INSTANCES:-1}
export SOCKS_BASE_PORT_CONFIGURED=${SOCKS_BASE_PORT_CONFIGURED:-$SOCKS_BASE_PORT_DEFAULT}
export CONTROL_BASE_PORT_CONFIGURED=${CONTROL_BASE_PORT_CONFIGURED:-$CONTROL_BASE_PORT_DEFAULT}
export DNS_BASE_PORT_CONFIGURED=${DNS_BASE_PORT_CONFIGURED:-$DNS_BASE_PORT_DEFAULT}
# Common ports for torgo's proxies and API (Go app will use defaults if not set)
export COMMON_SOCKS_PROXY_PORT=${COMMON_SOCKS_PROXY_PORT}
export COMMON_DNS_PROXY_PORT=${COMMON_DNS_PROXY_PORT}
export API_PORT=${API_PORT}
# Other operational parameters for torgo (Go app will use defaults if not set)
export ROTATION_STAGGER_DELAY_SECONDS=${ROTATION_STAGGER_DELAY_SECONDS}
export HEALTH_CHECK_INTERVAL_SECONDS=${HEALTH_CHECK_INTERVAL_SECONDS}
# ... and so on for all ENVs read by config.LoadConfig()

# --- Tor Instance Setup ---
N_INSTANCES_TO_START=$TOR_INSTANCES # Use the value that will be passed to Go app
if ! [[ "$N_INSTANCES_TO_START" =~ ^[0-9]+$ ]] || [ "$N_INSTANCES_TO_START" -lt 1 ]; then
    echo "Warning: Invalid TOR_INSTANCES value: '$N_INSTANCES_TO_START'. Defaulting to 1 for Tor setup."
    N_INSTANCES_TO_START=1
fi

echo "--- Preparing to start $N_INSTANCES_TO_START Tor instance(s) ---"
echo "SOCKS Base Port: $SOCKS_BASE_PORT_CONFIGURED"
echo "Control Base Port: $CONTROL_BASE_PORT_CONFIGURED"
echo "Tor Instance DNS Base Port: $DNS_BASE_PORT_CONFIGURED"

# Ensure _tor user and group exist (apk add tor should create them)
if ! getent group _tor > /dev/null; then echo "Creating group _tor"; addgroup -S _tor; fi
if ! getent passwd _tor > /dev/null; then echo "Creating user _tor"; adduser -S -G _tor -h /var/lib/tor -s /sbin/nologin _tor; fi

# Ensure Tor run directory exists and has correct permissions
mkdir -p "$TOR_RUN_DIR"
chown "${TOR_USER}:${TOR_GROUP}" "$TOR_RUN_DIR"
chmod 700 "$TOR_RUN_DIR"

# Ensure Tor base data directory exists and has correct permissions
if [ ! -d "$TOR_DATA_BASE_DIR" ]; then
    mkdir -p "$TOR_DATA_BASE_DIR"
fi
# Ensure _tor owns the base data directory.
# This is important if the volume was mounted from host with different ownership.
if [ "$(stat -c '%U' "$TOR_DATA_BASE_DIR")" != "$TOR_USER" ]; then
    echo "Setting ownership of $TOR_DATA_BASE_DIR to $TOR_USER:$TOR_GROUP"
    chown -R "${TOR_USER}:${TOR_GROUP}" "$TOR_DATA_BASE_DIR"
fi
chmod 700 "$TOR_DATA_BASE_DIR"

# Loop to configure and start each Tor instance
for i in $(seq 1 "$N_INSTANCES_TO_START"); do
    INSTANCE_NAME="instance${i}"
    DATA_DIR="${TOR_DATA_BASE_DIR}/${INSTANCE_NAME}"
    PID_FILE="${TOR_RUN_DIR}/tor.${INSTANCE_NAME}.pid"
    TORRC_FILE="${TORRC_DIR}/torrc.${INSTANCE_NAME}"

    CURRENT_SOCKS_PORT=$((SOCKS_BASE_PORT_CONFIGURED + i))
    CURRENT_CONTROL_PORT=$((CONTROL_BASE_PORT_CONFIGURED + i))
    CURRENT_DNS_PORT=$((DNS_BASE_PORT_CONFIGURED + i))

    echo "Setting up Tor instance $i:"
    echo "  DataDir: $DATA_DIR"
    echo "  SocksPort: 127.0.0.1:$CURRENT_SOCKS_PORT"
    echo "  ControlPort: 127.0.0.1:$CURRENT_CONTROL_PORT"
    echo "  DNSPort: 127.0.0.1:$CURRENT_DNS_PORT"
    echo "  Torrc: $TORRC_FILE"
    # PID_FILE is specified in torrc, Tor will manage it.

    mkdir -p "$DATA_DIR"
    # Tor itself will create files in DataDir as _tor user.
    # We ensure the parent DataDir ($DATA_DIR) is owned by _tor.
    chown -R "${TOR_USER}:${TOR_GROUP}" "$DATA_DIR"
    chmod 700 "$DATA_DIR"

    sed -e "s|__DATADIR__|${DATA_DIR}|g" \
        -e "s|__SOCKSPORT__|127.0.0.1:${CURRENT_SOCKS_PORT}|g" \
        -e "s|__CONTROLPORT__|127.0.0.1:${CURRENT_CONTROL_PORT}|g" \
        -e "s|__DNSPORT__|127.0.0.1:${CURRENT_DNS_PORT}|g" \
        -e "s|__PIDFILE__|${PID_FILE}|g" \
        "${TORRC_TEMPLATE}" > "${TORRC_FILE}"
    chmod 644 "${TORRC_FILE}" # Readable by _tor, owned by root (as script runs as root)

    echo "Verifying config for Tor instance $i (using: $TORRC_FILE)..."
    # Run verification as _tor user
    if su-exec "${TOR_USER}" tor -f "$TORRC_FILE" --verify-config; then
        echo "Starting Tor instance $i (using: $TORRC_FILE)..."
        # Start Tor as the _tor user, in the background
        su-exec "${TOR_USER}" tor -f "$TORRC_FILE" &
    else
        echo "FATAL: Configuration verification failed for Tor instance $i."
        echo "Contents of $TORRC_FILE:"
        cat "$TORRC_FILE"
        exit 1 # Exit if any Tor instance fails to configure
    fi
done

echo "--- Waiting for all Tor instances to initialize control cookies ---"
ALL_COOKIES_READY=0
WAIT_ATTEMPTS=0
MAX_WAIT_ATTEMPTS=120 # Increased wait time

while [ "${ALL_COOKIES_READY}" -eq 0 ] && [ "${WAIT_ATTEMPTS}" -lt "${MAX_WAIT_ATTEMPTS}" ]; do
    ALL_COOKIES_READY=1
    for i in $(seq 1 "$N_INSTANCES_TO_START"); do
        COOKIE_PATH="${TOR_DATA_BASE_DIR}/instance${i}/control_auth_cookie"
        if [ ! -f "${COOKIE_PATH}" ]; then
            ALL_COOKIES_READY=0
            break
        fi
    done
    if [ "${ALL_COOKIES_READY}" -eq 0 ]; then
        sleep 1
        WAIT_ATTEMPTS=$((WAIT_ATTEMPTS + 1))
        if [ $((WAIT_ATTEMPTS % 10)) -eq 0 ]; then
             echo "Still waiting for Tor control cookies... (Attempt ${WAIT_ATTEMPTS}/${MAX_WAIT_ATTEMPTS})"
        fi
    fi
done

if [ "${ALL_COOKIES_READY}" -eq 0 ]; then
    echo "FATAL: Not all Tor control cookies were found after ${MAX_WAIT_ATTEMPTS} seconds."
    for i in $(seq 1 "$N_INSTANCES_TO_START"); do
        COOKIE_PATH="${TOR_DATA_BASE_DIR}/instance${i}/control_auth_cookie"
        if [ ! -f "$COOKIE_PATH" ]; then
            echo "Missing cookie for instance $i: $COOKIE_PATH"
        fi
    done
    ps aux | grep tor # Show running tor processes for debugging
    exit 1
fi
echo "--- All Tor control cookies found. Tor instances should be running. ---"

# --- Start Privoxy ---
echo "--- Starting Privoxy in the background ---"
# Privoxy will run as root by default if not specified otherwise in its config or here.
# The --no-daemon flag keeps it in the foreground relative to its own process management,
# but we background it here with '&'. Tini will manage it.
privoxy --no-daemon "$PRIVOXY_CONFIG_FILE" &
PRIVOXY_PID=$!
echo "Privoxy started with PID $PRIVOXY_PID. Config: $PRIVOXY_CONFIG_FILE"
sleep 1 # Brief pause for Privoxy to bind port

# --- Start Torgo Go Application ---
echo "--- Starting Go 'torgo' application (main process) ---"
# Use exec to replace the shell process with the Go app.
# Tini (as PID 1) will then directly manage torgo-app.
exec /app/torgo-app

# If torgo-app exits, Tini will ensure other direct children (like the shell that launched background jobs)
# are handled, and then Tini itself will exit, causing the container to stop.
# Backgrounded Tor and Privoxy processes will receive signals from Tini upon container stop.
