#!/bin/sh
set -e # Exit immediately if a command exits with a non-zero status.

# Base ports for backend Tor instances
SOCKS_BASE_PORT_DEFAULT=9050
CONTROL_BASE_PORT_DEFAULT=9160
DNS_BASE_PORT_DEFAULT=9200

TOR_USER="_tor"
TOR_DATA_BASE_DIR="/var/lib/tor"
TOR_RUN_DIR="/var/run/tor" # For PID files
TORRC_TEMPLATE="/etc/tor/torrc.template"
TORRC_DIR="/etc/tor"

# Read number of instances, default to 1 if not set or invalid
N_INSTANCES=${TOR_INSTANCES:-1}
if ! [[ "$N_INSTANCES" =~ ^[0-9]+$ ]] || [ "$N_INSTANCES" -lt 1 ]; then
    echo "Warning: Invalid TOR_INSTANCES value: '$N_INSTANCES'. Defaulting to 1."
    N_INSTANCES=1
fi
export TOR_INSTANCES_CONFIGURED="$N_INSTANCES"

# Read base ports from ENV or use defaults
SOCKS_BASE_PORT=${SOCKS_BASE_PORT_CONFIGURED:-$SOCKS_BASE_PORT_DEFAULT}
CONTROL_BASE_PORT=${CONTROL_BASE_PORT_CONFIGURED:-$CONTROL_BASE_PORT_DEFAULT}
DNS_BASE_PORT=${DNS_BASE_PORT_CONFIGURED:-$DNS_BASE_PORT_DEFAULT}
export SOCKS_BASE_PORT_CONFIGURED="$SOCKS_BASE_PORT"
export CONTROL_BASE_PORT_CONFIGURED="$CONTROL_BASE_PORT"
export DNS_BASE_PORT_CONFIGURED="$DNS_BASE_PORT"


echo "Starting $N_INSTANCES Tor instance(s)..."
echo "Using SOCKS Base: $SOCKS_BASE_PORT, Control Base: $CONTROL_BASE_PORT, DNS Base: $DNS_BASE_PORT"

mkdir -p "$TOR_RUN_DIR"
chown "${TOR_USER}:${TOR_USER}" "$TOR_RUN_DIR"
chmod 700 "$TOR_RUN_DIR"

for i in $(seq 1 "$N_INSTANCES"); do
    INSTANCE_NAME="instance${i}"
    DATA_DIR="${TOR_DATA_BASE_DIR}/${INSTANCE_NAME}"
    PID_FILE="${TOR_RUN_DIR}/tor.${INSTANCE_NAME}.pid"
    TORRC_FILE="${TORRC_DIR}/torrc.${INSTANCE_NAME}"

    CURRENT_SOCKS_PORT=$((SOCKS_BASE_PORT + i))
    CURRENT_CONTROL_PORT=$((CONTROL_BASE_PORT + i))
    CURRENT_DNS_PORT=$((DNS_BASE_PORT + i)) # Port 0 for DNS means disabled in torrc

    echo "Setting up Tor instance $i:"
    echo "  DataDir: $DATA_DIR"
    echo "  SocksPort: $CURRENT_SOCKS_PORT"
    echo "  ControlPort: $CURRENT_CONTROL_PORT"
    echo "  DNSPort: $CURRENT_DNS_PORT"
    echo "  Torrc: $TORRC_FILE"
    echo "  PID File: $PID_FILE"

    mkdir -p "$DATA_DIR"
    # Ensure correct ownership if directory already existed with wrong owner
    if [ "$(stat -c '%U' "$DATA_DIR")" != "$TOR_USER" ]; then
        chown -R "${TOR_USER}:${TOR_USER}" "$DATA_DIR"
    fi
    chmod 700 "$DATA_DIR"

    # Create instance-specific torrc from template
    sed -e "s|__DATADIR__|${DATA_DIR}|g" \
        -e "s|__SOCKSPORT__|${CURRENT_SOCKS_PORT}|g" \
        -e "s|__CONTROLPORT__|${CURRENT_CONTROL_PORT}|g" \
        -e "s|__DNSPORT__|${CURRENT_DNS_PORT}|g" \
        -e "s|__PIDFILE__|${PID_FILE}|g" \
        "$TORRC_TEMPLATE" > "$TORRC_FILE"

    # Start Tor instance
    echo "Verifying config for Tor instance $i (tor -f $TORRC_FILE)..."
    if su-exec "${TOR_USER}" tor -f "$TORRC_FILE" --verify-config; then
        echo "Starting Tor instance $i (tor -f $TORRC_FILE)..."
        su-exec "${TOR_USER}" tor -f "$TORRC_FILE" &
    else
        echo "FATAL: Configuration verification failed for Tor instance $i. Check $TORRC_FILE and Tor logs."
        exit 1
    fi
done

# Wait for control cookies for all instances
echo "Waiting for all Tor instances to initialize and create control cookies..."
ALL_COOKIES_READY=0
WAIT_ATTEMPTS=0
MAX_WAIT_ATTEMPTS=60 # Wait up to 60 seconds (adjust as needed)

while [ "$ALL_COOKIES_READY" -eq 0 ] && [ "$WAIT_ATTEMPTS" -lt "$MAX_WAIT_ATTEMPTS" ]; do
    ALL_COOKIES_READY=1 # Assume ready until proven otherwise
    for i in $(seq 1 "$N_INSTANCES"); do
        INSTANCE_NAME="instance${i}"
        DATA_DIR="${TOR_DATA_BASE_DIR}/${INSTANCE_NAME}"
        COOKIE_PATH="${DATA_DIR}/control_auth_cookie"
        if [ ! -f "$COOKIE_PATH" ]; then
            ALL_COOKIES_READY=0
            break # No need to check further in this iteration
        fi
    done

    if [ "$ALL_COOKIES_READY" -eq 0 ]; then
        sleep 1
        WAIT_ATTEMPTS=$((WAIT_ATTEMPTS + 1))
        if [ $((WAIT_ATTEMPTS % 5)) -eq 0 ]; then # Print status every 5s
             echo "Still waiting for some Tor control cookies... ($WAIT_ATTEMPTS/$MAX_WAIT_ATTEMPTS)"
        fi
    fi
done

if [ "$ALL_COOKIES_READY" -eq 0 ]; then
    echo "FATAL: Not all Tor control cookies were found after $MAX_WAIT_ATTEMPTS seconds."
    for i in $(seq 1 "$N_INSTANCES"); do
        COOKIE_PATH="${TOR_DATA_BASE_DIR}/instance${i}/control_auth_cookie"
        if [ ! -f "$COOKIE_PATH" ]; then
            echo "Missing cookie for instance $i: $COOKIE_PATH"
        fi
    done
    exit 1
fi

echo "All Tor control cookies found. Starting Go 'torgo' application..."

# Set common ports for the Go application to listen on
export COMMON_SOCKS_PROXY_PORT="${COMMON_SOCKS_PROXY_PORT:-9000}"
export COMMON_DNS_PROXY_PORT="${COMMON_DNS_PROXY_PORT:-5300}"
export API_PORT="${API_PORT:-8080}"

# Set other configurations for the Go app
export ROTATION_STAGGER_DELAY_SECONDS="${ROTATION_STAGGER_DELAY_SECONDS:-10}"
export HEALTH_CHECK_INTERVAL_SECONDS="${HEALTH_CHECK_INTERVAL_SECONDS:-30}"
export IP_CHECK_URL="${IP_CHECK_URL:-https://check.torproject.org/api/ip}" # Ensure this is set if not hardcoded in Go
export SOCKS_TIMEOUT_SECONDS="${SOCKS_TIMEOUT_SECONDS:-10}"


# Execute the Go application
/app/torgo-app
