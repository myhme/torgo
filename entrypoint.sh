#!/bin/sh
set -e 

# Default Tor base ports if not configured by environment variables
SOCKS_BASE_PORT_DEFAULT=9050
CONTROL_BASE_PORT_DEFAULT=9160
DNS_BASE_PORT_DEFAULT=9200 # Tor's DNSPort

# Tor user and group, data and run directories
TOR_USER="_tor" 
TOR_GROUP="_tor"
TOR_DATA_BASE_DIR="/var/lib/tor" 
TOR_RUN_DIR="/var/run/tor"       
TORRC_TEMPLATE="/etc/tor/torrc.template" # Path to the torrc template
TORRC_DIR="/etc/tor" # Directory to store generated torrc files

# Create tor user and group if they don't exist (common in minimal Docker images)
if ! getent group "$TOR_GROUP" >/dev/null 2>&1; then
    echo "Group $TOR_GROUP does not exist. Creating..."
    addgroup -S "$TOR_GROUP"
else
    echo "Group $TOR_GROUP already exists."
fi

if ! getent passwd "$TOR_USER" >/dev/null 2>&1; then
    echo "User $TOR_USER does not exist. Creating..."
    # -D: Don't assign password, -H: Don't create home dir (we manage DataDir)
    adduser -S -G "$TOR_GROUP" -h "$TOR_DATA_BASE_DIR" -s /sbin/nologin "$TOR_USER"
else
    echo "User $TOR_USER already exists."
fi

# Number of Tor instances to run, defaults to 1 if not set or invalid
N_INSTANCES=${TOR_INSTANCES:-1}
if ! [[ "$N_INSTANCES" =~ ^[0-9]+$ ]] || [ "$N_INSTANCES" -lt 1 ]; then
    echo "Warning: Invalid TOR_INSTANCES value: '$N_INSTANCES'. Defaulting to 1."
    N_INSTANCES=1
fi
export TOR_INSTANCES_CONFIGURED="$N_INSTANCES" # Pass to Go app

# Determine base ports for Tor instances, using configured or default values
SOCKS_BASE_PORT=${SOCKS_BASE_PORT_CONFIGURED:-$SOCKS_BASE_PORT_DEFAULT}
CONTROL_BASE_PORT=${CONTROL_BASE_PORT_CONFIGURED:-$CONTROL_BASE_PORT_DEFAULT}
DNS_BASE_PORT=${DNS_BASE_PORT_CONFIGURED:-$DNS_BASE_PORT_DEFAULT}
export SOCKS_BASE_PORT_CONFIGURED="$SOCKS_BASE_PORT"    # Pass to Go app
export CONTROL_BASE_PORT_CONFIGURED="$CONTROL_BASE_PORT" # Pass to Go app
export DNS_BASE_PORT_CONFIGURED="$DNS_BASE_PORT"      # Pass to Go app


echo "Starting $N_INSTANCES Tor instance(s)..."
echo "Using SOCKS Base: $SOCKS_BASE_PORT, Control Base: $CONTROL_BASE_PORT, DNS Base: $DNS_BASE_PORT"

# Prepare Tor run directory
mkdir -p "$TOR_RUN_DIR"
echo "Setting ownership of $TOR_RUN_DIR to $TOR_USER:$TOR_GROUP"
chown "${TOR_USER}:${TOR_GROUP}" "$TOR_RUN_DIR"
chmod 700 "$TOR_RUN_DIR"

# Prepare Tor base data directory
if [ -d "$TOR_DATA_BASE_DIR" ] && [ "$(stat -c '%U' "$TOR_DATA_BASE_DIR")" != "$TOR_USER" ]; then
    echo "Warning: $TOR_DATA_BASE_DIR is not owned by $TOR_USER. Attempting to chown."
    chown -R "${TOR_USER}:${TOR_GROUP}" "$TOR_DATA_BASE_DIR" || echo "Warning: Failed to chown $TOR_DATA_BASE_DIR."
fi
chmod 700 "$TOR_DATA_BASE_DIR" 


# Loop to configure and start each Tor instance
for i in $(seq 1 "$N_INSTANCES"); do
    INSTANCE_NAME="instance${i}"
    DATA_DIR="${TOR_DATA_BASE_DIR}/${INSTANCE_NAME}"
    PID_FILE="${TOR_RUN_DIR}/tor.${INSTANCE_NAME}.pid"
    TORRC_FILE="${TORRC_DIR}/torrc.${INSTANCE_NAME}"

    # Calculate ports for the current instance
    # Tor ports are typically base + instance_number (1-indexed)
    # However, torgo instance IDs are 1-indexed, so use 'i' directly
    CURRENT_SOCKS_PORT=$((SOCKS_BASE_PORT + i))
    CURRENT_CONTROL_PORT=$((CONTROL_BASE_PORT + i))
    CURRENT_DNS_PORT=$((DNS_BASE_PORT + i))

    echo "Setting up Tor instance $i:"
    echo "  DataDir: $DATA_DIR"
    echo "  SocksPort: 0.0.0.0:$CURRENT_SOCKS_PORT" # Listen on localhost only
    echo "  ControlPort: 0.0.0.1:$CURRENT_CONTROL_PORT" # Listen on localhost only
    echo "  DNSPort: 0.0.0.1:$CURRENT_DNS_PORT" # Listen on localhost only
    echo "  Torrc: $TORRC_FILE"
    echo "  PID File: $PID_FILE"

    mkdir -p "$DATA_DIR"
    echo "Setting ownership of $DATA_DIR to $TOR_USER:$TOR_GROUP"
    chown -R "${TOR_USER}:${TOR_GROUP}" "$DATA_DIR"
    chmod 700 "$DATA_DIR"

    # Create torrc file from template for the current instance
    sed -e "s|__DATADIR__|${DATA_DIR}|g" \
        -e "s|__SOCKSPORT__|0.0.0.0:${CURRENT_SOCKS_PORT}|g" \
        -e "s|__CONTROLPORT__|0.0.0.1:${CURRENT_CONTROL_PORT}|g" \
        -e "s|__DNSPORT__|0.0.0.0:${CURRENT_DNS_PORT}|g" \
        -e "s|__PIDFILE__|${PID_FILE}|g" \
        "$TORRC_TEMPLATE" > "$TORRC_FILE"

    echo "Verifying config for Tor instance $i (tor -f $TORRC_FILE)..."
    # Run tor --verify-config as the tor user
    if su-exec "${TOR_USER}" tor -f "$TORRC_FILE" --verify-config; then
        echo "Starting Tor instance $i (tor -f $TORRC_FILE)..."
        # Start tor as the tor user in the background
        su-exec "${TOR_USER}" tor -f "$TORRC_FILE" &
    else
        echo "FATAL: Configuration verification failed for Tor instance $i. Check $TORRC_FILE and Tor logs."
        cat "$TORRC_FILE" # Print the generated torrc for debugging
        exit 1
    fi
done

echo "Waiting for all Tor instances to initialize and create control cookies..."
ALL_COOKIES_READY=0
WAIT_ATTEMPTS=0
MAX_WAIT_ATTEMPTS=90 # Increased wait time for slower systems or many instances

while [ "$ALL_COOKIES_READY" -eq 0 ] && [ "$WAIT_ATTEMPTS" -lt "$MAX_WAIT_ATTEMPTS" ]; do
    ALL_COOKIES_READY=1 # Assume ready until a missing cookie is found
    for i in $(seq 1 "$N_INSTANCES"); do
        COOKIE_PATH="${TOR_DATA_BASE_DIR}/instance${i}/control_auth_cookie"
        if [ ! -f "$COOKIE_PATH" ]; then
            ALL_COOKIES_READY=0 # Not ready yet
            break # No need to check further in this iteration
        fi
    done

    if [ "$ALL_COOKIES_READY" -eq 0 ]; then
        sleep 1
        WAIT_ATTEMPTS=$((WAIT_ATTEMPTS + 1))
        if [ $((WAIT_ATTEMPTS % 5)) -eq 0 ]; then # Log progress every 5 seconds
             echo "Still waiting for some Tor control cookies... ($WAIT_ATTEMPTS/$MAX_WAIT_ATTEMPTS seconds)"
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

# Ensure all relevant ENV variables are exported for the Go application
export COMMON_SOCKS_PROXY_PORT="${COMMON_SOCKS_PROXY_PORT:-9000}"
export COMMON_DNS_PROXY_PORT="${COMMON_DNS_PROXY_PORT:-5300}"
export API_PORT="${API_PORT:-8080}"
export ROTATION_STAGGER_DELAY_SECONDS="${ROTATION_STAGGER_DELAY_SECONDS:-15}"
export HEALTH_CHECK_INTERVAL_SECONDS="${HEALTH_CHECK_INTERVAL_SECONDS:-45}"
export IP_CHECK_URL="${IP_CHECK_URL:-https://check.torproject.org/api/ip}"
export SOCKS_TIMEOUT_SECONDS="${SOCKS_TIMEOUT_SECONDS:-15}"
export LOAD_BALANCING_STRATEGY="${LOAD_BALANCING_STRATEGY:-random}"

# Circuit Manager ENVs
export CIRCUIT_MANAGER_ENABLED="${CIRCUIT_MANAGER_ENABLED:-true}"
export CIRCUIT_MAX_AGE_SECONDS="${CIRCUIT_MAX_AGE_SECONDS:-3600}"
export CIRCUIT_ROTATION_STAGGER_SECONDS="${CIRCUIT_ROTATION_STAGGER_SECONDS:-30}"
export IP_DIVERSITY_ENABLED="${IP_DIVERSITY_ENABLED:-true}"
export IP_DIVERSITY_MIN_INSTANCES="${IP_DIVERSITY_MIN_INSTANCES:-2}"
export IP_DIVERSITY_SUBNET_CHECK_INTERVAL_SECONDS="${IP_DIVERSITY_SUBNET_CHECK_INTERVAL_SECONDS:-300}"
export IP_DIVERSITY_ROTATION_COOLDOWN_SECONDS="${IP_DIVERSITY_ROTATION_COOLDOWN_SECONDS:-900}"

# Performance Tester ENVs
export PERF_TEST_ENABLED="${PERF_TEST_ENABLED:-true}"
export PERF_TEST_INTERVAL_SECONDS="${PERF_TEST_INTERVAL_SECONDS:-300}"
# LATENCY_TARGET_GOOGLE_URL, LATENCY_TARGET_CLOUDFLARE_URL, SPEED_TEST_TARGET_URL, SPEED_TEST_TARGET_BYTES
# are already exported if set in the environment. If not, Go app uses defaults.

# Execute the Go application
/app/torgo-app
