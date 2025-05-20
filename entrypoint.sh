#!/bin/bash
set -e

# --- Configuration ---
CONFIG_BASE_DIR="/data/config" # Main persistent directory

TOR_TP_DIR="$CONFIG_BASE_DIR/tor_tp"
TOR_TRANSPARENT_CONF_TEMPLATE="/app/torrc.transparent.template" # Copied from Docker build
TOR_TRANSPARENT_CONF_FINAL="$TOR_TP_DIR/torrc.transparent"
TOR_USER="nobody"
TOR_UID=$(id -u $TOR_USER || echo 65534)
TOR_TP_DATA_DIR="$TOR_TP_DIR/data"      # Persistent data for system Tor

TOR_TRANS_PORT="9040" # System Tor's transparent TCP port (listens on 127.0.0.1)
TOR_DNS_PORT="9053"   # System Tor's DNS port (listens on 127.0.0.1)

DNSMASQ_DIR="$CONFIG_BASE_DIR/dnsmasq"
DNSMASQ_CONF_PRIMARY="$DNSMASQ_DIR/dnsmasq.conf"
# The actual adblock hosts file path will be passed to torgo via a flag.
# This is the default path dnsmasq will be configured to use if torgo doesn't override it via its flag.
DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ="$DNSMASQ_DIR/adblock.hosts"

DNSMASQ_PORT="53" # dnsmasq listens on this port for the container (on 127.0.0.1)

TORGO_INSTANCES_BASE_DIR="$CONFIG_BASE_DIR/torgo_instances" # For torgo's own Tor instances
TORGO_BASE_TORRC_FILE_DEFAULT="${TORGO_BASE_TORRC_PATH_DEFAULT:-$CONFIG_BASE_DIR/torgo_base/base_torrc}"


echo "--- Initializing Configuration and Data Directories in $CONFIG_BASE_DIR ---"
mkdir -p "$TOR_TP_DIR" "$TOR_TP_DATA_DIR" \
           "$DNSMASQ_DIR" \
           "$(dirname "$DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ")" \
           "$TORGO_INSTANCES_BASE_DIR" \
           "$(dirname "$TORGO_BASE_TORRC_FILE_DEFAULT")"

# --- System-wide Tor (Transparent Proxy) Setup ---
echo "Setting up system-wide Tor transparent proxy..."
mkdir -p "$TOR_TP_DATA_DIR"
chown -R "$TOR_USER":"$TOR_USER" "$TOR_TP_DATA_DIR"
chmod 700 "$TOR_TP_DATA_DIR"

# Create final torrc.transparent from template, prepending DataDirectory.
# The User directive is omitted as su-exec handles running Tor as the correct user.
echo "DataDirectory $TOR_TP_DATA_DIR" > "$TOR_TRANSPARENT_CONF_FINAL"
cat "$TOR_TRANSPARENT_CONF_TEMPLATE" >> "$TOR_TRANSPARENT_CONF_FINAL"
chown "$TOR_USER":"$TOR_USER" "$TOR_TRANSPARENT_CONF_FINAL"
chmod 600 "$TOR_TRANSPARENT_CONF_FINAL"
echo "Created/Updated $TOR_TRANSPARENT_CONF_FINAL with DataDirectory."

echo "Verifying system Tor configuration ($TOR_TRANSPARENT_CONF_FINAL)..."
if su-exec "$TOR_USER" tor --verify-config -f "$TOR_TRANSPARENT_CONF_FINAL"; then
    echo "System Tor configuration verified successfully."
else
    echo "ERROR: System Tor configuration verification failed. Check messages above."
    echo "Contents of $TOR_TRANSPARENT_CONF_FINAL:"
    cat "$TOR_TRANSPARENT_CONF_FINAL"
    exit 1
fi

echo "Starting system-wide Tor daemon from $TOR_TRANSPARENT_CONF_FINAL..."
su-exec "$TOR_USER" tor -f "$TOR_TRANSPARENT_CONF_FINAL" &
TOR_SYS_PID=$!

echo "Waiting for system Tor to bootstrap (up to 60 seconds)..."
attempts=0; max_attempts=60; bootstrapped_tcp=false; bootstrapped_dns=false
while [ $attempts -lt $max_attempts ]; do
    # Check for listening on 127.0.0.1 for these ports
    if ! $bootstrapped_tcp && netstat -tulnp | grep -q "127.0.0.1:$TOR_TRANS_PORT.*LISTEN.*tor"; then
        echo "System Tor TransPort (127.0.0.1:$TOR_TRANS_PORT) is open."
        bootstrapped_tcp=true
    fi
    if ! $bootstrapped_dns && netstat -tulnp | grep -q "127.0.0.1:$TOR_DNS_PORT.*LISTEN.*tor"; then
        echo "System Tor DNSPort (127.0.0.1:$TOR_DNS_PORT) is open."
        bootstrapped_dns=true
    fi
    if $bootstrapped_tcp && $bootstrapped_dns; then
        echo "System Tor fully bootstrapped and ports are open."
        break
    fi
    attempts=$((attempts+1)); sleep 1
done

if ! $bootstrapped_tcp || ! $bootstrapped_dns; then
    echo "ERROR: System Tor TransPort (127.0.0.1:$TOR_TRANS_PORT) or DNSPort (127.0.0.1:$TOR_DNS_PORT) did not open after $max_attempts seconds."
    echo "--- Attempting to get Tor process status ---"; ps aux | grep tor
    echo "--- Killing potentially stuck Tor process $TOR_SYS_PID ---"
    kill $TOR_SYS_PID || echo "Tor process $TOR_SYS_PID already exited or failed to kill."
    wait $TOR_SYS_PID 2>/dev/null; exit 1
fi

# --- Dnsmasq Setup (Adblocking) ---
echo "Configuring dnsmasq..."
ACTUAL_ADBLOCK_HOSTS_FILE="$DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ"
# Logic to determine ACTUAL_ADBLOCK_HOSTS_FILE based on torgo CMD args
# This assumes torgo's -adblockHostsFile flag value is what dnsmasq should use.
temp_adblock_path_from_cmd=""
next_arg_is_adblock_path=false
for arg_cmd in "$@"; do
    if $next_arg_is_adblock_path; then
        temp_adblock_path_from_cmd="$arg_cmd"
        break
    fi
    if [[ "$arg_cmd" == "-adblockHostsFile" ]]; then
        next_arg_is_adblock_path=true
    elif [[ "$arg_cmd" == -adblockHostsFile=* ]]; then
        temp_adblock_path_from_cmd=$(echo "$arg_cmd" | cut -d'=' -f2)
        break
    fi
done
if [ -n "$temp_adblock_path_from_cmd" ]; then
    ACTUAL_ADBLOCK_HOSTS_FILE="$temp_adblock_path_from_cmd"
    echo "INFO: Adblock hosts file for dnsmasq will be: $ACTUAL_ADBLOCK_HOSTS_FILE (from torgo CMD)"
fi


cat > "$DNSMASQ_CONF_PRIMARY" <<EOF
# Listen only on loopback for requests originating from this container
listen-address=127.0.0.1
port=${DNSMASQ_PORT}
bind-interfaces

# Do not use system's resolv.conf for upstream
no-resolv

# Forward all DNS queries to system Tor's DNSPort (which is on 127.0.0.1)
server=127.0.0.1#${TOR_DNS_PORT}

# Load adblock hosts file (managed by torgo application)
addn-hosts=${ACTUAL_ADBLOCK_HOSTS_FILE}

cache-size=1000
user=nobody # Run dnsmasq as nobody
group=nobody
# log-queries # Uncomment for debugging
EOF

mkdir -p "$(dirname "$ACTUAL_ADBLOCK_HOSTS_FILE")"
touch "$ACTUAL_ADBLOCK_HOSTS_FILE"
# Ensure torgo (running as nobody) can write to the adblock hosts file and its directory
chown -R "$TOR_USER":"$TOR_USER" "$(dirname "$ACTUAL_ADBLOCK_HOSTS_FILE")"
chown "$TOR_USER":"$TOR_USER" "$ACTUAL_ADBLOCK_HOSTS_FILE"
# Dnsmasq config directory also needs to be accessible if dnsmasq user is different,
# but we set user=nobody in dnsmasq.conf, so TOR_USER ownership should be fine.
chown "$TOR_USER":"$TOR_USER" "$DNSMASQ_DIR"
chown "$TOR_USER":"$TOR_USER" "$DNSMASQ_CONF_PRIMARY"


echo "Starting dnsmasq..."
dnsmasq -k --conf-file="$DNSMASQ_CONF_PRIMARY" &
DNSMASQ_PID=$!
echo "dnsmasq started (PID: $DNSMASQ_PID), using $ACTUAL_ADBLOCK_HOSTS_FILE (managed by torgo app)."
sleep 2 # Give dnsmasq a moment

# --- IPTables Setup ---
echo "Configuring iptables for transparent proxying..."
iptables -t nat -F TOR_OUTPUT || true
iptables -t nat -X TOR_OUTPUT || true
iptables -t nat -N TOR_OUTPUT
if ! iptables -t nat -C OUTPUT -j TOR_OUTPUT > /dev/null 2>&1; then
    iptables -t nat -A OUTPUT -j TOR_OUTPUT
fi

iptables -t nat -A TOR_OUTPUT -m owner --uid-owner "$TOR_UID" -j RETURN # System Tor's own traffic
# Dnsmasq (as nobody) traffic to 127.0.0.1#9053 (Tor's DNSPort) is local, excluded by 127.0.0.0/8 rule.

iptables -t nat -A TOR_OUTPUT -d 0.0.0.0/8 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 10.0.0.0/8 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 127.0.0.0/8 -j RETURN # Allows local services
iptables -t nat -A TOR_OUTPUT -d 169.254.0.0/16 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 172.16.0.0/12 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 192.168.0.0/16 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 224.0.0.0/4 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 240.0.0.0/4 -j RETURN

# Redirect DNS traffic (UDP and TCP port 53) to our local dnsmasq instance (127.0.0.1:53)
iptables -t nat -A TOR_OUTPUT -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:"$DNSMASQ_PORT"
iptables -t nat -A TOR_OUTPUT -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:"$DNSMASQ_PORT"

# Redirect remaining TCP traffic to system Tor's TransPort (127.0.0.1:9040)
iptables -t nat -A TOR_OUTPUT -p tcp --syn -j DNAT --to-destination 127.0.0.1:"$TOR_TRANS_PORT"
echo "iptables rules applied."


# --- Execute torgo application ---
TORGO_APP_USER="$TOR_USER"
echo "Preparing to start torgo application as user $TORGO_APP_USER..."
TORGO_ARGS_FINAL=()
TORGO_INSTANCE_BASE_PATH_FLAG_SET=false
ADBLOCK_HOSTS_FILE_FLAG_SET=false # This will be set by the logic below
BASE_TORRC_FLAG_SET=false

# Process arguments passed to the entrypoint (which are the CMD from Dockerfile)
# and add defaults if not present.
PASSED_ARGS=("$@")
for (( i=0; i<${#PASSED_ARGS[@]}; i++ )); do
    arg_cmd="${PASSED_ARGS[$i]}"
    case "$arg_cmd" in
        -torgoInstanceBasePath) TORGO_INSTANCE_BASE_PATH_FLAG_SET=true; TORGO_ARGS_FINAL+=("$arg_cmd"); i=$((i+1)); TORGO_ARGS_FINAL+=("${PASSED_ARGS[$i]}");;
        -adblockHostsFile) ADBLOCK_HOSTS_FILE_FLAG_SET=true; TORGO_ARGS_FINAL+=("$arg_cmd"); i=$((i+1)); TORGO_ARGS_FINAL+=("${PASSED_ARGS[$i]}");;
        -torrc) BASE_TORRC_FLAG_SET=true; TORGO_ARGS_FINAL+=("$arg_cmd"); i=$((i+1)); TORGO_ARGS_FINAL+=("${PASSED_ARGS[$i]}");;
        *) TORGO_ARGS_FINAL+=("$arg_cmd");;
    esac
done

if [ "$TORGO_INSTANCE_BASE_PATH_FLAG_SET" = false ]; then
    TORGO_ARGS_FINAL+=("-torgoInstanceBasePath" "$TORGO_INSTANCES_BASE_DIR")
fi
# The ACTUAL_ADBLOCK_HOSTS_FILE determined earlier is what torgo should use.
if [ "$ADBLOCK_HOSTS_FILE_FLAG_SET" = false ]; then
    TORGO_ARGS_FINAL+=("-adblockHostsFile" "$ACTUAL_ADBLOCK_HOSTS_FILE")
fi
if [ "$BASE_TORRC_FLAG_SET" = false ] && [ -n "$TORGO_BASE_TORRC_FILE_DEFAULT" ]; then
    TORGO_ARGS_FINAL+=("-torrc" "$TORGO_BASE_TORRC_FILE_DEFAULT")
fi

echo "Executing: su-exec $TORGO_APP_USER:$TORGO_APP_USER /usr/local/bin/torgo ${TORGO_ARGS_FINAL[@]}"
exec su-exec "$TORGO_APP_USER":"$TORGO_APP_USER" /usr/local/bin/torgo "${TORGO_ARGS_FINAL[@]}"

cleanup_background() {
    echo "Entrypoint cleanup: Stopping background services..."
    if [ -n "$DNSMASQ_PID" ] && kill -0 "$DNSMASQ_PID" > /dev/null 2>&1; then echo "Stopping dnsmasq ($DNSMASQ_PID)"; kill $DNSMASQ_PID; fi
    if [ -n "$TOR_SYS_PID" ] && kill -0 "$TOR_SYS_PID" > /dev/null 2>&1; then echo "Stopping system Tor ($TOR_SYS_PID)"; kill $TOR_SYS_PID; fi
    echo "Entrypoint cleanup complete."
}
trap cleanup_background SIGTERM SIGINT
