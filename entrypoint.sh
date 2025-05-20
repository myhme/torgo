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

TOR_TRANS_PORT="9040" # System Tor's transparent TCP port
TOR_DNS_PORT="9053"   # System Tor's DNS port

DNSMASQ_DIR="$CONFIG_BASE_DIR/dnsmasq"
DNSMASQ_CONF_PRIMARY="$DNSMASQ_DIR/dnsmasq.conf"
# The actual adblock hosts file path will be passed to torgo via a flag,
# and torgo will write to it. dnsmasq needs to be configured to read from that same path.
# We'll use a default here that torgo also defaults to if no flag is given.
DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ="$DNSMASQ_DIR/adblock.hosts"

DNSMASQ_PORT="53" # dnsmasq listens on this port for the container

# torgo application's base directory for its own Tor instances
TORGO_INSTANCES_BASE_DIR="$CONFIG_BASE_DIR/torgo_instances"
# torgo application's base torrc file (if user provides one)
TORGO_BASE_TORRC_FILE_DEFAULT="${TORGO_BASE_TORRC_PATH_DEFAULT:-$CONFIG_BASE_DIR/torgo_base/base_torrc}"


echo "--- Initializing Configuration and Data Directories in $CONFIG_BASE_DIR ---"
mkdir -p "$TOR_TP_DIR" "$TOR_TP_DATA_DIR" \
           "$DNSMASQ_DIR" \
           "$TORGO_INSTANCES_BASE_DIR" \
           "$(dirname "$DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ")" \
           "$(dirname "$TORGO_BASE_TORRC_FILE_DEFAULT")"


# --- System-wide Tor (Transparent Proxy) Setup ---
echo "Setting up system-wide Tor transparent proxy..."
# Create final torrc.transparent from template, ensuring User and DataDirectory are set
if [ ! -f "$TOR_TRANSPARENT_CONF_FINAL" ] || \
   ! grep -q "User $TOR_USER" "$TOR_TRANSPARENT_CONF_FINAL" || \
   ! grep -q "DataDirectory $TOR_TP_DATA_DIR" "$TOR_TRANSPARENT_CONF_FINAL"; then
    echo "User $TOR_USER" > "$TOR_TRANSPARENT_CONF_FINAL" # Tor will run as this user
    echo "DataDirectory $TOR_TP_DATA_DIR" >> "$TOR_TRANSPARENT_CONF_FINAL"
    cat "$TOR_TRANSPARENT_CONF_TEMPLATE" >> "$TOR_TRANSPARENT_CONF_FINAL"
    echo "Created/Updated $TOR_TRANSPARENT_CONF_FINAL"
fi
# Tor daemon needs to own its DataDirectory and config file directory
chown -R "$TOR_USER":"$TOR_USER" "$TOR_TP_DIR"
chmod 700 "$TOR_TP_DATA_DIR" # Tor requires strict permissions for DataDirectory

echo "Starting system-wide Tor daemon from $TOR_TRANSPARENT_CONF_FINAL..."
tor -f "$TOR_TRANSPARENT_CONF_FINAL" &
TOR_SYS_PID=$!
echo "Waiting for system Tor to bootstrap (approx 30-45 seconds)..."
sleep 35 # Allow more time, especially on first run or resource-constrained systems

# Basic check if Tor's ports are listening
if ! netstat -tulnp | grep -q ":$TOR_TRANS_PORT.*LISTEN.*tor" || \
   ! netstat -tulnp | grep -q ":$TOR_DNS_PORT.*LISTEN.*tor"; then
    echo "ERROR: System Tor TransPort ($TOR_TRANS_PORT) or DNSPort ($TOR_DNS_PORT) did not open. Check Tor logs."
    # Consider tailing Tor's log here for more info if it fails
    exit 1
fi
echo "System Tor TransPort and DNSPort appear to be open."


# --- Dnsmasq Setup (Adblocking) ---
echo "Configuring dnsmasq..."
# The -adblockHostsFile flag passed to torgo will determine the actual file path.
# This entrypoint configures dnsmasq to use the default path.
# Ensure torgo's default for -adblockHostsFile matches this.
ACTUAL_ADBLOCK_HOSTS_FILE="$DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ"
# Check if -adblockHostsFile is in torgo's CMD args to override default
for arg_val_cmd in "$@"; do
    if [[ "$arg_val_cmd" == -adblockHostsFile* ]]; then
        ACTUAL_ADBLOCK_HOSTS_FILE=$(echo "$arg_val_cmd" | cut -d'=' -f2)
        if [ -z "$ACTUAL_ADBLOCK_HOSTS_FILE" ] && [ "$arg_val_cmd" != "-adblockHostsFile" ]; then # for -flag value
             # find next argument if -flag value format
             next_arg_is_value=false
             for next_arg_val_cmd in "$@"; do
                if $next_arg_is_value ; then ACTUAL_ADBLOCK_HOSTS_FILE="$next_arg_val_cmd"; break; fi
                if [ "$next_arg_val_cmd" == "$arg_val_cmd" ]; then next_arg_is_value=true; fi
             done
        fi
        echo "INFO: Adblock hosts file for dnsmasq will be: $ACTUAL_ADBLOCK_HOSTS_FILE (from torgo CMD)"
        break 
    fi
done


cat > "$DNSMASQ_CONF_PRIMARY" <<EOF
# Listen on loopback and the DNS port for the container
listen-address=127.0.0.1
port=${DNSMASQ_PORT}
bind-interfaces # Important for listen-address

# Do not use system's resolv.conf for upstream
no-resolv

# Forward all DNS queries to system Tor's DNSPort
server=127.0.0.1#${TOR_DNS_PORT}

# Load adblock hosts file (managed by torgo application)
addn-hosts=${ACTUAL_ADBLOCK_HOSTS_FILE}

# Other settings
cache-size=1000
user=nobody # Run dnsmasq as nobody
group=nobody
# log-queries # Uncomment for debugging
# log-facility=/var/log/dnsmasq.log # Ensure path is writable
EOF

# Ensure adblock hosts file directory exists and file can be created by torgo (as nobody)
mkdir -p "$(dirname "$ACTUAL_ADBLOCK_HOSTS_FILE")"
touch "$ACTUAL_ADBLOCK_HOSTS_FILE" 
chown -R "$TOR_USER":"$TOR_USER" "$DNSMASQ_DIR" # For dnsmasq logs and for torgo to write adblock.hosts

echo "Starting dnsmasq..."
dnsmasq -k --conf-file="$DNSMASQ_CONF_PRIMARY" &
DNSMASQ_PID=$!
echo "dnsmasq started (PID: $DNSMASQ_PID), using $ACTUAL_ADBLOCK_HOSTS_FILE (managed by torgo app)."
sleep 5


# --- IPTables Setup ---
echo "Configuring iptables for transparent proxying..."
# Flush and delete TOR_OUTPUT chain if it exists to ensure clean setup
iptables -t nat -F TOR_OUTPUT || true
iptables -t nat -X TOR_OUTPUT || true
iptables -t nat -N TOR_OUTPUT

# Ensure OUTPUT chain jumps to TOR_OUTPUT, but only add the rule if it doesn't exist
if ! iptables -t nat -C OUTPUT -j TOR_OUTPUT > /dev/null 2>&1; then
    iptables -t nat -A OUTPUT -j TOR_OUTPUT
fi

# --- Rules for TOR_OUTPUT chain ---
# 1. Do not redirect Tor daemon's own traffic
iptables -t nat -A TOR_OUTPUT -m owner --uid-owner "$TOR_UID" -j RETURN

# 2. Do not redirect traffic from dnsmasq (usually runs as root or dnsmasq user, then drops to nobody)
#    Its traffic to 127.0.0.1#9053 (Tor's DNSPort) is local and should be allowed.
#    The general localnet exclusion below should cover this.

# 3. Do not redirect local and private network traffic
iptables -t nat -A TOR_OUTPUT -d 0.0.0.0/8 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 10.0.0.0/8 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 127.0.0.0/8 -j RETURN 
iptables -t nat -A TOR_OUTPUT -d 169.254.0.0/16 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 172.16.0.0/12 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 192.168.0.0/16 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 224.0.0.0/4 -j RETURN  # Multicast
iptables -t nat -A TOR_OUTPUT -d 240.0.0.0/4 -j RETURN  # Reserved

# 4. Redirect DNS traffic (UDP and TCP port 53) to our local dnsmasq instance
#    This applies to processes NOT running as TOR_USER and NOT destined for local/private nets.
iptables -t nat -A TOR_OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "$DNSMASQ_PORT"
iptables -t nat -A TOR_OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "$DNSMASQ_PORT"

# 5. Redirect remaining TCP traffic to system Tor's TransPort
iptables -t nat -A TOR_OUTPUT -p tcp --syn -j REDIRECT --to-ports "$TOR_TRANS_PORT"
echo "iptables rules applied."


# --- Execute torgo application ---
TORGO_APP_USER="$TOR_USER" # Run torgo as nobody
echo "Preparing to start torgo application as user $TORGO_APP_USER..."

# Prepare arguments for torgo, ensuring persistent paths are used
TORGO_ARGS_FINAL=()
TORGO_INSTANCE_BASE_PATH_FLAG_SET=false
ADBLOCK_HOSTS_FILE_FLAG_SET=false
BASE_TORRC_FLAG_SET=false

for arg_cmd in "$@"; do
    case "$arg_cmd" in
        -torgoInstanceBasePath*) TORGO_INSTANCE_BASE_PATH_FLAG_SET=true ;;
        -adblockHostsFile*) ADBLOCK_HOSTS_FILE_FLAG_SET=true ;;
        -torrc*) BASE_TORRC_FLAG_SET=true ;; # For torgo's base torrc
    esac
    TORGO_ARGS_FINAL+=("$arg_cmd")
done

if [ "$TORGO_INSTANCE_BASE_PATH_FLAG_SET" = false ]; then
    TORGO_ARGS_FINAL+=("-torgoInstanceBasePath" "$TORGO_INSTANCES_BASE_DIR")
fi
if [ "$ADBLOCK_HOSTS_FILE_FLAG_SET" = false ]; then
    TORGO_ARGS_FINAL+=("-adblockHostsFile" "$DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ")
fi
if [ "$BASE_TORRC_FLAG_SET" = false ] && [ -n "$TORGO_BASE_TORRC_PATH_DEFAULT" ]; then
    # Only add default if TORGO_BASE_TORRC_PATH_DEFAULT is set and not empty
    # And if user hasn't already provided -torrc in docker run CMD
    TORGO_ARGS_FINAL+=("-torrc" "$TORGO_BASE_TORRC_FILE_DEFAULT")
fi

echo "Executing: su-exec $TORGO_APP_USER:$TORGO_APP_USER /usr/local/bin/torgo ${TORGO_ARGS_FINAL[@]}"
# Use exec to replace this script process with torgo
exec su-exec "$TORGO_APP_USER":"$TORGO_APP_USER" /usr/local/bin/torgo "${TORGO_ARGS_FINAL[@]}"


# Cleanup function for background processes if torgo exits or script is signaled
# This trap might not be reached if exec is used above.
# The main torgo app should handle its own Tor instances cleanup on SIGTERM/SIGINT.
# The system Tor and dnsmasq will be killed when the container stops.
cleanup_background() {
    echo "Entrypoint cleanup: Stopping background services..."
    if [ -n "$DNSMASQ_PID" ] && kill -0 "$DNSMASQ_PID" > /dev/null 2>&1; then kill $DNSMASQ_PID; fi
    if [ -n "$TOR_SYS_PID" ] && kill -0 "$TOR_SYS_PID" > /dev/null 2>&1; then kill $TOR_SYS_PID; fi
    echo "Entrypoint cleanup complete."
}
trap cleanup_background SIGTERM SIGINT
