#!/bin/bash
set -e

# --- Configuration ---
CONFIG_BASE_DIR="/data/config" # Main persistent directory

TOR_TP_DIR="$CONFIG_BASE_DIR/tor_tp"
TOR_TRANSPARENT_CONF_TEMPLATE="/app/torrc.transparent.template" 
TOR_TRANSPARENT_CONF_FINAL="$TOR_TP_DIR/torrc.transparent"
TOR_USER="nobody"
TOR_UID=$(id -u $TOR_USER || echo 65534) 
TOR_TP_DATA_DIR="$TOR_TP_DIR/data"      

TOR_TRANS_PORT="9040" 
TOR_DNS_PORT="9053"   

DNSMASQ_DIR="$CONFIG_BASE_DIR/dnsmasq"
DNSMASQ_CONF_PRIMARY="$DNSMASQ_DIR/dnsmasq.conf"
DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ="$DNSMASQ_DIR/adblock.hosts"

DNSMASQ_PORT="53" 

TORGO_INSTANCES_BASE_DIR="$CONFIG_BASE_DIR/torgo_instances"
TORGO_BASE_TORRC_FILE_DEFAULT="${TORGO_BASE_TORRC_PATH_DEFAULT:-$CONFIG_BASE_DIR/torgo_base/base_torrc}"

echo "--- Initializing Configuration and Data Directories in $CONFIG_BASE_DIR ---"
mkdir -p "$TOR_TP_DIR" "$TOR_TP_DATA_DIR" \
           "$DNSMASQ_DIR" \
           "$(dirname "$DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ")" \
           "$TORGO_INSTANCES_BASE_DIR" \
           "$(dirname "$TORGO_BASE_TORRC_FILE_DEFAULT")"

# --- System-wide Tor (Transparent Proxy) Setup ---
echo "Setting up system-wide Tor transparent proxy..."
# Ensure DataDirectory exists and has correct permissions for Tor user
mkdir -p "$TOR_TP_DATA_DIR"
chown -R "$TOR_USER":"$TOR_USER" "$TOR_TP_DATA_DIR"
chmod 700 "$TOR_TP_DATA_DIR" # Tor requires strict permissions (rwx------)

# Create final torrc.transparent from template, setting User and DataDirectory
# This ensures DataDirectory is correctly set *before* verify-config
echo "User $TOR_USER" > "$TOR_TRANSPARENT_CONF_FINAL"
echo "DataDirectory $TOR_TP_DATA_DIR" >> "$TOR_TRANSPARENT_CONF_FINAL"
cat "$TOR_TRANSPARENT_CONF_TEMPLATE" >> "$TOR_TRANSPARENT_CONF_FINAL"
chown "$TOR_USER":"$TOR_USER" "$TOR_TRANSPARENT_CONF_FINAL" # Tor user should be able to read its config
chmod 600 "$TOR_TRANSPARENT_CONF_FINAL"
echo "Created/Updated $TOR_TRANSPARENT_CONF_FINAL with correct DataDirectory and User."

echo "Verifying system Tor configuration ($TOR_TRANSPARENT_CONF_FINAL)..."
# Run verify-config as the user Tor will run as, to check DataDirectory permissions
# su-exec needs the user and then the command.
if su-exec "$TOR_USER" tor --verify-config -f "$TOR_TRANSPARENT_CONF_FINAL"; then
    echo "System Tor configuration verified successfully."
else
    echo "ERROR: System Tor configuration verification failed. Check messages above."
    echo "Contents of $TOR_TRANSPARENT_CONF_FINAL:"
    cat "$TOR_TRANSPARENT_CONF_FINAL"
    exit 1
fi

echo "Starting system-wide Tor daemon from $TOR_TRANSPARENT_CONF_FINAL..."
# Start Tor as the TOR_USER to ensure it can access its DataDirectory correctly from the start
# The `User nobody` in torrc will also ensure it drops privileges if started as root.
# Running directly as TOR_USER is safer.
su-exec "$TOR_USER" tor -f "$TOR_TRANSPARENT_CONF_FINAL" &
TOR_SYS_PID=$!

echo "Waiting for system Tor to bootstrap (up to 60 seconds)..."
attempts=0
max_attempts=60 # Check every second for up to 60 seconds
bootstrapped_tcp=false
bootstrapped_dns=false

while [ $attempts -lt $max_attempts ]; do
    if ! $bootstrapped_tcp && netstat -tulnp | grep -q ":$TOR_TRANS_PORT.*LISTEN.*tor"; then
        echo "System Tor TransPort ($TOR_TRANS_PORT) is open."
        bootstrapped_tcp=true
    fi
    if ! $bootstrapped_dns && netstat -tulnp | grep -q ":$TOR_DNS_PORT.*LISTEN.*tor"; then
        echo "System Tor DNSPort ($TOR_DNS_PORT) is open."
        bootstrapped_dns=true
    fi
    if $bootstrapped_tcp && $bootstrapped_dns; then
        echo "System Tor fully bootstrapped and ports are open."
        break
    fi
    attempts=$((attempts+1))
    sleep 1
done

if ! $bootstrapped_tcp || ! $bootstrapped_dns; then
    echo "ERROR: System Tor TransPort ($TOR_TRANS_PORT) or DNSPort ($TOR_DNS_PORT) did not open after $max_attempts seconds."
    echo "Recent Tor log entries (if any were output to stdout by Tor):"
    # This assumes Tor logs to stdout as configured. If not, this won't show much.
    # You might need to check /var/log/tor/log or similar if Tor logs to a file by default.
    # However, our torrc specifies "Log notice stdout".
    echo "--- Attempting to get Tor process status ---"
    ps aux | grep tor
    echo "--- Killing potentially stuck Tor process $TOR_SYS_PID ---"
    kill $TOR_SYS_PID || echo "Tor process $TOR_SYS_PID already exited or failed to kill."
    wait $TOR_SYS_PID 2>/dev/null
    exit 1
fi

# --- Dnsmasq Setup (Adblocking) ---
echo "Configuring dnsmasq..."
ACTUAL_ADBLOCK_HOSTS_FILE="$DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ"
for arg_val_cmd in "$@"; do
    if [[ "$arg_val_cmd" == -adblockHostsFile* ]]; then
        ACTUAL_ADBLOCK_HOSTS_FILE=$(echo "$arg_val_cmd" | cut -d'=' -f2)
        if [ -z "$ACTUAL_ADBLOCK_HOSTS_FILE" ] && [ "$arg_val_cmd" != "-adblockHostsFile" ]; then 
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
listen-address=127.0.0.1
port=${DNSMASQ_PORT}
bind-interfaces
no-resolv
server=127.0.0.1#${TOR_DNS_PORT}
addn-hosts=${ACTUAL_ADBLOCK_HOSTS_FILE} 
cache-size=1000
user=nobody
group=nobody
EOF

mkdir -p "$(dirname "$ACTUAL_ADBLOCK_HOSTS_FILE")"
touch "$ACTUAL_ADBLOCK_HOSTS_FILE" 
chown -R "$TOR_USER":"$TOR_USER" "$DNSMASQ_DIR" 

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
iptables -t nat -A TOR_OUTPUT -m owner --uid-owner "$TOR_UID" -j RETURN 
iptables -t nat -A TOR_OUTPUT -d 0.0.0.0/8 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 10.0.0.0/8 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 127.0.0.0/8 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 169.254.0.0/16 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 172.16.0.0/12 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 192.168.0.0/16 -j RETURN
iptables -t nat -A TOR_OUTPUT -d 224.0.0.0/4 -j RETURN  
iptables -t nat -A TOR_OUTPUT -d 240.0.0.0/4 -j RETURN  
iptables -t nat -A TOR_OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "$DNSMASQ_PORT"
iptables -t nat -A TOR_OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "$DNSMASQ_PORT"
iptables -t nat -A TOR_OUTPUT -p tcp --syn -j REDIRECT --to-ports "$TOR_TRANS_PORT"
echo "iptables rules applied."

# --- Execute torgo application ---
TORGO_APP_USER="$TOR_USER" 
echo "Preparing to start torgo application as user $TORGO_APP_USER..."
TORGO_ARGS_FINAL=()
TORGO_INSTANCE_BASE_PATH_FLAG_SET=false
ADBLOCK_HOSTS_FILE_FLAG_SET=false
BASE_TORRC_FLAG_SET=false
for arg_cmd in "$@"; do
    case "$arg_cmd" in -torgoInstanceBasePath*) TORGO_INSTANCE_BASE_PATH_FLAG_SET=true ;; -adblockHostsFile*) ADBLOCK_HOSTS_FILE_FLAG_SET=true ;; -torrc*) BASE_TORRC_FLAG_SET=true ;; esac
    TORGO_ARGS_FINAL+=("$arg_cmd")
done
if [ "$TORGO_INSTANCE_BASE_PATH_FLAG_SET" = false ]; then TORGO_ARGS_FINAL+=("-torgoInstanceBasePath" "$TORGO_INSTANCES_BASE_DIR"); fi
if [ "$ADBLOCK_HOSTS_FILE_FLAG_SET" = false ]; then TORGO_ARGS_FINAL+=("-adblockHostsFile" "$DEFAULT_ADBLOCK_HOSTS_FILE_FOR_DNSMASQ"); fi
if [ "$BASE_TORRC_FLAG_SET" = false ] && [ -n "$TORGO_BASE_TORRC_PATH_DEFAULT" ]; then TORGO_ARGS_FINAL+=("-torrc" "$TORGO_BASE_TORRC_FILE_DEFAULT"); fi

echo "Executing: su-exec $TORGO_APP_USER:$TORGO_APP_USER /usr/local/bin/torgo ${TORGO_ARGS_FINAL[@]}"
# Use exec to replace this script process with torgo.
# This means the trap below for cleanup_background might not execute if torgo handles signals itself.
# However, Docker will send SIGTERM to the main process (torgo after exec).
# The system_tor and dnsmasq will be children and should also receive signals or be cleaned by Docker.
exec su-exec "$TORGO_APP_USER":"$TORGO_APP_USER" /usr/local/bin/torgo "${TORGO_ARGS_FINAL[@]}"

# This trap is unlikely to be hit due to 'exec' above, but kept for safety.
# The main torgo application should have its own signal handling for its Tor instances.
cleanup_background() {
    echo "Entrypoint cleanup: Stopping background services..."
    if [ -n "$DNSMASQ_PID" ] && kill -0 "$DNSMASQ_PID" > /dev/null 2>&1; then echo "Stopping dnsmasq ($DNSMASQ_PID)"; kill $DNSMASQ_PID; fi
    if [ -n "$TOR_SYS_PID" ] && kill -0 "$TOR_SYS_PID" > /dev/null 2>&1; then echo "Stopping system Tor ($TOR_SYS_PID)"; kill $TOR_SYS_PID; fi
    echo "Entrypoint cleanup complete."
}
trap cleanup_background SIGTERM SIGINT

# Keep the script alive if exec wasn't used (e.g., for debugging if torgo was backgrounded)
# wait $TOR_SYS_PID $DNSMASQ_PID # This would only work if they were not backgrounded with &
# For now, relying on exec to make torgo the main process.
