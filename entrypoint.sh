#!/bin/sh
set -e

SOCKS_BASE_PORT_DEFAULT=9050
CONTROL_BASE_PORT_DEFAULT=9160
DNS_BASE_PORT_DEFAULT=9200
TOR_USER="_tor"
TOR_GROUP="_tor"
TOR_DATA_BASE_DIR="/var/lib/tor"
TOR_RUN_DIR="/var/run/tor"
TORRC_TEMPLATE="/etc/tor/torrc.template"
TORRC_DIR="/etc/tor"
PRIVOXY_CONFIG_FILE="/etc/privoxy/config"

export TOR_INSTANCES=${TOR_INSTANCES:-1}
export SOCKS_BASE_PORT_CONFIGURED=${SOCKS_BASE_PORT_CONFIGURED:-$SOCKS_BASE_PORT_DEFAULT}
export CONTROL_BASE_PORT_CONFIGURED=${CONTROL_BASE_PORT_CONFIGURED:-$CONTROL_BASE_PORT_DEFAULT}
export DNS_BASE_PORT_CONFIGURED=${DNS_BASE_PORT_CONFIGURED:-$DNS_BASE_PORT_DEFAULT}
# Other ENVs for torgo app are passed directly from docker-compose

N_INSTANCES_TO_START=$TOR_INSTANCES
if ! [[ "$N_INSTANCES_TO_START" =~ ^[0-9]+$ ]] || [ "$N_INSTANCES_TO_START" -lt 1 ]; then
    N_INSTANCES_TO_START=1
fi

echo "--- Preparing $N_INSTANCES_TO_START Tor instance(s) ---"
mkdir -p "$TOR_RUN_DIR"
chown "${TOR_USER}:${TOR_GROUP}" "$TOR_RUN_DIR"
chmod 700 "$TOR_RUN_DIR"
if [ ! -d "$TOR_DATA_BASE_DIR" ]; then mkdir -p "$TOR_DATA_BASE_DIR"; fi
if [ "$(stat -c '%U' "$TOR_DATA_BASE_DIR")" != "$TOR_USER" ]; then
    chown -R "${TOR_USER}:${TOR_GROUP}" "$TOR_DATA_BASE_DIR"
fi
chmod 700 "$TOR_DATA_BASE_DIR"

for i in $(seq 1 "$N_INSTANCES_TO_START"); do
    INSTANCE_NAME="instance${i}"
    DATA_DIR="${TOR_DATA_BASE_DIR}/${INSTANCE_NAME}"
    PID_FILE="${TOR_RUN_DIR}/tor.${INSTANCE_NAME}.pid"
    TORRC_FILE="${TORRC_DIR}/torrc.${INSTANCE_NAME}"
    CURRENT_SOCKS_PORT=$((SOCKS_BASE_PORT_CONFIGURED + i))
    CURRENT_CONTROL_PORT=$((CONTROL_BASE_PORT_CONFIGURED + i))
    CURRENT_DNS_PORT=$((DNS_BASE_PORT_CONFIGURED + i))

    echo "Setting up Tor instance $i: DataDir=$DATA_DIR, SocksPort=127.0.0.1:$CURRENT_SOCKS_PORT, ControlPort=127.0.0.1:$CURRENT_CONTROL_PORT, DNSPort=127.0.0.1:$CURRENT_DNS_PORT"
    mkdir -p "$DATA_DIR"
    chown -R "${TOR_USER}:${TOR_GROUP}" "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    sed -e "s|__DATADIR__|${DATA_DIR}|g" \
        -e "s|__SOCKSPORT__|127.0.0.1:${CURRENT_SOCKS_PORT}|g" \
        -e "s|__CONTROLPORT__|127.0.0.1:${CURRENT_CONTROL_PORT}|g" \
        -e "s|__DNSPORT__|127.0.0.1:${CURRENT_DNS_PORT}|g" \
        -e "s|__PIDFILE__|${PID_FILE}|g" \
        "$TORRC_TEMPLATE" > "$TORRC_FILE"
    echo "Verifying Tor instance $i config..."
    if su-exec "${TOR_USER}" tor -f "$TORRC_FILE" --verify-config; then
        echo "Starting Tor instance $i..."
        su-exec "${TOR_USER}" tor -f "$TORRC_FILE" &
    else
        echo "FATAL: Tor instance $i config verification failed." && cat "$TORRC_FILE" && exit 1
    fi
done

echo "--- Waiting for Tor control cookies ---"
ALL_COOKIES_READY=0; WAIT_ATTEMPTS=0; MAX_WAIT_ATTEMPTS=90
while [ "$ALL_COOKIES_READY" -eq 0 ] && [ "$WAIT_ATTEMPTS" -lt "$MAX_WAIT_ATTEMPTS" ]; do
    ALL_COOKIES_READY=1
    for i in $(seq 1 "$N_INSTANCES_TO_START"); do
        if [ ! -f "${TOR_DATA_BASE_DIR}/instance${i}/control_auth_cookie" ]; then
            ALL_COOKIES_READY=0; break
        fi
    done
    if [ "$ALL_COOKIES_READY" -eq 0 ]; then
        sleep 1; WAIT_ATTEMPTS=$((WAIT_ATTEMPTS + 1))
        if [ $((WAIT_ATTEMPTS % 10)) -eq 0 ]; then echo "Still waiting for Tor cookies... ($WAIT_ATTEMPTS/$MAX_WAIT_ATTEMPTS)"; fi
    fi
done
if [ "$ALL_COOKIES_READY" -eq 0 ]; then echo "FATAL: Not all Tor cookies found." && exit 1; fi
echo "--- All Tor cookies found. ---"

echo "--- Starting Privoxy ---"
privoxy --no-daemon "$PRIVOXY_CONFIG_FILE" &
echo "Privoxy started. Config: $PRIVOXY_CONFIG_FILE"
sleep 1 # Brief pause for Privoxy

echo "--- Starting Go 'torgo' application ---"
exec /app/torgo-app
