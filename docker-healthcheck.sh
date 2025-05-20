#!/bin/sh
# docker-healthcheck.sh for torgo service

# Exit immediately if a command exits with a non-zero status.
set -e

# Configuration for the health check
# These should match the ports the Go application listens on for common services
# The Go app reads these from ENV, so we can too if they are passed to the healthcheck.
# For simplicity here, we'll use common defaults or allow them to be overridden by ENV.
COMMON_SOCKS_PORT=${COMMON_SOCKS_PROXY_PORT:-9000} # Default to 9000 if not set
PROXY_ADDRESS="127.0.0.1:${COMMON_SOCKS_PORT}"
IP_CHECK_URL=${IP_CHECK_URL:-https://check.torproject.org/api/ip} # Default IP check URL

# Timeout for the curl command (in seconds)
CURL_TIMEOUT=10

# Attempt to make a request through the common SOCKS5 proxy
# -s: silent
# -f: fail fast (don't output HTML error pages, return error code on server error)
# --socks5-hostname: Use SOCKS5 proxy, DNS resolution happens on proxy side
# --connect-timeout: Max time for connection
# --max-time: Max total time for operation
echo "Health check: Attempting to connect to ${IP_CHECK_URL} via SOCKS5 proxy ${PROXY_ADDRESS}..."

if curl -sf --socks5-hostname "${PROXY_ADDRESS}" --connect-timeout "${CURL_TIMEOUT}" --max-time "${CURL_TIMEOUT}" "${IP_CHECK_URL}" | grep -q '"IsTor":true'; then
  echo "Health check: PASSED - Successfully connected via Tor and response indicates Tor usage."
  exit 0 # Healthy
else
  echo "Health check: FAILED - Could not connect via Tor or response did not indicate Tor usage."
  exit 1 # Unhealthy
fi
