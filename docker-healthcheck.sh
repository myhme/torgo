#!/bin/sh
set -e

COMMON_SOCKS_PORT=${COMMON_SOCKS_PROXY_PORT:-9000}
PROXY_ADDRESS="127.0.0.1:${COMMON_SOCKS_PORT}"
IP_CHECK_URL=${IP_CHECK_URL:-https://check.torproject.org/api/ip}
CURL_CONNECT_TIMEOUT=10
CURL_MAX_TIME=15

echo "Health check: Probing ${IP_CHECK_URL} via SOCKS5 ${PROXY_ADDRESS}..."
TMP_OUTPUT=$(mktemp)
CURL_EXIT_CODE=0
set +e
curl -sf --socks5-hostname "${PROXY_ADDRESS}" \
     --connect-timeout "${CURL_CONNECT_TIMEOUT}" \
     --max-time "${CURL_MAX_TIME}" \
     "${IP_CHECK_URL}" > "${TMP_OUTPUT}"
CURL_EXIT_CODE=$?
set -e

if [ ${CURL_EXIT_CODE} -eq 0 ]; then
  if grep -q '"IsTor":true' "${TMP_OUTPUT}"; then
    echo "Health check: PASSED - Tor usage confirmed."
    rm -f "${TMP_OUTPUT}"
    exit 0
  else
    echo "Health check: FAILED - Connected, but response did not confirm Tor usage."
    cat "${TMP_OUTPUT}"
    rm -f "${TMP_OUTPUT}"
    exit 1
  fi
else
  echo "Health check: FAILED - curl exited with code ${CURL_EXIT_CODE}."
  cat "${TMP_OUTPUT}" # Show output which might contain error from curl
  rm -f "${TMP_OUTPUT}"
  exit 1
fi
