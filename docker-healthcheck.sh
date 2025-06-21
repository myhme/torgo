#!/bin/sh
set -e

# This health check now calls the application's built-in health endpoint.
# This is more reliable as it checks if the core logic is operational and
# can find a healthy backend Tor instance.

API_PORT=${API_PORT:-8080}
HEALTH_URL="http://127.0.0.1:${API_PORT}/api/v1/healthz"
CURL_TIMEOUT=10

echo "Health check: Probing built-in health endpoint at ${HEALTH_URL}"

# Use curl to check the endpoint. --fail causes curl to exit with an error
# for HTTP status codes >= 400.
if curl --silent --fail --max-time "${CURL_TIMEOUT}" "${HEALTH_URL}"; then
    echo "Health check: PASSED."
    exit 0
else
    echo "Health check: FAILED. The /healthz endpoint reported an unhealthy status or timed out."
    exit 1
fi