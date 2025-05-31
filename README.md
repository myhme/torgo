# torgo: Advanced Multi-Instance Tor Controller, SOCKS/DNS/HTTP Proxy, and Privacy Enhancer

**torgo** is a Go application designed to manage multiple backend Tor instances. It provides unified SOCKS5 and DNS proxy interfaces with load balancing, an HTTP API for fine-grained control, a Web UI for monitoring, and includes features like automatic circuit rotation, IP diversity management, and DNS caching. It also bundles Privoxy for easy HTTP-to-SOCKS5 bridging, facilitating selective Tor routing when combined with an external reverse proxy.

## Features

* **Multiple Backend Tor Instances**: Run and manage `N` independent Tor processes, configurable at startup. \
* **Common SOCKS5 Proxy**: A single entry point (default: `0.0.0.0:9000`) that load balances SOCKS5 connections across healthy backend Tor instances. \
* **Common DNS Proxy**:
    * A single entry point (default: `0.0.0.0:5300`) that load balances DNS queries across healthy backend Tor instances' DNS resolvers. \
    * Includes configurable **DNS caching** to improve response times and reduce load on Tor's DNS.
* **Bundled Privoxy HTTP Proxy**:
    * Privoxy runs within the `torgo` Docker container (default port: `8118`).
    * Acts as an HTTP-to-SOCKS5 bridge, forwarding HTTP requests to `torgo`'s common SOCKS5 proxy.
    * Simplifies setups where an external reverse proxy (like Nginx or HAProxy on the host) selectively routes HTTP/HTTPS traffic through Tor.
* **Load Balancing**: Distributes incoming SOCKS and DNS requests across available healthy Tor instances (currently round-robin). \
* **Health Monitoring**: Periodically checks the health of each backend Tor instance and excludes unhealthy ones from the load balancing pool. \
* **Automatic Circuit Rotation**: Configurable time-based automatic `NEWNYM` signals for Tor instances. \
* **IP Diversity Management**:
    * Monitors external IPs of Tor instances to ensure diversity across subnets (e.g., /24). \
    * Can trigger rotations if too many instances share similar IP subnets.
    * (Conceptual) New circuit requests via the API can incorporate an immediate diversity check with retries.
* **Management API & Web UI**:
    * An HTTP API (default: `0.0.0.0:8080`) for instance control: rotate circuit, get health, stats, IP, and configuration. \
    * Global endpoint to rotate all healthy instances with a stagger delay. \
    * A basic Web UI served at `/webui` for monitoring instance status and triggering new circuits. \
* **Dockerized**: Easy to build and deploy using Docker and Docker Compose. Includes a Docker health check. \
* **Configurable**: Most parameters are configurable via environment variables. \

## Project Structure (Refined Modular Layout)

```
torgo/
├── cmd/torgo/
│   └── main.go                     # Main application entry point
│
├── internal/
│   ├── api/                        # HTTP API handlers and WebUI serving
│   │   ├── handlers.go
│   │   └── webui_handler.go        # (Handles webui.html embedding and serving)
│   │   └── static_web_ui/      <-- Your index.html, style.css, etc. go here
│   │
│   ├── config/                     # Application configuration
│   │   └── config.go
│   │
│   ├── dns/                        # DNS related logic
│   │   ├── cache.go                # DNS caching
│   │   └── proxy.go                # DNS proxy server and request handling
│   │
│   ├── socks/                      # SOCKS proxy logic
│   │   └── proxy.go
│   │
│   ├── tor/                        # Tor instance management and control
│   │   └── instance.go
│   │
│   ├── health/                     # Health monitoring for Tor instances
│   │   └── monitor.go
│   │
│   ├── rotation/                   # Circuit rotation strategies
│   │   ├── auto_monitor.go         # Time-based auto-rotation
│   │   └── diversity_monitor.go    # IP diversity based rotation
│   │
│   └── lb/                         # Load balancing logic
│       └── loadbalancer.go
│
├── Dockerfile
├── docker-compose.yml
├── docker-healthcheck.sh
├── entrypoint.sh
├── go.mod
├── go.sum
├── privoxy_config                  # Bundled Privoxy configuration
└── README.md
```

## Prerequisites

* Docker
* Docker Compose

## Getting Started

1.  **Clone the repository (or ensure all project files are in place).**
2.  **(Optional) Create a `.env` file** in the project root to customize settings. See `docker-compose.yml` for available variables and their defaults. Example:
    ```env
    TOR_INSTANCES=5
    API_PORT=8088
    COMMON_SOCKS_PROXY_PORT=9999
    COMMON_DNS_PROXY_PORT=5353 # For Torgo's DNS proxy
    PRIVOXY_HTTP_PORT=8118 # For the bundled Privoxy's HTTP port mapping
    DNS_CACHE_ENABLED=true
    DNS_CACHE_EVICTION_INTERVAL_SECONDS=600
    ```
3.  **Build and run using Docker Compose**:
    ```bash
    docker-compose up --build -d
    ```
    This will build the `torgo` image (including Privoxy) and start the service in detached mode.

## Configuration

Key environment variables (set in `.env` or `docker-compose.yml` \):

* `TOR_INSTANCES`: Number of backend Tor instances.
* `SOCKS_BASE_PORT_CONFIGURED`, `CONTROL_BASE_PORT_CONFIGURED`, `DNS_BASE_PORT_CONFIGURED`: Base ports for individual Tor instances.
* `COMMON_SOCKS_PROXY_PORT`: Port for `torgo`'s common SOCKS5 proxy.
* `COMMON_DNS_PROXY_PORT`: Port for `torgo`'s common DNS proxy.
* `API_PORT`: Port for the management API and WebUI.
* `PRIVOXY_HTTP_PORT`: Host port to map to the bundled Privoxy's internal port (8118).
* Rotation & Health: `ROTATION_STAGGER_DELAY_SECONDS`, `HEALTH_CHECK_INTERVAL_SECONDS`, `AUTO_ROTATE_CIRCUIT_INTERVAL_SECONDS`, `AUTO_ROTATE_STAGGER_DELAY_SECONDS`.
* IP Checks & Timeouts: `IP_CHECK_URL`, `SOCKS_TIMEOUT_SECONDS`, `DNS_TIMEOUT_SECONDS`.
* IP Diversity: `IP_DIVERSITY_CHECK_INTERVAL_SECONDS`, `IP_DIVERSITY_ROTATION_COOLDOWN_SECONDS`, `MIN_INSTANCES_FOR_IP_DIVERSITY_CHECK`.
* DNS Cache: `DNS_CACHE_ENABLED`, `DNS_CACHE_EVICTION_INTERVAL_SECONDS`, `DNS_CACHE_DEFAULT_MIN_TTL_SECONDS`, `DNS_CACHE_MIN_TTL_OVERRIDE_SECONDS`, `DNS_CACHE_MAX_TTL_OVERRIDE_SECONDS`.

(Refer to `internal/config/config.go` for how these are parsed \)

## Using torgo

* **SOCKS5 Proxy**: Configure applications to use `127.0.0.1:<COMMON_SOCKS_PROXY_PORT>`.
* **DNS Proxy**: Configure system/applications to use `127.0.0.1:<COMMON_DNS_PROXY_PORT>` (UDP & TCP).
* **HTTP Proxy (via bundled Privoxy)**:
    * The bundled Privoxy listens on port 8118 inside the container. If you map this to a host port (e.g., `8118:8118`), applications can use `http://127.0.0.1:8118` as an HTTP proxy to access the Tor network via `torgo`.
    * More commonly, this is used with a reverse proxy like Nginx on your VPS for selective routing (see below).
* **Web UI**: Access at `http://localhost:<API_PORT>/webui`. \

## API Endpoints

The management API listens on `http://localhost:<API_PORT>` \.

### Global Endpoints
* **`GET /api/v1/app-details`**: Provides basic application configuration details.
* **`POST` or `GET` `/api/v1/rotate-all-staggered`**: Rotates circuits for all healthy instances, staggered. Streams progress.

### Per-Instance Endpoints
Replace `<id>` with the Tor instance number (e.g., `tor1`, `tor2`).

* **`POST` or `GET` `/api/v1/tor<id>/rotate`**: Signals for a new circuit (NEWNYM).
* **`GET /api/v1/tor<id>/health`**: Checks health status.
* **`GET /api/v1/tor<id>/stats`**: Retrieves Tor statistics.
* **`GET /api/v1/tor<id>/ip`**: Gets the current external IP through this instance.
* **`GET /api/v1/tor<id>/config`**: Retrieves backend instance configuration details.
* **(Risky)** `POST /api/v1/tor<id>/config/{socksport|dnsport|controlport}`: Dynamically changes backend ports.

## Advanced Usage: Selective Routing

To route only specific websites through Tor while others go direct, you can use an external reverse proxy (like Nginx or HAProxy) on your VPS host.

1.  Your client (e.g., browser connected via WireGuard) points to this external Nginx/HAProxy as its HTTPS proxy.
2.  Nginx/HAProxy terminates SSL and inspects the requested domain.
3.  Based on your rules:
    * For Tor-bound domains, Nginx/HAProxy forwards the HTTP request to the `torgo` container's Privoxy port (e.g., `http://127.0.0.1:8118` if mapped from the container).
    * Privoxy then forwards this to `torgo`'s SOCKS5 proxy, out to Tor.
    * Other domains can be proxied directly by Nginx/HAProxy or blocked.

## Development

* The Go application (`cmd/torgo/main.go`) uses packages from `internal/`.
* Ensure Go (1.21+) is installed for local development.
* `go mod tidy` for dependencies.

## Stopping the Service

```bash
docker-compose down
```

## Future Enhancements / TODO

* More sophisticated load balancing strategies (e.g., least connections)..
* Enhanced Web UI with more stats and controls.
* Metrics endpoint for Prometheus scraping.
* More robust error handling and recovery for individual Tor process issues beyond control port commands.

