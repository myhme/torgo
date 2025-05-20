# torgo: Multi-Instance Tor Controller & Load Balancing Proxy

**torgo** is a Go application designed to manage multiple backend Tor instances, providing a unified SOCKS5 and DNS proxy interface with round-robin load balancing. It also exposes an HTTP API for fine-grained control over individual Tor instances, including circuit rotation, health checks, and statistics, along with a basic Web UI for monitoring.

## Features

* **Multiple Backend Tor Instances**: Run and manage `N` independent Tor processes.
* **Common SOCKS5 Proxy**: A single entry point (default: `0.0.0.0:9000`) that load balances SOCKS5 connections across healthy backend Tor instances.
* **Common DNS Proxy**: A single entry point (default: `0.0.0.0:5300`) that load balances DNS queries across healthy backend Tor instances, allowing for Tor-resolved DNS.
* **Round-Robin Load Balancing**: Distributes incoming SOCKS and DNS requests across available healthy Tor instances.
* **Individual Tor Instance Control API**:
    * Rotate Tor circuit (`SIGNAL NEWNYM`) for a specific instance.
    * Get health status of an instance.
    * Retrieve statistics from an instance.
    * Get the current external IP address used by an instance.
    * Dynamically configure an instance's backend SOCKS, DNS, and Control ports (use with caution for ControlPort).
* **Global Staggered Rotation API**: Rotate circuits for all healthy Tor instances one by one with a configurable delay.
* **Health Monitoring**: Periodically checks the health of each backend Tor instance and excludes unhealthy ones from the load balancing pool.
* **Basic Web UI**: A simple web interface served at `/webui` to monitor instance status and trigger new circuits.
* **Dockerized**: Easy to build and deploy using Docker and Docker Compose.
* **Docker Health Check**: Integrated health check for the Docker container via the common SOCKS5 proxy.
* **Configurable**: Key parameters like the number of Tor instances, base ports, common proxy ports, and rotation delays are configurable via environment variables.

## Project Structure

```
torgo/
├── cmd/torgo/              # Main application package
│   └── main.go
├── internal/               # Internal packages
│   ├── api/                # HTTP API handlers & WebUI
│   │   ├── handlers.go
│   │   └── webui.html
│   ├── config/             # Application configuration
│   ├── health/             # Health monitoring
│   ├── lb/                 # Load balancing logic
│   ├── proxy/              # SOCKS5 and DNS proxy servers
│   └── torinstance/        # Tor instance management
├── Dockerfile              # Builds the application
├── docker-compose.yml      # For easy deployment
├── docker-healthcheck.sh   # Script for Docker health checks
├── entrypoint.sh           # Starts Tor instances and the Go app
├── go.mod                  # Go module definition
├── go.sum
└── torrc.template          # Template for Tor configuration
```
## Prerequisites

* Docker
* Docker Compose

## Getting Started

1.  **Clone the repository (or create the files as provided in our discussion).**
2.  **(Optional) Create a `.env` file** in the project root to customize settings (see `docker-compose.yml` for available variables). For example:
    ```env
    TOR_INSTANCES=5
    API_PORT=8088
    COMMON_SOCKS_PROXY_PORT=9999
    COMMON_DNS_PROXY_PORT=5353
    ROTATION_STAGGER_DELAY_SECONDS=20
    ```
3.  **Build and run using Docker Compose**:
    ```bash
    docker-compose up --build -d
    ```
    This will build the `torgo` image and start the service in detached mode.

## Configuration

The application is configured via environment variables, primarily set in `docker-compose.yml` or a `.env` file.

**Key Environment Variables (defaults are shown if not set in `.env` or `docker-compose.yml`):**

* `TOR_INSTANCES`: Number of backend Tor instances to run (default specified in `docker-compose.yml`, e.g., `3`).
* `API_PORT`: Port for the Go management API and WebUI (default: `8080`).
* `COMMON_SOCKS_PROXY_PORT`: Port for the common SOCKS5 proxy (default: `9000`).
* `COMMON_DNS_PROXY_PORT`: Port for the common DNS proxy (default: `5300`).
* `ROTATION_STAGGER_DELAY_SECONDS`: Delay (in seconds) between rotating circuits in the "rotate-all-staggered" command (default: `10` or `15` as per `docker-compose.yml`).
* `HEALTH_CHECK_INTERVAL_SECONDS`: Interval for checking backend Tor instance health (default: `30` or `45` as per `docker-compose.yml`).
* `IP_CHECK_URL`: URL used to check the external IP of a Tor instance (default: `https://check.torproject.org/api/ip`).
* `SOCKS_TIMEOUT_SECONDS`: Timeout for SOCKS operations within the Go app (default: `10` or `15` as per `docker-compose.yml`).
* `SOCKS_BASE_PORT_CONFIGURED`: Base port for backend Tor SOCKS listeners (default: `9050`). Instance `j` uses `BASE + j`.
* `CONTROL_BASE_PORT_CONFIGURED`: Base port for backend Tor Control listeners (default: `9160`). Instance `j` uses `BASE + j`.
* `DNS_BASE_PORT_CONFIGURED`: Base port for backend Tor DNS listeners (default: `9200`). Instance `j` uses `BASE + j`.

## Using torgo

* **SOCKS5 Proxy**: Configure your applications to use `127.0.0.1:<COMMON_SOCKS_PROXY_PORT>` (e.g., `127.0.0.1:9000` if using default).
* **DNS Proxy**: Configure your system or applications to use `127.0.0.1:<COMMON_DNS_PROXY_PORT>` (e.g., `127.0.0.1:5300` if using default) for DNS resolution.
* **Web UI**: Access the web interface at `http://localhost:<API_PORT>/webui` (e.g., `http://localhost:8080/webui`).

## API Endpoints

The management API listens on `http://localhost:<API_PORT>`.

### Global Endpoints

* **`GET` or `POST` `/api/v1/rotate-all-staggered`**:
    Rotates the Tor circuits for all currently healthy backend instances in a staggered manner. Streams progress.
* **`GET` `/api/v1/app-details`**:
    Provides basic application configuration details (number of instances, common ports).

### Per-Instance Endpoints

Replace `<id>` with the Tor instance number (e.g., `tor1`, `tor2`, ..., `torN`).

* **`POST` or `GET` `/api/v1/tor<id>/rotate`**:
    Signals the specified Tor instance to get a new circuit (NEWNYM).
    *Example*: `curl -X POST http://localhost:8080/api/v1/tor1/rotate`

* **`GET` `/api/v1/tor<id>/health`**:
    Checks the health of the specified Tor instance.
    *Example*: `curl http://localhost:8080/api/v1/tor1/health`

* **`GET` `/api/v1/tor<id>/stats`**:
    Retrieves statistics from the specified Tor instance.
    *Example*: `curl http://localhost:8080/api/v1/tor1/stats`

* **`GET` `/api/v1/tor<id>/ip`**:
    Gets the current external IP address as seen by the specified Tor instance.
    *Example*: `curl http://localhost:8080/api/v1/tor1/ip`

* **`GET` `/api/v1/tor<id>/config`**:
    Retrieves the backend configuration details for the specified Tor instance.
    *Example*: `curl http://localhost:8080/api/v1/tor1/config`

* **`POST` `/api/v1/tor<id>/config/socksport`**:
    Dynamically changes the backend SOCKS port for the specified Tor instance.
    *JSON Body*: `{"address": "127.0.0.1", "port": 9055}`

* **`POST` `/api/v1/tor<id>/config/dnsport`**:
    Dynamically changes the backend DNS port for the specified Tor instance. Port `0` disables it.
    *JSON Body*: `{"address": "127.0.0.1", "port": 9255}`

* **`POST` `/api/v1/tor<id>/config/controlport`**:
    **HIGHLY RISKY**. Dynamically changes the backend Control port.
    *JSON Body*: `{"address": "127.0.0.1", "port": 9165}`

## Development

* The Go application is structured into `cmd/torgo` and `internal/` packages.
* Ensure Go (1.24+) is installed.
* Run `go mod tidy` to manage dependencies.
* The `webui.html` uses a local `tailwind.css`. You'll need to provide this file (e.g., by downloading the full build from Tailwind's CDN or by using the Tailwind CLI to generate an optimized version based on `webui.html`). For the Web UI to correctly load `tailwind.css` when served by the Go app, you might need to adjust the Go app to serve static assets or embed `tailwind.css` similarly to `webui.html`. The current `webui.html` expects `tailwind.css` to be served from the same path level.

## Stopping the Service

```bash
docker-compose down
```

## Future Enhancements / TODO

* More sophisticated load balancing strategies.
* Full SOCKS5 server implementation for commands beyond CONNECT (e.g., using armon/go-socks5).
* Enhanced Web UI with more interactive elements and visualizations (e.g., charts for traffic).