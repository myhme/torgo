# torgo: Multi-Instance Tor Controller & Load Balancing Proxy

**torgo** is a Go application designed to manage multiple backend Tor instances, providing a unified SOCKS5 and DNS proxy interface with configurable load balancing. It also exposes an HTTP API for fine-grained control over individual Tor instances, including circuit rotation, health checks, and statistics, along with a Web UI for monitoring and basic control.

**Key Features:**
* **Unified Circuit Manager**: Combines circuit age-based rotation and IP diversity logic.
* **Performance Metrics**: Periodically tests each Tor instance for latency and light download speed.
* **WebUI Enhancements**: Displays performance metrics and allows configuration of Tor Exit Node policies.
* **Configurable Load Balancing**: Supports "random", "round-robin", and "least-connections-proxy".
* **Structured Logging**: Uses `log/slog` for structured, configurable logging (JSON/text, levels).
* More environment variables for fine-tuning these new features.

## Features (Existing & Enhanced)

* **Multiple Backend Tor Instances**: Run and manage `N` independent Tor processes.
* **Common SOCKS5 Proxy**: A single entry point (default: `0.0.0.0:9000`) that load balances SOCKS5 connections.
* **Common DNS Proxy**: A single entry point (default: `0.0.0.0:5300`) that load balances DNS queries.
* **Configurable Load Balancing**: "random" (default), "round-robin", "least-connections-proxy".
* **Circuit Management API & Automation**:
    * Manual rotation of individual or all circuits.
    * Automated rotation based on circuit age and IP address diversity (via CircuitManager).
* **Health Monitoring**: Periodically checks backend Tor instances.
* **Performance Testing**: Optional periodic latency and speed tests per instance.
* **Web UI**: (`/webui`)
    * Monitor instance status, IP, active connections.
    * Trigger new circuits.
    * View performance metrics (latency, speed).
    * Configure ExitNode and ExcludeNode policies per instance.
* **Dockerized**: Easy deployment with Docker and Docker Compose.
* **Highly Configurable**: Via environment variables, including logging.

## Project Structure (Simplified for v3)

```
torgo/
├── cmd/torgo/
│   └── main.go
├── internal/
│   ├── api/                # HTTP API handlers & WebUI (handlers.go, webui.html)
│   ├── circuitmanager/     # NEW: Unified circuit rotation, IP diversity, performance tests (manager.go)
│   ├── config/             # Application configuration (config.go)
│   ├── health/             # Health monitoring (monitor.go)
│   ├── lb/                 # Load balancing logic (loadbalancer.go)
│   ├── proxy/              # SOCKS5 and DNS proxy servers (dns_proxy.go, socks_proxy.go)
│   └── torinstance/        # Tor instance management & control (instance.go)
├── Dockerfile
├── docker-compose.yml
├── docker-healthcheck.sh
├── entrypoint.sh
├── go.mod
├── go.sum
├── README.md               # This file
└── torrc.template          # Template for Tor configuration
```

## Prerequisites

* Docker
* Docker Compose

## Getting Started

1.  **Clone the repository (or create the files as provided).**
2.  **(Optional) Create a `.env` file** in the project root to customize settings (see `docker-compose.yml` for available variables).
3.  **Build and run using Docker Compose**:
    ```bash
    docker-compose up --build -d
    ```

## Configuration

Key environment variables (see `docker-compose.yml` and `internal/config/config.go` for defaults and full list):

* `TOR_INSTANCES`: Number of backend Tor instances.
* `API_PORT`, `COMMON_SOCKS_PROXY_PORT`, `COMMON_DNS_PROXY_PORT`.
* `LOAD_BALANCING_STRATEGY`: `random`, `round-robin`, `least-connections-proxy`.
* `LOG_LEVEL`: `debug`, `info`, `warn`, `error`.
* `LOG_FORMAT`: `text`, `json`.
* `CIRCUIT_MANAGER_ENABLED`: `true` or `false`.
* `CIRCUIT_MAX_AGE_SECONDS`: Max age for circuits before rotation (0 to disable).
* `IP_DIVERSITY_ENABLED`: `true` or `false` (within CircuitManager).
* `PERF_TEST_ENABLED`: `true` or `false`.
* `PERF_TEST_INTERVAL_SECONDS`: How often to run performance tests.
* ... and many more for fine-tuning.

## Using torgo

* **SOCKS5 Proxy**: Configure applications to use `127.0.0.1:<COMMON_SOCKS_PROXY_PORT>`.
* **DNS Proxy**: Configure system/applications to use `127.0.0.1:<COMMON_DNS_PROXY_PORT>`.
* **Web UI**: Access at `http://localhost:<API_PORT>/webui`.

## API Endpoints

The management API listens on `http://localhost:<API_PORT>`.

### Global Endpoints

* **`GET /api/v1/app-details`**: Application configuration.
* **`POST` or `GET` `/api/v1/rotate-all-staggered`**: Manually rotate all healthy circuits.

### Per-Instance Endpoints (`<id>` is the numeric instance ID, e.g., `1`, `2`)

* **`POST` or `GET` `/api/v1/instance/<id>/rotate`**: New circuit for the instance.
* **`GET /api/v1/instance/<id>/health`**: Health status.
* **`GET /api/v1/instance/<id>/stats`**: Tor statistics.
* **`GET /api/v1/instance/<id>/ip`**: External IP.
* **`GET /api/v1/instance/<id>/config`**: Instance configuration, including current node policies.
* **`POST /api/v1/instance/<id>/config/nodepolicy`**: Set node policies (ExitNodes, ExcludeNodes, EntryNodes).
    * JSON Body: `{"policy_type": "ExitNodes", "nodes": "{us},{ca}"}` or `{"policy_type": "ExcludeNodes", "nodes": "{ru}"}`. Empty `nodes` clears.
* **`GET /api/v1/instance/<id>/performancemetrics`**: Get stored latency and speed test results.
* **`POST /api/v1/instance/<id>/config/<porttype>`**: (`porttype` = `socksport`, `dnsport`, `controlport`) Dynamically change backend ports.

## Development

* Go (1.24+ recommended).
* Run `go mod tidy`.
* The `webui.html` is self-contained.

## Stopping

```bash
docker-compose down
