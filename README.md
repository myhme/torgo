# torgo: Advanced Multi-Instance Tor Controller & Transparent Gateway

**torgo** is a Go application designed to manage multiple backend Tor instances, supervised for robustness. It provides two powerful modes of operation: a standard **Application Proxy** and an advanced **Transparent Gateway**.

It includes unified SOCKS5 and DNS proxy interfaces, intelligent load balancing, an HTTP API, a Web UI, and production-ready features like **graceful circuit rotation**, IP diversity management, and in-memory DNS caching.

## Key Features

* **Dual Mode Operation**: Use as a standard application proxy or as a transparent gateway that automatically forces all client traffic through Tor.
* **Round-Robin Load Balancing**: Maximizes throughput by distributing parallel requests (e.g., from web browsers) across all healthy Tor instances.
* **Graceful Circuit Rotation**: Prevents connection drops during IP rotation by "draining" instances of existing connections before renewing their circuit.
* **Built-in Kill Switch & Health Checks**: A native `/api/v1/healthz` endpoint and a two-layer system of network isolation and health checks ensure traffic is blocked if the Tor service fails, preventing IP leaks.
* **Dynamic Runtime Configuration**: Customize Tor and Privoxy behavior using environment variables without rebuilding the image.
* **Privacy-First Design**: All traffic, including DNS, is routed over Tor. Caching is done in-memory to avoid writing sensitive data to disk.
* **Hardened & Modernized**: Built with a stripped Go binary and explicit dependencies via Go Modules for a smaller, more secure footprint.

## Project Structure (Refined Modular Layout)

```
torgo/
├── Dockerfile
├── docker-compose.yml
├── docker-healthcheck.sh
├── entrypoint.sh
├── go.mod
├── go.sum
├── privoxy.conf.template
├── torrc.template
├── README.md
├── cmd/
│   └── torgo/
│       └── main.go
└── internal/
    ├── api/
    │   ├── handlers.go
    │   ├── webui_handler.go
    │   └── static_web_ui/
    │       └── index.html
    ├── config/
    │   └── config.go
    ├── dns/
    │   ├── cache.go
    │   └── proxy.go
    ├── health/
    │   └── monitor.go
    ├── lb/
    │   └── loadbalancer.go
    ├── rotation/
    │   ├── auto_monitor.go
    │   ├── diversity_monitor.go
    │   └── graceful.go
    ├── socks/
    │   └── proxy.go
    └── tor/
        └── instance.go
```

## Operating Modes

You can choose the mode that best fits your needs.

### 1. Transparent Gateway Mode (Recommended for Simplicity)

This is the easiest and most comprehensive way to force a container's traffic through Tor. It automatically captures and redirects all network traffic, requiring no changes to your client applications.

**How to use:**
1.  In `docker-compose.yml`, set the environment variable `TORGO_TRANSPARENT_PROXY=true`.
2.  For your client container, set `network_mode: "service:torgo"`.

The client container will now have all of its TCP and DNS traffic automatically routed through `torgo`'s Tor circuits.

*Security Note:* This mode requires granting the `torgo` container the `NET_ADMIN` capability, which gives it elevated network permissions.

### 2. Application Proxy Mode (Advanced / No Elevated Permissions)

This mode does not require special container permissions but requires your client applications to be explicitly configured to use a proxy.

**How to use:**
1.  In `docker-compose.yml`, ensure `TORGO_TRANSPARENT_PROXY` is `false` or unset.
2.  Connect your client container to an isolated network that it shares with `torgo` (see previous examples if needed).
3.  Configure your client application to use the `torgo` proxy (e.g., `socks5://torgo:9000` or `http://torgo:8118`).

## Advanced Runtime Configuration

Customize Tor and Privoxy by setting environment variables in `docker-compose.yml`.

* **`TORGO_TRANSPARENT_PROXY`**: Set to `true` to enable the transparent gateway mode.
* **`PRIVOXY_LOG_LEVEL`**: Sets logging verbosity for Privoxy (`0` = quiet, `1` = startup/fatal, `512` = blocked URLs).
* **`TOR_EXIT_NODES`**: Restrict Tor exit nodes to specific countries (e.g., `{us},{gb}`).
* **`TOR_MAX_CIRCUIT_DURTINESS`**: Sets the max time in seconds a circuit can be used (e.g., `900` for 15 minutes).

