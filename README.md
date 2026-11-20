# Raddy

Raddy is a Rust reverse proxy and static file server with automatic TLS via Cloudflare DNS-01. It supports HTTP/1.1, HTTP/2, WebSocket upgrades, gRPC upstreams over h2c, and TCP/TLS passthrough. HTTPS termination and TLS passthrough can share a port and use SNI to select a route.

[Русский](README.ru.md) · [Releases](https://github.com/rawtls/raddy/releases) · [License](LICENSE) · [Security](SECURITY.md)

Raddy is an early-stage project. It supports a subset of Caddyfile syntax, not the full Caddy module ecosystem. See [Compatibility](#compatibility) before migrating a configuration.

## Quick start

With Rust 1.94 or newer, create `local.Raddyfile`:

```caddyfile
{
    default_bind 127.0.0.1
}

:8080 {
    respond "OK"
}
```

```sh
cargo build --locked --release
./target/release/raddy --config local.Raddyfile validate
./target/release/raddy --config local.Raddyfile run
```

In another terminal, run `curl -fsS http://127.0.0.1:8080/`. This returns `OK` and needs no domain or Cloudflare credentials.

Without `--config`, Raddy looks for `raddy.json`, `Raddyfile`, and `Caddyfile` in that order. Files ending in `.json` use JSON; other files use Caddyfile syntax. See the sample [`Raddyfile`](Raddyfile) and [`raddy.example.json`](raddy.example.json).

## Docker Compose (Linux host networking)

Save `compose.yaml` next to your `Raddyfile`:

```yaml
services:
  raddy:
    image: ghcr.io/rawtls/raddy:v0.3.0
    container_name: raddy
    restart: unless-stopped
    stop_grace_period: 35s
    network_mode: host
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    environment:
      - CF_API_TOKEN
    volumes:
      - ./Raddyfile:/etc/raddy/Raddyfile:ro
      - raddy-data:/data

volumes:
  raddy-data:
```

The image is available for `linux/amd64` and `linux/arm64`. Images can also be loaded from the release archives with `docker load`. To build from a checkout instead, replace `image:` with `build: .` and run `docker compose build`.

With host networking, omit `ports:`. Raddy binds directly on the host: make sure the ports are free and restrict access to internal listeners with `bind` or a firewall. An upstream such as `127.0.0.1:10001` can reach Xray running on the same Linux host. The mounted configuration and any mounted certificates must be readable by UID `10001`.

### Cloudflare DNS-01

For automatic HTTPS, put `.env` next to `compose.yaml` and run Docker Compose from that directory:

```dotenv
CF_API_TOKEN=your_cloudflare_token
```

Use a token scoped to the relevant zones, with **Zone:Read** and **DNS:Edit**. To split permissions, set `zone_token` to a separate **Zone:Read** token and leave only **DNS:Edit** on `api_token`. Do not commit `.env`. A value exported in your shell overrides `.env`. If you do not use Cloudflare DNS-01, omit the token.

For example, use this `Raddyfile`, replacing `app.example.com` and the upstream with your own:

```caddyfile
{
    data_dir /data/raddy-data
    cloudflare {
        api_token {env.CF_API_TOKEN}
    }
}

app.example.com {
    reverse_proxy http://127.0.0.1:10001
}
```

```sh
docker compose run --rm raddy validate
docker compose up -d
```

Validation checks the configuration and configured PEM files, but does not contact the certificate authority. Before deploying, test issuance against ACME staging and keep a backup of `data_dir` outside the source tree. To use existing PEM files instead of ACME, set `tls /path/to/cert.pem /path/to/key.pem` in the site block.

## Routing, TLS passthrough, and PROXY protocol

Use `reverse_proxy http://…` for HTTP/1.1 upstreams, including WebSocket upgrades. Use `reverse_proxy h2c://…` for an unencrypted HTTP/2 upstream, such as a gRPC service behind Raddy TLS termination. `handle` keeps the path; `handle_path` strips the matched prefix.

```caddyfile
tls://pass.example.com:443 {
    proxy 127.0.0.1:10002
}

*.example.com {
    respond "HTTPS terminated by Raddy"
}

tcp://:443 {
    proxy 127.0.0.1:10003
}
```

Configure Cloudflare DNS-01 or existing PEM files for the HTTPS site. `tls://` inspects ClientHello for SNI and forwards the original TLS bytes to the upstream; it does not terminate TLS. Matching order on a shared port is exact SNI, single-label wildcard, `tls://*:port`, then the optional TCP fallback. HTTPS and passthrough cannot use the same SNI pattern, and listeners sharing a port must use the same bind address. SNI is routing information, not authentication.

Enable outgoing `proxy_protocol v1` or `proxy_protocol v2` inside `proxy` or `reverse_proxy` only if the upstream expects it. For HTTP reverse proxying, it prevents pooling upstream connections across requests. Incoming `proxy_protocol_accept` is a per-port setting: configure it only behind a trusted load balancer and list its IP addresses or CIDRs. On such ports, clients without a PROXY header or from an untrusted address are rejected.

## Operating Raddy

- On Unix, send `SIGUSR1` to reload configuration and imported files (`docker compose kill -s SIGUSR1 raddy`). If the reload fails, the old configuration remains active. Established TCP, TLS passthrough, and WebSocket tunnels are preserved during reload.
- On `SIGTERM` or `SIGINT`, Raddy stops accepting new connections and gives active traffic up to 30 seconds to finish by default. Use `run --grace-period-secs` to adjust this and give the container a longer `stop_grace_period`.
- The global `max_connections` option limits accepted client TCP connections across ports (`0` disables the limit). It does not limit HTTP/2 streams or account for upstream file descriptors. Set host file-descriptor limits and load-test with your expected workload.
- Static files support conditional requests and single byte ranges. On Unix, file cache entries can hold file bodies up to 16 KiB; the default cache stores up to 1,024 entries, with a 30-second TTL. Small files can stay cached after replacement or deletion until that TTL expires. Large files are streamed. To reopen paths for every request, set `static_cache_ttl 0s` in the global block.
- Keep production configuration, tokens, certificates, and ACME storage outside your static file root. Without a trusted PROXY protocol listener, Raddy uses the immediate peer address for `X-Forwarded-For`, not a chain supplied by the client.

See the [Russian reference](README.ru.md) for the full configuration fields, DNS CLI, and additional routing examples.

## Performance

Local benchmark on Debian 13 x86_64 (QEMU, 4 vCPUs): one vCPU each for the server, load generator, and echo backend; 32 HTTP/1.1 connections; three runs of eight seconds per case; 1 KiB files and POST bodies. The table shows median requests per second and p99 latency. `wrk` reported no errors in 42 runs.

| Scenario | Raddy before body cache | Raddy with body cache | nginx 1.26.3 |
| --- | ---: | ---: | ---: |
| HTTP static file | 300,782 · 0.15 ms | 318,502 · 0.14 ms | 134,410 · 0.31 ms |
| HTTPS static file, keep-alive | 34,897 · 1.93 ms | 70,133 · 0.55 ms | 90,616 · 0.47 ms |
| HTTPS static file, new connection per request | 2,821 · 6.68 ms | 2,792 · 5.22 ms | 1,762 · 5.70 ms |
| HTTPS to HTTP upstream, POST | 32,245 · 2.65 ms | 32,586 · 2.37 ms | 37,099 · 3.00 ms |
| Same POST with upstream PROXY v1 | 5,471 · 7.52 ms | 5,476 · 7.58 ms | Not measured |

Both servers used TLS 1.3 and the same ECDSA P-256 certificate. nginx session caching and tickets were disabled; Raddy used its TLS defaults. Requests per second for new connections include the cost of TCP and TLS setup, but `wrk` p99 does not measure total connection setup time. The POST backend is a Python echo server. These results do not measure XHTTP/VLESS, TLS passthrough, HTTP/2, or thousands of persistent sessions.

```sh
python3 tests/benchmark.py target/release/raddy --nginx /usr/sbin/nginx
```

The script requires Linux, at least three available CPUs, `python3`, `openssl`, `taskset`, and `wrk`. Add `--baseline /path/to/previous/raddy` to compare another build or `--case tls-keepalive` to run only the keep-alive test.

## Compatibility

Raddy supports common Caddyfile directives including `respond`, `reverse_proxy`, `root`, `file_server`, `handle`, `handle_path`, `route`, `rewrite`, `try_files`, `header`, and `import`, but their full Caddy semantics are not guaranteed. Unsupported directives are rejected at configuration time. There is no Caddy admin API, plugin loading, HTTP/3, UDP proxying, `file_server browse`, internal or on-demand TLS, or ACME HTTP-01/TLS-ALPN-01. WebSocket upgrades use HTTP/1.1; extended CONNECT over HTTP/2 is not supported. See the [detailed compatibility notes](README.ru.md#границы-совместимости).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
python3 tests/network.py target/release/raddy
# With Caddy 2.10.2 on PATH:
python3 tests/caddy_parity.py target/release/raddy
```

Licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) and the [security reporting policy](SECURITY.md).
