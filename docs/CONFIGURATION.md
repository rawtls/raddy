# Configuring Raddy

[Русский](CONFIGURATION.ru.md) · [Home](../README.md) · [Sample Raddyfile](../Raddyfile) · [Sample JSON](../raddy.example.json)

## Configuration file

Without `--config`, Raddy looks for `raddy.json`, `Raddyfile`, and `Caddyfile` in that order. A `.json` file uses JSON; other files use Caddyfile syntax. To run from source (Rust 1.94 or newer):

```sh
cargo build --locked --release
./target/release/raddy --config Raddyfile validate
./target/release/raddy --config Raddyfile run
```

## Docker Compose (Linux host networking)

Save `compose.yaml` next to your `Raddyfile`:

```yaml
services:
  raddy:
    image: ghcr.io/rawtls/raddy:v0.4.1
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

Validation compiles the HTTP handlers, checks their filesystem roots and validates configured PEM files. It neither binds ports nor contacts the certificate authority. Before deploying, test issuance against ACME staging and keep a backup of `data_dir` outside the source tree. To use existing PEM files instead of ACME, set `tls /path/to/cert.pem /path/to/key.pem` in the site block.

Automatic certificate caches are isolated by ACME directory URL. Bundles from versions without that separation are not used automatically; the first start after upgrading can require fresh issuance. Raddy records pending DNS‑01 TXT cleanup in `data_dir` and retries it on start and during renewal when Cloudflare credentials are configured.

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

### Per-route HTTP proxy timeouts

```caddyfile
reverse_proxy http://127.0.0.1:10001 {
    connect_timeout 10s
    response_header_timeout 30s
    stream_idle_timeout 5m
}
```

These Raddy-specific options take positive whole-second durations. `connect_timeout` sets the TCP dial timeout (default 10s, not a TLS handshake timeout). `response_header_timeout` bounds the wait for upstream headers across attempts; upload progress extends it. `stream_idle_timeout` limits idle time waiting for response frames after the headers; request-body activity on **the same HTTP exchange** also extends it. It does not combine activity from separate XHTTP requests or change WebSocket tunnels after Upgrade. Without a route override the global `request_timeout` still applies as before. In JSON use `connect_timeout_secs`, `response_header_timeout_secs`, `stream_idle_timeout_secs` in `proxy`. Available since v0.4.1.

## Operating Raddy

On HTTPS termination listeners, connections closed before TLS completes, invalid TLS record types, and handshake timeouts are logged individually at debug level. At info level a nonempty `TLS handshake summary` reports counts per listener every minute (and on configuration drain). Other handshake failures and post-handshake decryption errors remain warnings. No client IP or SNI is included in the summary.

- Starting with v0.5.0-rc.1: Raddy supports multiple HTTPS ports with independent bind addresses, SNI certificates and HTTP routes. For example, `*.example.com` and `https://*.example.com:9443` with `bind 127.0.0.1` in the latter block can use different handlers. An exact `tls://pass.example.com:443` passthrough route affects only port 443. JSON HTTPS sites can set `listen` to an `IP:port`, defaulting to `https_addr`. Duplicate host patterns are rejected on the same endpoint, not across ports. One bind address per HTTPS port and one plain HTTP listener are supported. With multiple HTTPS ports, automatic HTTP redirects only target sites on the configured default HTTPS endpoint; a secondary-only host is not redirected to a private port.
- In Caddyfile syntax, `root` sets a directory but does not serve it on its own: add `file_server`. In the legacy JSON site format, `root` still enables static serving.
- The proxy's `request_timeout` limits the wait for origin headers while upload progress is idle, then the pause between response frames. An active upload can take longer than this setting. Before origin headers, an idle timeout produces `504`; after headers it ends the response stream.
- On Unix, send `SIGUSR1` to reload configuration and imported files (`docker compose kill -s SIGUSR1 raddy`). If the reload fails, the old configuration remains active. Established TCP, TLS passthrough, and WebSocket tunnels are preserved during reload.
- On `SIGTERM` or `SIGINT`, Raddy stops accepting new connections and gives active traffic up to 30 seconds to finish by default. Use `run --grace-period-secs` to adjust this and give the container a longer `stop_grace_period`.
- The global `max_connections` option limits accepted client TCP connections across ports (`0` disables the limit). It does not limit HTTP/2 streams or account for upstream file descriptors. Set host file-descriptor limits and load-test with your expected workload.
- Static files support conditional requests and single byte ranges. On Unix, file cache entries can hold file bodies up to 16 KiB; the default cache stores up to 1,024 entries, with a 30-second TTL. Small files can stay cached after replacement or deletion until that TTL expires. Large files are streamed. To reopen paths for every request, set `static_cache_ttl 0s` in the global block.
- Keep production configuration, tokens, certificates, and ACME storage outside your static file root. Without a trusted PROXY protocol listener, Raddy uses the immediate peer address for `X-Forwarded-For`, not a chain supplied by the client.

## Validation and tests

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
python3 tests/network.py target/release/raddy
python3 -B tests/http_proxy.py target/release/raddy
# With Caddy 2.10.2 on PATH:
python3 tests/caddy_parity.py target/release/raddy
```

## Compatibility

Raddy supports common Caddyfile directives including `respond`, `reverse_proxy`, `root`, `file_server`, `handle`, `handle_path`, `route`, `rewrite`, `try_files`, `header`, and `import`, but their full Caddy semantics are not guaranteed. Unsupported directives are rejected at configuration time. There is no Caddy admin API, plugin loading, HTTP/3, UDP proxying, `file_server browse`, internal or on-demand TLS, or ACME HTTP-01/TLS-ALPN-01. WebSocket upgrades use HTTP/1.1; extended CONNECT over HTTP/2 is not supported. See the [detailed compatibility notes](CONFIGURATION.ru.md#границы-совместимости).
