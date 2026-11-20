# Raddy

Raddy is an early-stage Rust reverse proxy and static file server. It supports HTTP/1.1, HTTP/2, WebSocket, gRPC upstreams over h2c, automatic TLS via Cloudflare DNS-01, and TCP/TLS passthrough. HTTPS termination and TLS passthrough can share a port and select routes by SNI. PROXY protocol v1/v2 is opt-in.

Raddy supports a subset of the Caddyfile format. It is not a drop-in replacement for Caddy and cannot load Caddy plugins. See the [compatibility notes](README.md#границы-совместимости) for current limits.

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

In another terminal, run `curl -fsS http://127.0.0.1:8080/`. The response body is `OK`.

Build the container locally with `docker build -t raddy:local .`. The Docker entrypoint loads `/etc/raddy/Raddyfile`; mount the configuration there and persist `/data`. When a release is published, Linux amd64 and arm64 container archives will be available in the Releases section. GHCR package visibility is managed separately.

## Deploy responsibly

Keep production configuration, DNS credentials, certificates, and ACME storage outside the public repository and outside your static file root. For Cloudflare DNS-01, use a scoped token with Zone Read and DNS Edit and pass it as `CF_API_TOKEN`. Configure host file-descriptor limits and load-test before exposing a busy service. See the [nginx benchmark and methodology](README.md#производительность) for measured results and their limits.

Rust checks: `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo test --locked --all-targets`. With Caddy 2.10.2 on `PATH`, compare the HTTP routing fixtures using `python3 tests/caddy_parity.py target/release/raddy`.

Licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) and the [security reporting policy](SECURITY.md). Full documentation: [Русский](README.md).
