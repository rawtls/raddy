# Raddy

Raddy is a Rust reverse proxy and static file server. Use it to serve a site over HTTPS, proxy an app, or forward raw TCP. It can terminate HTTPS for one hostname and pass TLS through to another service on the same port.

[Русский](README.ru.md) · [Configuration](docs/CONFIGURATION.md) · [Benchmarks](docs/BENCHMARKS.md) · [Releases](https://github.com/rawtls/raddy/releases)

## Try it locally

Create a `Raddyfile` in an empty directory:

```caddyfile
:8080 {
    respond "Hello from Raddy"
}
```

Run it with Docker:

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  --mount type=bind,src="$PWD/Raddyfile",dst=/etc/raddy/Raddyfile,readonly \
  ghcr.io/rawtls/raddy:v0.3.0
```

Open `http://127.0.0.1:8080/`. You don't need a domain or a Cloudflare token for this example. [Docker Compose for Linux](docs/CONFIGURATION.md#docker-compose-linux-host-networking) shows how to deploy with persistent certificates and log rotation.

## Where to go next

- [Enable HTTPS with Cloudflare DNS-01](docs/CONFIGURATION.md#cloudflare-dns-01)
- [Set up HTTP routing, TLS passthrough, or PROXY protocol](docs/CONFIGURATION.md#routing-tls-passthrough-and-proxy-protocol)
- Compare Raddy, Caddy, and nginx: [HTTP/HTTPS](docs/BENCHMARKS.md) · [TCP/TLS passthrough](docs/BENCHMARKS.layer4.md)

Raddy is under active development. It reads a subset of Caddyfile syntax; it is [not a drop-in replacement for Caddy](docs/CONFIGURATION.md#compatibility).

[Apache-2.0](LICENSE) · [Security reporting](SECURITY.md)
