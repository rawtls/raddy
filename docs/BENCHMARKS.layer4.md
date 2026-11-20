# TCP and TLS passthrough benchmarks

[Home](../README.md) · [HTTP/HTTPS benchmarks](BENCHMARKS.md) · [Raw Layer 4 results](benchmarks/layer4-results.jsonl)

The proxies forward bytes; they do not act as HTTP servers in this test. The TLS passthrough listener selects an upstream by SNI, then forwards the untouched TLS session. TLS terminates at the same nginx origin for every proxy.

![TCP relay and TLS passthrough throughput comparison (requests per second)](benchmarks/layer4-throughput.svg)

![TCP relay and TLS passthrough tail latency comparison (p99)](benchmarks/layer4-latency-p99.svg)

Each panel has its own scale and starts at zero. The throughput numbers are application requests per second, not connections per second or bulk throughput in Gbit/s.

| Workload | Raddy | Caddy + caddy-l4 | nginx stream |
| --- | ---: | ---: | ---: |
| TCP relay, keep-alive | 148,427 · 0.32 ms | 126,901 · 0.48 ms | 149,670 · 0.32 ms |
| TCP relay, new connection per request | 27,955 · 1.75 ms | 14,589 · 4.88 ms | 34,688 · 1.47 ms |
| TLS passthrough, keep-alive | 90,803 · 0.56 ms | 92,287 · 0.52 ms | 93,202 · 0.49 ms |
| TLS passthrough, new connection per request | 1,730 · 5.91 ms | 1,716 · 6.07 ms | 1,740 · 6.00 ms |

Values are median requests per second and median p99 response latency. `wrk` reported no errors in 36 measured runs. Raddy and nginx were within 1% on TCP keep-alive; nginx had the highest throughput on TCP reconnect. All three were within 3% on each TLS passthrough workload, where they shared the same TLS origin.

## Method

- Raddy `v0.3.0` release binary (checked against the release SHA-256), nginx `1.26.3` with the matching Debian `ngx_stream_module`, and a separate Caddy `2.11.4` build with `caddy-l4 v0.1.2` (xcaddy `0.4.7`, Go `1.25.12`). The standard Caddy binary used for the HTTP comparison does not have the Layer 4 module.
- Debian 13 x86_64 with four QEMU vCPUs. The proxy, `wrk`, and nginx origin each ran on a separate vCPU. nginx used one worker; Raddy used `TOKIO_WORKER_THREADS=1`, and Caddy used `GOMAXPROCS=1`.
- `wrk` sent HTTP/1.1 requests for a 1 KiB file through each proxy, with 32 concurrent connections and three eight-second runs after a two-second warm-up. Separate ports were used for raw TCP and TLS passthrough. PROXY protocol was not used.
- For TLS, the client sent SNI `localhost` and the origin used TLS 1.3 and an ECDSA P-256 certificate, without a session cache or tickets. Each proxy was checked for successful forwarding of that SNI and rejection of an unmatched name. Reconnect sends `Connection: close` on each request; throughput includes connection setup, but the `wrk` p99 column does not measure the full TCP/TLS handshake.

This loopback microbenchmark does not measure real Xray/VLESS sessions, bulk transfer bandwidth, or long-running tunnel capacity. The common origin and client can also limit the results.

## Reproduce it

Use the tools listed in the [HTTP/HTTPS benchmark](BENCHMARKS.md#reproduce-it) and an nginx stream module matching the nginx binary. Build Caddy with [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build v2.11.4 --with github.com/mholt/caddy-l4@v0.1.2 --output ./caddy-l4
mkdir -p target/benchmark-charts
python3 tests/benchmark.py target/release/raddy --layer4 \
  --caddy ./caddy-l4 --nginx /usr/sbin/nginx \
  --nginx-stream-module /usr/lib/nginx/modules/ngx_stream_module.so \
  > target/layer4-results.jsonl
python3 tests/benchmark_charts.py target/layer4-results.jsonl target/benchmark-charts --layer4
```
