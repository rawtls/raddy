# syntax=docker/dockerfile:1
FROM rust:1.94.0-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcap2-bin \
    && groupadd --gid 10001 raddy \
    && useradd --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin raddy \
    && install -d -o raddy -g raddy -m 0700 /data \
    && install -d -m 0755 /etc/raddy \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/raddy /usr/local/bin/raddy
RUN setcap cap_net_bind_service=+ep /usr/local/bin/raddy
LABEL org.opencontainers.image.description="Raddy HTTP(S) and TCP reverse proxy"
EXPOSE 80/tcp 443/tcp
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/raddy", "--config", "/etc/raddy/Raddyfile"]
CMD ["run"]
