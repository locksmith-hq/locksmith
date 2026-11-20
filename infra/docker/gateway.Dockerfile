# syntax=docker/dockerfile:1
# gateway image (AGPL-3.0 server component). Build from the repo root:
#   docker build -f infra/docker/gateway.Dockerfile -t locksmith-gateway .
FROM rust:1.100.0-slim-bookworm AS build
WORKDIR /src
# The base image already has this toolchain; this stops rust-toolchain.toml from fetching components.
ENV RUSTUP_TOOLCHAIN=1.100.0
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    --mount=type=secret,id=cabundle,required=false \
    if [ -f /run/secrets/cabundle ]; then export CARGO_HTTP_CAINFO=/run/secrets/cabundle; fi; \
    cargo build --release --locked -p ls-gateway \
    && install -D target/release/locksmith-gateway /out/locksmith-gateway

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="locksmith-gateway" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/locksmith-hq/locksmith"
# No package install: neither service links OpenSSL (rustls); CA certificates come from the build stage.
COPY --from=build /etc/ssl/certs /etc/ssl/certs
RUN echo 'locksmith:x:10001:10001::/nonexistent:/usr/sbin/nologin' >> /etc/passwd \
    && echo 'locksmith:x:10001:' >> /etc/group
COPY --from=build /out/locksmith-gateway /usr/local/bin/locksmith-gateway
COPY LICENSE /licenses/LICENSE
COPY LICENSE-APACHE /licenses/LICENSE-APACHE
ENV LOCKSMITH_GATEWAY_BIND=0.0.0.0:8090
USER 10001
EXPOSE 8090
# No curl in the image: a bash TCP probe of the health endpoint.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD ["bash","-c","exec 3<>/dev/tcp/127.0.0.1/8090 && printf 'GET /healthz HTTP/1.0\\r\\n\\r\\n' >&3 && head -n1 <&3 | grep -q ' 200 '"]
ENTRYPOINT ["/usr/local/bin/locksmith-gateway"]
