# Local dev image for the core service (build context: the repository root).
# `docker compose -f infra/compose/compose.yaml build core`
FROM rust:1.100.0-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p ls-core-service --bin locksmith-core

FROM debian:bookworm-slim
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN useradd --system --uid 10001 core
COPY --from=build /src/target/release/locksmith-core /usr/local/bin/locksmith-core
USER core
ENTRYPOINT ["/usr/local/bin/locksmith-core"]
