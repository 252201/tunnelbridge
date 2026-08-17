# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim AS web
RUN corepack enable
WORKDIR /src
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/api-types/package.json packages/api-types/index.ts packages/api-types/
COPY web/admin/package.json web/admin/
RUN pnpm install --frozen-lockfile
COPY web/admin web/admin
RUN pnpm --filter @tunnelbridge/admin build

FROM rust:1.94-bookworm AS rust
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/protocol crates/protocol
COPY server server
COPY desktop/src-tauri/Cargo.toml desktop/src-tauri/Cargo.toml
COPY desktop/src-tauri/build.rs desktop/src-tauri/build.rs
COPY desktop/src-tauri/src desktop/src-tauri/src
RUN cargo build --release -p tunnelbridge-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home tunnelbridge \
    && mkdir -p /app/data /app/admin \
    && chown -R tunnelbridge:tunnelbridge /app
WORKDIR /app
COPY --from=rust /src/target/release/tunnelbridge-server /usr/local/bin/tunnelbridge-server
COPY --from=web /src/web/admin/dist /app/admin
USER tunnelbridge
ENV TB_LISTEN_ADDR=0.0.0.0:8080 \
    TB_DATABASE_URL=sqlite:///app/data/tunnelbridge.db?mode=rwc \
    TB_ADMIN_DIST=/app/admin \
    TB_PORT_START=20000 \
    TB_PORT_END=20100 \
    RUST_LOG=tunnelbridge_server=info
EXPOSE 8080 20000-20100
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD curl -fsS http://127.0.0.1:8080/readyz || exit 1
ENTRYPOINT ["tunnelbridge-server"]
