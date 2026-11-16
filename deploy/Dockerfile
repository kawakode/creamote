# Image du serveur Creamote (rendezvous + relay).
# Construction depuis la racine du dépôt :
#   docker build -f deploy/Dockerfile -t creamote-server .
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p creamote-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data creamote \
    && mkdir -p /data && chown creamote /data
COPY --from=build /src/target/release/creamote-server /usr/local/bin/creamote-server
USER creamote
VOLUME ["/data"]
EXPOSE 21400/udp 21401/tcp
ENTRYPOINT ["creamote-server", "--listen", "0.0.0.0:21400", "--data-dir", "/data", "--api-listen", "0.0.0.0:21401"]
