FROM rust:1.92-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang gawk make pkg-config protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p mithril-node -p mithril-control

FROM debian:bookworm-slim AS node
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/mithril-node /usr/local/bin/mithril-node
ENTRYPOINT ["/usr/local/bin/mithril-node"]
CMD ["--config", "/etc/mithril/node.json"]

FROM debian:bookworm-slim AS control
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/mithril-control /usr/local/bin/mithril-control
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mithril-control"]
CMD ["--config", "/etc/mithril/control.json"]
