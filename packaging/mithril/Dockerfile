FROM rust:1.92-trixie AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       autoconf automake autopoint bison clang flex gawk libglib2.0-dev libostree-dev \
       libtool make pkg-config protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.lock Cargo.toml ./
COPY bpf ./bpf
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release -p mithril-node -p mithril-control \
    && cargo rustc --locked --release -p mithril-node --bin mithril-oci-hook -- -C target-feature=+crt-static \
    && install -D -m 0755 target/release/mithril-node /out/mithril-node \
    && install -D -m 0755 target/release/mithril-oci-hook /out/mithril-oci-hook \
    && install -D -m 0755 target/release/mithril-inspect /out/mithril-inspect \
    && install -D -m 0755 target/release/mithril-control /out/mithril-control \
    && install -D -m 0755 target/release/kubectl-mithril /out/kubectl-mithril

FROM debian:trixie-slim AS node
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/mithril-node /usr/local/bin/mithril-node
COPY --from=build /out/mithril-oci-hook /usr/local/bin/mithril-oci-hook
COPY --from=build /out/mithril-inspect /usr/local/bin/mithril-inspect
ENTRYPOINT ["/usr/local/bin/mithril-node"]
CMD ["--config", "/etc/mithril/node.json"]

FROM debian:trixie-slim AS control
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/mithril-control /usr/local/bin/mithril-control
COPY --from=build /out/kubectl-mithril /usr/local/bin/kubectl-mithril
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mithril-control"]
CMD ["--config", "/etc/mithril/control.json"]
