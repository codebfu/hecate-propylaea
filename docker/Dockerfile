# syntax=docker/dockerfile:1
# Build from the parent directory that contains both `hecate/` and `hecate-propylaea/`:
#   docker build -f hecate-propylaea/docker/Dockerfile -t hecate-propylaea .

ARG PROPYLAEA_VERSION=0.1.0

FROM rust:1.93-bookworm AS rust
ARG PROPYLAEA_VERSION
WORKDIR /src

# Minimal hecate workspace so hecate-protocol (workspace package) resolves.
COPY hecate/crates/protocol /src/hecate/crates/protocol
RUN printf '%s\n' \
  '[workspace]' \
  'resolver = "2"' \
  'members = ["crates/protocol"]' \
  '' \
  '[workspace.package]' \
  "version = \"${PROPYLAEA_VERSION}\"" \
  'edition = "2024"' \
  'license = "MIT"' \
  'authors = ["Hecate Contributors"]' \
  '' \
  '[workspace.dependencies]' \
  'serde = { version = "1", features = ["derive"] }' \
  'serde_json = "1"' \
  'uuid = { version = "1", features = ["serde", "v4"] }' \
  'chrono = { version = "0.4", features = ["serde"] }' \
  'thiserror = "2"' \
  > /src/hecate/Cargo.toml

COPY hecate-propylaea/Cargo.toml hecate-propylaea/Cargo.lock* /src/hecate-propylaea/
COPY hecate-propylaea/crates /src/hecate-propylaea/crates

WORKDIR /src/hecate-propylaea
RUN sed -i "s/^version = \".*\"/version = \"${PROPYLAEA_VERSION}\"/" Cargo.toml \
    && cargo build --release -p hecate-propylaea

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 propylaea \
    && useradd -u 1000 -g propylaea -m -s /usr/sbin/nologin propylaea \
    && mkdir -p /var/lib/hecate-propylaea \
    && chown -R propylaea:propylaea /var/lib/hecate-propylaea
COPY --from=rust /src/hecate-propylaea/target/release/hecate-propylaea /usr/local/bin/hecate-propylaea
USER propylaea
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hecate-propylaea"]
