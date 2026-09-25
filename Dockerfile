FROM rust:1.98.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY build.rs ./
COPY proto ./proto
RUN cargo test --locked && cargo build --release --locked
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --create-home oknef
COPY --from=build /build/target/release/oknef-back /usr/local/bin/oknef-back
USER 10001
WORKDIR /home/oknef
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/local/bin/oknef-back"]
