# Oknef backend

Rust HTTP and WebSocket service for authenticated workspace operations. It
connects the browser and native clients to record storage and internal services.

## Setup

Use Rust/Cargo with a native build toolchain and OpenSSL development libraries.
The container build pins Rust 1.98.1. Start the configured database service and
provider services before exercising their routes.

```sh
cp .env.example .env
cargo build --locked
cargo run --locked --bin oknef-back
```

Edit `.env` before running:

- `HTTP_BIND`: local listening address. The template uses port 8080; choose an
  unused port when other projects are running.
- `DATABASE_SERVICE_URL`, `DB_SERVICE_TOKEN`: database-service endpoint and
  matching service credential.
- `AI_CORE_URL`, `AI_CORE_GRPC_URL`, `AI_CORE_TOKEN`: HTTP and gRPC core endpoints
  with their matching internal credential.
- `COVENANT_URL`, `COVENANT_TOKEN`: advisory workflow endpoint and credential.
- `PUBLIC_ORIGIN`: the exact canonical client origin, including scheme and local
  port. Use `http://localhost:3180` for that local frontend or `https://oknef.com`
  for the production frontend. Passkey registration binds to this origin's host.
- `COOKIE_SECURE`: `false` for local HTTP; `true` is required with an HTTPS origin.
- `DEMO_ENABLED`, `DEMO_EMAIL`, `DEMO_PASSWORD`: demo configuration. Set a generated
  demo credential of at least 16 characters, even when demo access is disabled.

Generate separate internal credentials of at least 32 characters and configure
matching values in their services. No provider API key belongs in this process.
The template's service hostnames require a shared container network; replace
those endpoints with reachable local URLs when running binaries directly.

## Development

```sh
cargo fmt --check
cargo test --locked
cargo build --release --locked
```

`build.rs` generates bindings from the repository-local `proto/ai.proto` using
vendored `protoc`. With the service on its template port:

```sh
curl --fail http://127.0.0.1:8080/health
python3 tests/e2e.py --base http://127.0.0.1:8080 --origin http://localhost:3180
python3 tests/websocket.py --base http://127.0.0.1:8080 --origin http://localhost:3180
```

The Python checks require running services and enabled demo access. They create
fictional test accounts and records; use a dedicated test database. The WebSocket
script uses a local HTTP endpoint. Add `--live-ai` to `tests/e2e.py` only when
configured provider requests and their usage charges are intended.

## Containers

```sh
docker build -t oknef-back:dev .
docker compose up --build
```

Build from this repository alone. Compose reads `.env`; `HOST_PORT` and
`IMAGE_TAG` control the local port mapping and image tag. Its default network
does not automatically connect separately started service projects. Compose is
for local development; production deployment uses Terraform.
