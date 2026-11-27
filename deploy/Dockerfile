# Vernam (VRNM) Testnet — Hardened Multi-Stage Dockerfile
# Zero external crate dependencies: builds completely offline from Cargo.toml + src/.
#
# Build from repository root:
#   docker build -f deploy/Dockerfile -t vernam-testnet:latest .
#
# Note: Edition 2024 requires Rust >= 1.85. `rust:1-slim` tracks the latest
# Rust 1.x release on Docker Hub (you can pin e.g. `rust:1.98-slim` if desired).

# -----------------------------------------------------------------------------
# Stage 1: Offline Rust Release Builder
# -----------------------------------------------------------------------------
FROM rust:1-slim AS builder

WORKDIR /build

# Copy manifest and source (zero external crates; no network fetch needed)
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

# Build optimized release binary offline and normalize name to `vrnm`
RUN cargo build --release --offline && \
    if [ -f target/release/vernam-rs ]; then \
        cp target/release/vernam-rs /tmp/vrnm; \
    else \
        cp target/release/vrnm /tmp/vrnm; \
    fi && \
    (command -v strip >/dev/null 2>&1 && strip /tmp/vrnm || true)

# -----------------------------------------------------------------------------
# Stage 2: Minimal Hardened Runtime Image
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 10001 vernam && \
    useradd --system --uid 10001 --gid vernam \
        --home-dir /var/lib/vernam \
        --shell /usr/sbin/nologin \
        --no-create-home vernam && \
    mkdir -p /var/lib/vernam && \
    chown vernam:vernam /var/lib/vernam && \
    chmod 0700 /var/lib/vernam

COPY --from=builder --chmod=0755 /tmp/vrnm /usr/local/bin/vrnm
RUN ln -s /usr/local/bin/vrnm /usr/local/bin/vernam-rs

ENV VRNM_BIND=0.0.0.0:8080 \
    VRNM_DATA_DIR=/var/lib/vernam \
    HOME=/var/lib/vernam

USER vernam:vernam
WORKDIR /var/lib/vernam

VOLUME ["/var/lib/vernam"]

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/vrnm"]
CMD ["testnet", "--bind", "0.0.0.0:8080"]
