# Builder stage
ARG RUST_VERSION=1.90.0
FROM docker.io/library/rust:${RUST_VERSION}-slim-bookworm AS builder

WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config=* \
    libssl-dev=* \
    git=* \
    curl=* && \
    rm -rf /var/lib/apt/lists/*

ARG GIT_COMMIT
ENV GIT_COMMIT=${GIT_COMMIT}

COPY . .

RUN cargo build --release --bin nftbk-server


# Runtime stage
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/nftbk-server /app/nftbk-server

CMD ["/app/nftbk-server", "--listen-address", "0.0.0.0:8080"]
