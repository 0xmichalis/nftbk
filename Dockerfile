# Builder stage
FROM docker.io/library/debian:bookworm-slim AS builder

WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config=* \
    libssl-dev=* \
    git=* \
    curl=* \
    ca-certificates=* \
    build-essential=* && \
    rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --default-toolchain none --profile minimal

ARG GIT_COMMIT
ENV GIT_COMMIT=${GIT_COMMIT}

COPY rust-toolchain.toml ./
RUN rustup show active-toolchain || rustup toolchain install

COPY . .

RUN cargo build --release --bin nftbk-server


# Runtime stage
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/nftbk-server /app/nftbk-server

CMD ["/app/nftbk-server", "--listen-address", "0.0.0.0:8080"]
