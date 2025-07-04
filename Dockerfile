# Builder stage
FROM docker.io/library/rust:1.86-slim-bookworm as builder

WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy the entire project
COPY . .

# Build the release binary
RUN cargo build --release --bin nftbk-server

# Runtime stage
FROM gcr.io/distroless/cc-debian12

WORKDIR /app

# Copy all necessary files
COPY --from=builder /usr/src/app/target/release/nftbk-server /app/nftbk-server
COPY config_chains.toml /app/config_chains.toml

# Expose the port your server listens on (adjust if needed)
EXPOSE 8080

# Run as non-root user for security
USER nonroot:nonroot

CMD ["/app/nftbk-server", "--listen-address", "0.0.0.0:8080"]
