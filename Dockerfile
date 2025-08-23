# Multi-stage Dockerfile for building OxideDB for Linux
FROM rust:1.82-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/src/oxidedb

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false oxidedb

# Create data directory
RUN mkdir -p /data && chown oxidedb:oxidedb /data

# Copy binary from builder stage
COPY --from=builder /usr/src/oxidedb/target/release/oxidedb /usr/local/bin/oxidedb

# Set proper permissions
RUN chmod +x /usr/local/bin/oxidedb

# Switch to app user
USER oxidedb

# Set working directory
WORKDIR /app

# Create data directory
VOLUME ["/data"]

# Expose port
EXPOSE 3030

# Set environment variables
ENV RUST_LOG=info
ENV DATABASE_PATH=/data

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:11597/health || exit 1

# Run the application
CMD ["/usr/local/bin/oxidedb"]
