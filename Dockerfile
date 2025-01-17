# PostHawk - Precision Email Validation Service
# Version: 1.0.0

# Build stage
FROM golang:1.21-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git ca-certificates tzdata gcc libc-dev

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -tags netgo \
    -o email-validator

# Final stage
FROM scratch

# Import from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/email-validator /email-validator

# Create non-root user
USER 65532:65532

# Expose port
EXPOSE 8080

# Set environment variables
ENV PORT=8080 \
    RATE_LIMIT=5 \
    RATE_BURST=10 \
    SMTP_TIMEOUT=10 \
    LOG_LEVEL=info \
    CHECK_DISPOSABLE=true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/email-validator", "-health-check"]

# Set entrypoint
ENTRYPOINT ["/email-validator"]