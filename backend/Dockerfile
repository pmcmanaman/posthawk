# Go backend Dockerfile
FROM golang:1.21-alpine

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source and data files
COPY backend/ ./backend
COPY disposable_domains.txt ./

# Build
RUN go build -o main ./backend/main.go

EXPOSE 8080

CMD ["./main"]
