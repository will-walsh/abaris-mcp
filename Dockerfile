# Stage 1: Build
FROM golang:1.26 AS builder

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a statically linked binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /build/abaris ./cmd/abaris

# Stage 2: Minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy the binary
COPY --from=builder /build/abaris /app/abaris

# Copy the config directory (identity.yaml, routing.yaml, policies/)
COPY --from=builder /build/config /app/config

# App Runner / ECS inject PORT at runtime; default to 8080 for local runs
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/app/abaris"]
