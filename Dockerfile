FROM golang:1.25 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/agentspy ./cmd/agentspy

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/agentspy /usr/local/bin/agentspy
COPY config.yaml /app/config.yaml

ENTRYPOINT ["/usr/local/bin/agentspy"]
CMD ["-config", "/app/config.yaml"]
