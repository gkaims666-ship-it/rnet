# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN go build -ldflags="-s -w" -o /rnet-relay .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN adduser -D -u 1000 relay
USER relay
COPY --from=builder /rnet-relay /usr/local/bin/rnet-relay

EXPOSE 7777/udp

ENTRYPOINT ["rnet-relay"]
CMD ["--port", "7777"]
