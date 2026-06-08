FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /kalki-proxy ./cmd/kalki-proxy/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /kalki-proxy /usr/local/bin/kalki-proxy
EXPOSE 8080 9090
ENTRYPOINT ["kalki-proxy"]
