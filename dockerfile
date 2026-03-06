FROM golang:alpine AS builder

WORKDIR /app

# Copy go module files first (better layer caching)
COPY go.mod ./
RUN go mod download

# Copy source
COPY main.go .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o smtproxy

# ---- Runtime image ----

FROM alpine:latest

RUN apk add --no-cache openssl ca-certificates

# Copy binary
COPY --from=builder /app/smtproxy /usr/local/bin/smtproxy

USER 1000
EXPOSE 25 465 1025 1465

ENTRYPOINT ["/usr/local/bin/smtproxy"]
