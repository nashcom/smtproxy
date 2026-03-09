# ---- Build stage ----

FROM golang:alpine AS builder
WORKDIR /app
# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.gBuildPlatform=alpine" -o smtproxy

# ---- Runtime image ----

FROM alpine

RUN apk add --no-cache ca-certificates libcap

# Copy binary
COPY --from=builder /app/smtproxy /usr/local/bin/smtproxy

# Allow to bind to ports below 1024
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/smtproxy && mkdir /tls && chown 1000 /tls

USER 1000
EXPOSE 25 465 1025 1465

ENTRYPOINT ["/usr/local/bin/smtproxy"]
