# Proxy Protocol Support

## Overview

`smtproxy` supports receiving client connection metadata via the
[PROXY protocol Versions 1 \& 2](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt).


This allows a reverse proxy such as **NGINX** or **HAProxy** to forward the original client IP address
and connection metadata even when the SMTP connection itself originates from a proxy.

In short:

```
SMTP client → NGINX (proxy_protocol) → smtproxy → Domino
```


`smtproxy` extracts the client information and forwards it to the upstream SMTP server

- **XCLIENT** SMTP extension

This enables the backend mail server to see the **real client IP and TLS parameters**, preserving correct logging, rate limiting, and policy enforcement.


## Architecture

```
                SMTP Client (client IP)
                     │
                     │
                     ▼
            ┌─────────────────┐
            │      NGINX      │
            │   (ProxyProto)  │
            └─────────────────┘
                     │
                     │  PROXY protocol (v1 / v2)
                     ▼
            ┌─────────────────┐
            │     smtproxy    │
            │                 │
            │  extracts:      │
            │  • client IP    │
            │  • TLS metadata │
            └─────────────────┘
                     │
                     │  SMTP + metadata
                     ▼
            ┌─────────────────┐
            │    HCL Domino   │
            │    SMTP Server  │
            └─────────────────┘
```


# Proxy Protocol

The **PROXY protocol** is a simple header sent before the application protocol (SMTP in this case). It allows a proxy to pass connection metadata such as:

- source IP
- destination IP
- source port
- destination port

Two protocol versions exist:


| Version | Description |
|---------|-------------|
| v1      | Human readable ASCII header |
| v2      | Binary protocol supporting additional metadata |


Example (v1):

```
PROXY TCP4 203.0.113.10 192.0.2.20 50000 25
````

`smtproxy` supports both **PROXY v1** and **PROXY v2**.


# NGINX Configuration Example


NGINX can forward SMTP connections using the **stream module** with

`proxy_protocol`.


Example:


```nginx

worker_processes 1;

events {
    worker_connections 1024;
}

stream {

    resolver 10.43.0.10 valid=30s ipv6=off;

    upstream backend_proxy {
        zone backend_proxy 64k;
        server smtproxy.domino.svc.cluster.local:25 resolve;
    }

    server {
        listen 25;
        proxy_pass backend_proxy;
        proxy_protocol on;
    }
}

````

This configuration ensures the **original client IP is preserved** when the

connection is forwarded to `smtproxy`.


# smtproxy Processing

When `smtproxy` receives a connection with PROXY protocol enabled it:

1. Parses the PROXY header
2. Extracts client metadata
3. Stores connection attributes
4. Forwards them to the backend SMTP server


The following metadata may be captured:

| Field       | Description                   |
| ----------- | ----------------------------- |
| client IP   | original connecting host      |
| client port | source port                   |
| TLS version | negotiated TLS protocol       |
| TLS cipher  | negotiated cipher             |
| TLS curve   | negotiated key exchange curve |


# Metadata Forwarding

`smtproxy` can forward client metadata to the upstream SMTP server using one of two mechanisms.

## XCLIENT


If the backend SMTP server supports the \**XCLIENT\** SMTP extension,
`smtproxy` injects client attributes directly into the SMTP session.


Example:

```
XCLIENT ADDR=203.0.113.10 NAME=client.example
```

Advantages:

- standardized SMTP extension
- supported by many MTAs
- avoids modifying message headers


# Domino Integration

HCL Domino can consume the forwarded metadata

## XCLIENT

Domino supports **XCLIENT** for trusted SMTP gateways.
This allows Domino to treat the connection as if it originated from the original client IP.
Processing **XCLIENT** commands require Nash!Com SpamGeek or other software which can intercept SMTP sessions on C-API extension manager level.

Benefits:

- correct spam filtering
- proper logging
- accurate policy enforcement

The PROXY protocol **must only be accepted from trusted sources**.
If exposed publicly, attackers could spoof client IP addresses.

Recommended safeguards:

- Only allow proxy connections from localhost or trusted proxies
- Restrict firewall access
- Disable PROXY protocol on public listeners


Example:

```
allow 127.0.0.1
deny all
```

# Summary

`smtproxy` enables modern SMTP proxy deployments by preserving original client information even when connections are routed through a reverse proxy.


Key capabilities:

- PROXY protocol v1/v2 support
- Extraction of client and TLS metadata
- Forwarding via XCLIENT

This ensures that backend SMTP servers retain full visibility into the original connection details.
