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


`smtproxy` extracts the client information and forwards it to the upstream
SMTP server (e.g. **HCL Domino**) using either:

- **XCLIENT** SMTP extension
- **SMTP headers**

This enables the backend mail server to see the **real client IP and TLS parameters**, preserving correct logging, rate limiting, and policy enforcement.


## Architecture

```
                SMTP Client
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

worker_processes  1;

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


Example debug output:

```
2026/03/12 16:29:19 [00000006 127.0.0.1] DEBUG: U<  "smtproxy-client: ip=1.2.3.4 host=mail.example.com\r\n"
2026/03/12 16:29:19 [00000006 127.0.0.1] DEBUG: U<  "smtproxy-tls: version=TLS1.3 cipher=TLS_AES_128_GCM_SHA256 curve=X25519\r\n"

```

# Metadata Forwarding

`smtproxy` can forward client metadata to the upstream SMTP server using one of two mechanisms.

## 1. XCLIENT


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


## 2. SMTP Headers


If **XCLIENT is not available**, `smtproxy` can inject metadata as headers

during message submission.

Example headers:

```
smtproxy-client: ip=203.0.113.10 host=
smtproxy-tls: version=TLS1.3 cipher=TLS_AES_128_GCM_SHA256 curve=X25519

```

These headers are inserted before the message is handed to the upstream SMTP server.


# Domino Integration

HCL Domino can consume the forwarded metadata using either:

## XCLIENT

Domino supports **XCLIENT** for trusted SMTP gateways.
This allows Domino to treat the connection as if it originated from the original client IP.
Processing **XCLIENT** commands require Nash!Com SpamGeek or other software which can intercept SMTP sessions on C-API extension manager level.

Benefits:

- correct spam filtering
- proper logging
- accurate policy enforcement


## Header Processing

If headers are used instead of XCLIENT, Domino agents or mail rules can inspect the following headers:

```
smtproxy-client
smtproxy-tls
```

These headers provide:

- original client IP
- TLS parameters
- connection metadata


This allows Domino applications or mail processing logic to make decisions

based on the real sender information.


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


# Logging

`smtproxy` logs the extracted metadata to aid debugging and auditing.

Example log:

```
DEBUG: smtproxy-client: ip=127.0.0.1
DEBUG: smtproxy-tls: version=TLS1.3 cipher=TLS_AES_128_GCM_SHA256

```

# Summary

`smtproxy` enables modern SMTP proxy deployments by preserving original client information even when connections are routed through a reverse proxy.


Key capabilities:

- PROXY protocol v1/v2 support
- extraction of client and TLS metadata
- forwarding via XCLIENT or SMTP headers

This ensures that backend SMTP servers retain full visibility into the original connection details.
