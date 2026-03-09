
# SMTP TLS Proxy

This program implements a lightweight **SMTP proxy with STARTTLS and Implicit TLS support**.
It sits between SMTP clients and one or more upstream mail servers and adds features such as TLS enforcement, routing, and connection logging.  
The proxy is designed to be **simple, fast, and container-friendly**, making it suitable for modern deployments such as Kubernetes (K8s) environments.


# Environment variables

Because the application is intended to run containerized the configuration leverages environment variables.  
Environment variables, their short description and their default and current value are printed at startup.

Copy the `env_template` int `.env` and customize the value to pass them to the container at startup.


```

Variable                            Description                        Default                         Current
--------------------------------------------------------------------------------------------------------------------------------------------
SMTPROXY_SERVER_NAME                Server name                        <OS Hostname>                   mailprox.example.com
SMTPROXY_LISTEN_ADDR                STARTTLS listen address            :25                             :25
SMTPROXY_TLS_LISTEN_ADDR            TLS      listen address            :465                            :465
SMTPROXY_METRICS_LISTEN_ADDR        Metrics  listen address            :9100                           :9100
SMTPROXY_ROUTING_MODE               Routing mode                       local-first                     local-first
SMTPROXY_LOCAL_UPSTREAMS            Local  upstreams                   :25                             [mail.example.com:25]
SMTPROXY_REMOTE_UPSTREAMS           Remote upstreams                   []                              []
SMTPROXY_DNS_SERVERS                DNS Servers                        []                              [1.2.3.4]
SMTPROXY_REQUIRE_TLS                Require TLS                        true                            true
SMTPROXY_UPSTREAM_STARTTLS          Upstream use STARTTLS              true                            true
SMTPROXY_UPSTREAM_REQUIRE_TLS       Upstream requires TLS              true                            true
SMTPROXY_UPSTREAM_TLS               Upstream implicit TLS              false                           false
SMTPROXY_TLS13_ONLY                 TLS13 only                         false                           false
SMTPROXY_UPSTREAM_TLS13_ONLY        Upstream TLS13 only                false                           false
SMTPROXY_SKIP_CERT_VALIDATION       Skip cert validation               false                           false
SMTPROXY_SEND_XCLIENT               XCLIENT to signal IP               false                           false
SMTPROXY_MAX_CONNECTIONS            Maximum sessions                   1000                            1000
SMTPROXY_TRUSTED_ROOT_FILE          Trusted root file                  <System trust store>            []
SMTPROXY_CERT_DIR                   Certificate directory              /tls                            /tls
SMTPROXY_MICROCA_CURVE_NAME         Optional MicroCA CurveName         []                              []
SMTPROXY_CLIENT_TIMEOUT             Client timeout (sec)               120                             2m0s
SMTPROXY_SHUTDOWN_SECONDS           Max shutdown time (sec)            60                              60
SMTPROXY_CERT_UPDATE_CHECK_SECONDS  Cert Update Check (sec)            300                             300
SMTPROXY_LOGLEVEL                   Log level                          ERROR                           ERROR
SMTPROXY_HANDSHAKE_LOGLEVEL         Handshake Log level                NONE                            NONE

Routing mode values:
  [local-first|failover|loadbalance]

Log level values:
  3=NONE 4=ERROR 5=INFO 6=VERBOSE 7=DEBUG


```


# Build the container image

```
/build.sh
```

This build command creates the container image using the standard Alpine build.
For additional build options check [Build alternative images](docs/build.md).


# Run on Docker

```
docker run -d --name smtproxy -p 25:25 -p 465:465 -v ./tls:/tls smtproxy
```

## Important parameters

The program requires at least a certificate and key which by default is expected in the `/tls`directory
For the Docker example a certificate and key are specified via volume mounts

Certificates and keys need to provided in PEM format and need to have the follwing extensions:

- **.key** Unencrypted PEM RSA or ECDSA key
- **.crt** Leaf certificate and full chain in PEM format

The .key and .crt file must match by name

Example:

- server.key
- server.crt

If no certificate/key is found, a Micro CA is created and a new key and certificate is created for the server host name.
By default the certificate is a RSA key and can be optionally changed to an ECDSA key.

To generate an ECDSA key use `SMTPROXY_MICROCA_CURVE_NAME=P256`


# Logging

The application supports multiple log levels and provides a very clean and helpful log format.
See this [example log document](docs/smtproxy_log_example.md)


## Log level

There are 5 standard log levels from **NONE** to **DEBUG**

- **0**=NONE
- **1**=ERROR
- **2**=INFO
- **3**=VERBOSE
- **4**=DEBUG


# Basic Operations

The proxy accepts SMTP connections from clients, optionally upgrades them to TLS, connects to an upstream mail server, and forwards the SMTP session.

Typical flow:

```text
SMTP Client
     │
     ▼
SMTP Proxy
     │
     ▼
Upstream SMTP Server
```

The proxy can enforce TLS on both the client side and the upstream connection.


# Connection Flow

The following diagram shows a typical SMTP session handled by the proxy.

```text
        SMTP Client
             │
             │ 1. Connect
             ▼
       SMTP Proxy Listener
             │
             │ 2. Send greeting
             │
             │ 3. EHLO / HELO
             │
             │ 4. STARTTLS (optional)
             ▼
        TLS Handshake
             │
             │ 5. Connect to upstream server
             ▼
     Upstream SMTP Server
             │
             │ 6. Optional STARTTLS to upstream
             │
             │ 7. XCLIENT information (optional)
             │
             ▼
        SMTP Transaction
     (MAIL / RCPT / DATA)
             │
             ▼
      Transparent Data Tunnel
```

After the DATA command the proxy switches to a **tunnel mode** where the message data is streamed directly between the client and the upstream server.


# Listener Modes

The proxy supports two SMTP listener types.

## STARTTLS Listener

A normal SMTP listener accepts plaintext connections and supports STARTTLS.

Example:

```text
Client → SMTP → STARTTLS → TLS
```


## Implicit TLS Listener

The proxy can also listen on a port where TLS is required immediately.

Example:

```text
Client → TLS → SMTP
```

This is compatible with SMTPS clients.


# TLS Features

The proxy supports modern TLS functionality.

Supported features include:

* TLS 1.2 and TLS 1.3
* Optional TLS 1.3-only policy
* Automatic certificate selection
* RSA and ECDSA certificates
* Client and upstream TLS negotiation

Multiple certificates can be loaded so the proxy can automatically choose the best certificate depending on the client’s capabilities.


# Upstream Connections

The proxy connects to one or more upstream SMTP servers.

It supports three upstream modes:

Plain SMTP

```text
Proxy → Upstream SMTP
```

STARTTLS

```text
Proxy → EHLO → STARTTLS → TLS
```

Implicit TLS

```text
Proxy → TLS → Upstream
```

TLS verification can also be enforced using trusted root certificates.


# Routing and Failover

Multiple upstream servers can be configured.

The proxy supports three routing modes:

## Local-First

Local servers are tried first, followed by remote servers.

## Failover

If one server fails, the proxy automatically tries the next server.

## Load Balancing

Connections are distributed across servers using round-robin selection.


# Multiple key support

SMTP servers mostly use RSA keys.
But ECDSA keys are getting wider spread with TLS 1.3.
TLS 1.3 has improved support for picking the right ciphers and using the right certificates.
The SMTP proxy tries to pick the right certificates for TLS 1.2 and TLS 1.3 using a custom logic.
The handshake code iterates thru the certificates and tries to find the best match.
A separate log logic is available to log details about the handshake.


# XCLIENT Support

The proxy can optionally send **XCLIENT information** to the upstream SMTP server.

This allows the upstream server to see the original client IP and TLS details.

Example:

```text
XCLIENT ADDR=192.168.1.25 TLSVERSION=TLS1.3 TLSCIPHER=TLS_AES_256_GCM_SHA384
```

This is useful when the upstream server supports XCLIENT (for example Postfix).


# Session Logging

Each SMTP session generates a **summary log entry**.

The log contains information such as:

* client IP
* upstream server
* TLS version and cipher
* bytes transferred
* session duration
* session status

This makes it easy to analyze SMTP traffic and troubleshoot connection issues.


# Performance Characteristics

The proxy is designed to be lightweight and efficient.

Key properties include:

* streaming data forwarding
* minimal buffering
* low memory usage
* concurrent connection handling
* efficient TLS handling

Because message data is streamed directly between client and upstream server, large messages do not consume significant memory.


# Typical Use Cases

This proxy can be used for:

* enforcing TLS policies for SMTP
* adding TLS support to legacy mail servers
* routing SMTP traffic across multiple servers
* exposing SMTP services securely in container environments
* collecting session-level SMTP statistics


# Summary

This SMTP proxy provides a simple way to add modern TLS capabilities and routing to existing mail infrastructures.

Main features include:

* STARTTLS and implicit TLS support
* upstream TLS negotiation
* TLS policy enforcement
* upstream routing and failover
* XCLIENT support
* session logging

The implementation focuses on **simplicity, performance, and operational visibility**, making it suitable for both traditional and cloud-native deployments.
