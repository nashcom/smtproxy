
# SMTP TLS Proxy

[![HCL Ambassador](https://img.shields.io/static/v1?label=HCL&message=Ambassador&color=006CB7&labelColor=DDDDDD&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMjYuMjQgODYuMjgiPjxkZWZzPjxzdHlsZT4uY2xzLTF7ZmlsbDojMDA2Y2I3O308L3N0eWxlPjwvZGVmcz48ZyBpZD0iTGF5ZXJfMiIgZGF0YS1uYW1lPSJMYXllciAyIj48ZyBpZD0iRWJlbmVfMSIgZGF0YS1uYW1lPSJFYmVuZSAxIj48cG9seWdvbiBjbGFzcz0iY2xzLTEiIHBvaW50cz0iMTI2LjI0IDQzLjE0IDkxLjY4IDQzLjE0IDcyLjIgODYuMjggMTA2Ljc2IDg2LjI4IDEyNi4yNCA0My4xNCIvPjxwb2x5Z29uIGNsYXNzPSJjbHMtMSIgcG9pbnRzPSIwIDQzLjE0IDM0LjU2IDQzLjE0IDU0LjA0IDg2LjI4IDE5LjQ4IDg2LjI4IDAgNDMuMTQiLz48cG9seWdvbiBjbGFzcz0iY2xzLTEiIHBvaW50cz0iNjMuMTIgMCA0My42NCA0My4xNCA2My4xMiA4Ni4yOCA4Mi42IDQzLjE0IDYzLjEyIDAiLz48L2c+PC9nPjwvc3ZnPg==)](https://www.hcl-software.com/about/hcl-ambassadors)
[![Nash!Com Blog](https://img.shields.io/badge/Blog-Nash!Com-blue)](https://blog.nashcom.de)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/nashcom/buil-test/blob/main/LICENSE)


This project implements a lightweight **SMTP proxy with STARTTLS and Implicit TLS support**.
It sits between SMTP clients and one or more upstream mail servers and adds features such as TLS enforcement, routing, and connection logging.  
The proxy is designed to be **simple, fast, and container-friendly**, making it suitable for modern deployments such as Kubernetes (K8s) environments.


# Main functionality and benefits

## Provides up to date TLS version and cipher support (TLS 1.3)

The application can be built with the latest version of Go.
Go supports TLS 1.3 and a current set of ciphers.
It also supports the first [Post-Quantum Cryptography](https://www.nist.gov/pqc) algorithm.


## Implements STARTTLS and Implicit TLS for SMTP load-balancing with flexible configuration

There are basically two scenarios:

* For incoming SMTP connections, multiple back-end servers can be configured to deliver messages to the available servers.
* For outgoing SMTP connections to a relay host.

Both use cases require a separate instance either for incoming or outgoing SMTP connections.


## Uses XCLIENT command to provide information about original IP address and Remote host (IN-ARPA address) resolution

A normal SMTP load balancer would usually hide the original IP address and hostname and instead show the load balancer's IP address.
**smtproxy** can signal the original IP address via the XCLIENT command in the incoming SMTP stream.

Example:

```text
XCLIENT ADDR=79.194.3.107 NAME=p4fc2036b.dip0.t-ipconnect.de TLSVERSION=TLS1.3 TLSCIPHER=TLS_AES_128_GCM_SHA256 TLSCURVE=X25519
```


## DNS reverse lookup with separate cache and DNS server configuration

DNS lookup performance is important for high-volume transmissions.
In addition, administrators might want to configure DNS servers independently from the OS-level DNS configuration.

The SMTP Proxy provides its own DNS cache and a separate DNS configuration.


## Support for RSA and ECDSA certificates and ciphers in parallel

The proxy supports multiple certificates which allow RSA and ECDSA cryptography in parallel.
Most SMTP servers still use RSA today, especially when supporting TLS 1.2 clients and ensuring the TLS handshake behaves correctly.
Supporting RSA and ECDSA has been improved in TLS 1.3. Therefore, providing TLS 1.3 support becomes important for modern SMTP connections.


## Automatic certificate update

Certificates and keys are provided in PEM format and are read from a specified directory on disk (default: **/tls**).
The SMTP Proxy checks the directory for changed and new certificates and keys and updates the configuration on demand without requiring a restart.


## TLS session resumption

Especially for servers with higher load, support for resuming existing TLS sessions reduces the overhead of the TLS handshake.


## Provides detailed logging and TLS enforcement

The SMTP Proxy comes with very flexible and detailed logging, which includes TLS version, cipher, and CurveID.
In addition, it can be configured to only allow TLS encrypted sessions.

Example:

```
INFO: Session Summary | Duration 0.27s | C->U 656B | U->C 462B | Avg 0.00 MB/s | Client [127.0.0.1] (STARTTLS TLS1.3 TLS_AES_128_GCM_SHA256 new) -> Upstream [127.0.0.1:25] (STARTTLS TLS1.2 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 new) Status: [OK]
```

The project also provides very detailed logging and debugging.
See this [[example log document]](docs/smtproxy_log_example.md) for details.


## Prometheus compatible /metrics endpoint

Detailed statistics for SMTP sessions, DNS lookups, configuration issues, and data transferred.
It provides a modern observability endpoint.


# SMTP Proxy -- NOT A RELAY HOST!

The project implements an SMTP Proxy only. It is not intended to replace existing relay hosts like a Postfix server.

It does not contain any logic to dispatch messages to different servers.
Instead, it is explicitly designed to sit between the SMTP mail server and a relay host to secure the connection and provide high availability.

The container can sit in front of a HCL Domino server and also in front of any SMTP appliance or other relay host.


# Environment variables

Because the application is intended to run containerized the configuration leverages environment variables.  
Environment variables, their short description and their default and current value are printed at startup.

The output contains the variable name, description, default value and current value.
See the [Environment variables](docs/environment_variables.md) table for details.


# Pull the container images

The container image can be pulled from GitHub registry:

```
docker pull ghcr.io/nashcom/smtproxy:latest
```


# Build the container image

The image can be also build on Docker. The project contains a build script including alternate build options.

```
/build.sh
```

This build command creates the container image using the standard Alpine build.
For additional build options check [Build alternative images](docs/build.md).


# Run on Docker

A simple way to run the Docker container is the following invocation.

```
docker run -d --name smtproxy -p 25:25 -p 465:465 -v ./tls:/tls smtproxy
```

The project also contains a helper script [smtproxctl](tools/smtproxyctl.sh) to run on Docker.
**smtproxctl** can be installed via [tools/install.sh](tools/install.sh)

There is also [docker-compose.yml](examples/docker/docker-compose.yml) file.


# Run on Kubernetes (K8s)

The container image is also designed for K8s. 
To ensure the original IP address is passed to the containers the load balancer needs to be configured to pass the original IP.
See the [Kubernetes configuration directory](examples/k8s) for details.


## TLS Keys and Certificates

The program requires at least a certificate and key which by default is expected in the `/tls`directory
For the Docker example a certificate and key are specified via volume mounts

Certificates and keys need to provided in PEM format and need to have the follwing extensions:

- `.key` Unencrypted PEM RSA or ECDSA key
- `.crt` Leaf certificate and full chain in PEM format

The `.key` and `.crt` file must match by name

### Example:

- server.key
- server.crt

If no certificate is found, a Micro CA is created and a new key and certificate is created for the server host name.
By default the certificate is a RSA key and can be optionally changed to an ECDSA key.

To generate an ECDSA key use `SMTPROXY_MICROCA_CURVE_NAME=P256`


# Logging

The application supports multiple log levels and provides a very clean and helpful log format.
See this [example log document](docs/smtproxy_log_example.md).
The log is written to STDOUT.


## Log level

There are five standard log levels from **NONE** to **DEBUG**
Th default log level is **ERROR**.


| Level   | Description |
|---------|-------------|
| NONE    | Log nothing. |
| ERROR   | Log only errors and failures. |
| INFO    | Log important connection, protocol, and TLS state changes. |
| VERBOSE | Log additional operational details useful for tracing normal flow. |
| DEBUG   | Log full debug and protocol trace output, including client/upstream command and response flow. |


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

The proxy supports :

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
This is useful when the upstream server supports XCLIENT (for example Postfix).
It allows the upstream server to see the original client IP and TLS details.


## Example:

```text
XCLIENT ADDR=79.194.3.107 NAME=p4fc2036b.dip0.t-ipconnect.de TLSVERSION=TLS1.3 TLSCIPHER=TLS_AES_128_GCM_SHA256 TLSCURVE=X25519
```

## Standard values

- ADDR
- NAME


## Additional values

The application provides additional fields, which are not part of the official standard.

- TLSVERSION
- TLSCIPHER
- TLSCURVE

SpamGeek for Domino can also leverage XCLIENT configuraitons. See [SpamGeek configuration](docs/spamgeek.md) for details.


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

