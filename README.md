
# SMTP TLS Proxy

This program implements a lightweight **SMTP proxy with STARTTLS and Implicit TLS support**.
It sits between SMTP clients and one or more upstream mail servers and adds features such as TLS enforcement, routing, and connection logging.  
The proxy is designed to be **simple, fast, and container-friendly**, making it suitable for modern deployments such as Kubernetes (K8s) environments.


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
**smtproxctl** can be installed via [install_smtproxctl.sh](tools/install_smtproxctl.sh)

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
See this [example log document](docs/smtproxy_log_example.md)
The log is written to STDOUT.


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

