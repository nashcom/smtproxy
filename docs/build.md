# Building the Container Image

## TL;DR

Run the default build:

`./build.sh`

Use additional options for alternative images:

`./build.sh -wolfi`  
`./build.sh -static`

---

# Overview

This project provides multiple Docker build variants.
Each variant uses a **multi-stage build**:

1. A **Go builder image** compiles the application.
2. The compiled binary is copied into a **minimal runtime image**.

This approach significantly reduces the final image size and attack surface.

---

# Available Build Variants

| Variant              | Dockerfile          | Builder Image                  | Runtime Image                      | Description                                                             |
| -------------------- | ------------------- | ------------------------------ | ---------------------------------- | ----------------------------------------------------------------------- |
| **Alpine (default)** | `Dockerfile`        | `golang:alpine`                | `alpine:latest`                    | Standard and widely compatible image with a small footprint.            |
| **Wolfi**            | `dockerfile_wolfi`  | `cgr.dev/chainguard/go:latest` | `cgr.dev/chainguard/wolfi-base`    | Uses Chainguard’s Wolfi images optimized for security and minimal CVEs. |
| **Static**           | `dockerfile_static` | `cgr.dev/chainguard/go:latest` | `cgr.dev/chainguard/static:latest` | Very small runtime image using a statically linked binary.              |


# Choosing the Right Variant

| Use Case                          | Recommended Variant |
| --------------------------------- | ------------------- |
| Maximum compatibility             | **Alpine**          |
| Security-focused environments     | **Wolfi**           |
| Smallest possible container image | **Static**          |


# Build Script

The project includes a helper script:

```
build.sh
```

The script builds the container image and selects the appropriate Dockerfile.


# Build Commands

## Default Build (Alpine)

Builds the standard Alpine-based image.

```bash
./build
```

## Wolfi Image

Builds the image using Chainguard's Wolfi base image.

```bash
./build -wolfi
```


## Static Image

Builds a minimal image containing only the statically linked binary.

```bash
./build -static
```


# Notes

* All builds use **multi-stage Docker builds**.
* Only the compiled binary is copied into the runtime image.
* The final container images contain **no build tooling or source code**.
