# TLS/SSL certificate and key directory

This directory contains certificates and keys.
Usually on Kubernetes a secret is used.
On Docker this directory is mounted into `/tls` to provide a similar experience.
The location of certificates can be changed with environment variables.


## Default file names

The default names are:

- tls.crt
- tls.key


