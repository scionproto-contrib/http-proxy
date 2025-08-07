# SCION-HTTP Proxy

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)
This project uses [pre-commit](https://pre-commit.com/#quick-start) hooks.

This repository contains modules that support an HTTP(S) proxy for SCION. One can build their own Go implementation or use existing
frameworks, e.g., [Caddy server to build upon](#caddy-plugins).

This project is supported by the [NGI Zero Entrust program](https://nlnet.nl/project/SCION-proxy/) established by [NLnet](https://nlnet.nl/).

## Caddy plugins

The [caddy-scion](https://github.com/scionproto-contrib/caddy-scion) repository contains an instantiation of the HTTP proxy in the form of Caddy modules. 

## User/admin setup

If you are looking to install and configure the SCION-HTTP proxy as a user or network administrator, please refer to the [HTTP Proxy Documentation](https://scion-http-proxy.readthedocs.io/en/latest/index.html).

## Developer setup

If you are looking to set up a developer environment, you can directly refer to the [Development Setup](https://scion-http-proxy.readthedocs.io/en/latest/dev_setup.html) section.

## Dependencies

This project requires a forked version of quic-go that handle PMTUD when using the SCION network. If you're using this library in your project, add the following replace directive to your go.mod:

```go
replace github.com/quic-go/quic-go => github.com/Anapaya/quic-go v0.50.1-0.20250318085304-31c2831f6fe0
```
