# SCION-HTTP Proxy

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)
This project uses [pre-commit](https://pre-commit.com/#quick-start) hooks.

This repository contains modules that support an HTTP(S) proxy for SCION. One can build their own Go implementation or use existing
frameworks, e.g., [Caddy server to build upon](#caddy-plugins).

## Caddy plugins

The [caddy-scion](https://github.com/scionproto-contrib/caddy-scion) repository contains an instantiation of the HTTP proxy in the form of Caddy modules. 

## User/admin setup

If you are looking to install and configure the SCION-HTTP proxy as a user or network administrator, please refer to the [HTTP Proxy Documentation](https://scion-http-proxy.readthedocs.io/en/latest/index.html).

## Developer setup

If you are looking to set up a developer environment, you can directly refer to the [Development Setup](https://scion-http-proxy.readthedocs.io/en/latest/dev_setup.html) section.