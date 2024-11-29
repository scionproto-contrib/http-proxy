# SCION-HTTP Proxy

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)
This project uses [pre-commit](https://pre-commit.com/#quick-start) hooks.

Repository for SCION related Caddy modules for implementing a HTTP(s) proxy for SCION.

## User/admin setup

If you are looking for installing and configuring the SCION-HTTP proxy as an user or network administrator, please refer to the [HTTP Proxy Documentation](https://scion-http-proxy.readthedocs.io/en/latest/index.html)

## Developer setup

If you are looking for setting up a developer environment, you can directly refer to the [Development Setup](https://scion-http-proxy.readthedocs.io/en/latest/dev_setup.html) section.

## E2E tests

Only runnable on a SCION enabled host. Additionally the add an entry to `/etc/hosts` of the form:
 ```
 <local ISD-AS>,[<IP address use to reach SCION services>] scion.local
 ```
Where the ` <local ISD-AS>` is the ISD-AS number the host is running on. (one can verify it in the `topology.json` by default this is located under `/etc/scion`) and `<IP address use to reach SCION services>` is the local address that your host uses to reach the SCION services, i.e. SCION border router and SCION Control service. You can find out this addres by inspecting the `etc/scion/topology.json` file:
```
"control_service": {
    "cs-1": {
      "addr": "<IP address use to reach SCION services>"
    },
  }
```
and then issuing:
```
$ sudo ip route get <IP address use to reach SCION services>
```

If your SCION daemon is not listening on the default address i.e. `127.0.0.1:30255`, provide the actual address as a flag to the test.

```bash
go test \
  -timeout 30s \
  -tags=e2e \
  -v \
  -run .\* github.com/scionassociation/http-proxy/test \
  -sciond-address 127.0.0.1:30255
```
