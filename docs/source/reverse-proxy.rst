SCION HTTP Reverse Proxy
========================

The SCION HTTP Reverse Proxy makes HTTP(S) resources available via SCION by configuring a reverse proxy in front of them.
It is implemented as a Caddy plugin, and can be used with any compatible Caddy server version.
If you are looking for the forward proxy, see :doc:`Forward Proxy <forward-proxy>`.

Prerequisites
-------------
- A SCION-enabled host in a SCION-enabled network (see `Access and Host Configuration <https://docs.scion.org/projects/scion-applications/en/latest/applications/access.html>`_).

Installation
------------
A debian package will be made available soon.
In the meantime, you can build the plugin from source as follows:

- Download the source code from the `SCION HTTP Proxy repository <https://github.com/scionproto-contrib/http-proxy>`_.
- Build the plugin by running the following command in the root directory of the repository:

    .. code-block:: bash

        go build -o scion-caddy caddy/main.go

    or (if you only want to build the forward proxy):

    .. code-block:: bash

        go build -o scion-caddy reverse/main.go

- Copy the binary to ``/usr/local/bin`` or any other directory in your ``$PATH``.
- Add a data directory for the plugin to store its data:

    .. code-block:: bash

        sudo mkdir -p /usr/share/scion/caddy-scion
        sudo chown -R $USER:$USER /usr/share/scion

- Install the systemd service file by copying it to ``/etc/systemd/system`` and enabling it (you can take as a reference the file ``scion-caddy-passthrough-proxy.service`` in the `examples <https://github.com/scionproto-contrib/http-proxy/tree/main/_examples>`_ folder):

    .. code-block:: bash

        sudo cp scion-caddy-passthrough-proxy.service /etc/systemd/system/
        sudo systemctl enable scion-caddy-passthrough-proxy.service

- Start the service:

    .. code-block:: bash

        sudo systemctl start scion-caddy-passthrough-proxy.service

Build for Windows and install
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

At the moment, you can download the `latest realease <https://github.com/scionproto-contrib/http-proxy/releases>`_ available or build the plugin from source as follows:

- Download the source code from the `SCION HTTP Proxy repository <https://github.com/scionproto-contrib/http-proxy>`_.
- Build the plugin by running the following command in the root directory of the repository:

  .. code-block:: bash

    make build-windows scion-caddy

or (if you only want to build the reverse proxy)

  .. code-block:: bash

    make build-windows scion-caddy-reverse

- Ensure that you are running the scion-endhost stack as described in the `SCION documentation <https://docs.scion.org/projects/scion-applications/en/latest/applications/access.html>`_.

- Add a data directory for the plugin to store its data (in a PowerShell terminal):

  .. code-block:: bash

    mkdir -p AppData\\scion\\caddy-scion

- Modify the JSON configuration file to point to the correct paths for the plugin data directory.

If you followed the configurations in the `examples <https://github.com/scionproto-contrib/http-proxy/tree/main/_examples>`_ folder, replace ``/usr/share/scion/caddy-scion`` with ``AppData\\scion\\caddy-scion``.

- Run the binary with the configuration file:

  .. code-block:: bash

    .\\scion-caddy run -conf \\path\\to\\your\\config.json

.. warning::
  The SCION endhost stack is not officially supported on Windows, but it can be built and run with some limitations.
  Mainly, the dispatcher is not supported on Windows, but you can run SCION applications in environments that do not require the dispatcher.
  This is applicable if your network provider runs SCION version > 0.11.0, available from the `Releases <https://github.com/scionproto/scion/releases>`_.

Configuration
-------------
The SCION HTTP Reverse Proxy is configured via the Caddy JSON config. The location of the JSON config is specified in the systemd service file or when running the binary via the ``-conf`` flag.
One can enable two modes of operation: layer-5 reverse proxy and layer-4 reverse proxy (passthrough) by configuring the Caddy JSON file accordingly.

Layer-5 Reverse Proxy
~~~~~~~~~~~~~~~~~~~~~
The SCION HTTP Reverse Proxy can act as a layer-5 reverse proxy, terminating the TLS connection and forwarding the request to the backend server.
In this case, the reverse proxy must provide the expected certificate for the specified domain. It will afterwards forward the HTTP request (using whatever version of HTTP supported by the backend server) to the backend server.

.. _reverse-proxy-figure:
.. image:: img/https_combinations.png
    :alt: SCION HTTP Reverse Proxy Diagram
    :align: center

One can follow the example in the `examples <https://github.com/scionproto-contrib/http-proxy/tree/main/_examples/reverse.json>`__ to configure the reverse proxy to serve specific domains in this mode.
For more information on how to configure Caddy, see the `Caddy documentation <https://caddyserver.com/docs/json/apps/http/>`_.

Layer-4 Reverse Proxy (Passthrough)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If TLS termination option is not desirable due to the setup, the SCION HTTP Reverse Proxy can act as a layer-4 reverse proxy, forwarding the TCP connection to the backend server.
In this case, the reverse proxy will not terminate the TLS connection, but will forward the TCP connection to the backend server.

This feature is enabled via the non-standard layer-4 module (see `Caddy layer-4 documentation <https://caddyserver.com/docs/json/apps/layer4>`_).

One can follow the example in the `examples <https://github.com/scionproto-contrib/http-proxy/tree/main/_examples/caddy-scion-passthrough-scion.json.json>`__ to configure the reverse proxy to serve specific domains in this mode.
For more information on how to configure Caddy, see the `Caddy layer-4 documentation <https://caddyserver.com/docs/json/apps/layer4>`_.
