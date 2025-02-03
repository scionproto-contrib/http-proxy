SCION HTTP Forward Proxy
========================

The SCION HTTP Forward Proxy provides access to HTTP(S) resources via SCION by using a configured proxy for all SCION-enabled domains.
It is implemented as a Caddy plugin, and can be used with any compatible Caddy server version.
If you are looking for the reverse proxy, see :doc:`Reverse Proxy <reverse-proxy>`.

Prerequisites
-------------
- A ``SCION-enabled host`` in a ``SCION-enabled network`` (see `Access and Host Configuration <https://docs.scion.org/projects/scion-applications/en/latest/applications/access.html>`_).

Installation
------------

You can install the SCION HTTP Reverse Proxy plugin either building from source or adding the plugin to an existing Caddy installation.

Add plugin to existing Caddy installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you have an existing Caddy installation, you can add the SCION HTTP Proxy plugin to it. The plugin contains both the reverse proxy (supporting the 3 flavors of HTTP) and the forward proxy.
Please visit the `Caddy SCION plugin documentation <https://caddyserver.com/docs/modules/scion>`_ for more information on how to extend Caddy with SCION.

Build for Linux
---------------

You can build the caddy server containing the SCION plugin from source as follows:

- Download the source code from the `Caddy SCION repository <https://github.com/scionproto-contrib/caddy-scion>`_.
- Build the plugin by running the following command in the root directory of the repository:

  .. code-block:: bash

    go build -o ./build/scion-caddy-forward./cmd/scion-caddy-forward

- or (if you only want to build the forward and reverse proxy)

  .. code-block:: bash

    go build -o ./build/scion-caddy ./cmd/scion-caddy

Then, you can follow the steps below to install the plugin:

- Ensure that you are running the scion-endhost stack as described in the `SCION documentation <https://docs.scion.org/projects/scion-applications/en/latest/applications/access.html>`_.

- Copy the binary to ``/usr/local/bin`` or any other directory in your ``$PATH``.

- Add a data directory for the plugin to store its data:

  .. code-block:: bash

    sudo mkdir -p /usr/share/scion/caddy-scion
    sudo chown -R $USER:$USER /usr/share/scion

- Optionally you can create a systemd service and enable it. You can use the example service file ``scion-caddy.service`` in the `examples <https://github.com/scionproto-contrib/http-proxy/tree/main/_examples>`__.
  
- You can use the ``forward.json`` file in `examples <https://github.com/scionproto-contrib/http-proxy/blob/main/_examples/scion-caddy-forward-proxy.json>`__ folder as reference configuration file.
  The configuration is passed using the ``-config`` flag when running the binary. If you created a service, move it to ``/etc/scion/`` or the path that you have configured in the systemd service file.
  
- If you are running the **forward proxy as a local proxy**, please follow the localhost configuration `instructions <#running-the-scion-http-forward-proxy-locally>`_ to integrate it with your browser.

Build for MacOS
---------------

You can build the caddy server containing the SCION plugin from source as follows:

- Download the source code from the `Caddy SCION repository <https://github.com/scionproto-contrib/caddy-scion>`_.
- Build the plugin by running the following command in the root directory of the repository:

  .. code-block:: bash

    GOOS=darwin GOARCH=amd64 go build -o ./build/scion-caddy-forward./cmd/scion-caddy-forward

- or (if you only want to build the forward and reverse proxy)

  .. code-block:: bash

    GOOS=darwin GOARCH=amd64 go build -o ./build/scion-caddy ./cmd/scion-caddy

Then, you can follow the steps below to install the plugin:

- Ensure that you are running the scion-endhost stack as described in the `SCION documentation <https://docs.scion.org/projects/scion-applications/en/latest/applications/access.html>`_.

- Apply the necessary permissions to the binary:

  .. code-block:: bash

    chmod +x scion-caddy

- Add a data directory for the plugin to store its data:

  .. code-block:: bash

    sudo mkdir -p /usr/local/scion/caddy-scion
    sudo chown -R $USER /usr/local/scion

- You can use the ``forward.json`` file in `examples <https://github.com/scionproto-contrib/http-proxy/blob/main/_examples/scion-caddy-forward-proxy.json>`__ folder as reference configuration file.
  The configuration is passed using the ``-config`` flag when running the binary.
  Next, modify the JSON configuration file to point to the correct paths for the plugin data directory. Mainly, **replace** ``/usr/share/scion/caddy-scion`` with ``/usr/local/scion/caddy-scion``.

- Run the binary with the configuration file:

  .. code-block:: bash

    ./scion-caddy -conf /path/to/your/scion-caddy-forward-proxy.json

- If you are running the **forward proxy as a local proxy**, please follow the localhost configuration `instructions <#running-the-scion-http-forward-proxy-locally>`_ to integrate it with your browser.


Build for Windows
-----------------

.. note::
  Experimental option. The SCION HTTP forward proxy has not been tested on Windows yet.

You can build the caddy server containing the SCION plugin from source as follows:

- Download the source code from the `Caddy SCION repository <https://github.com/scionproto-contrib/caddy-scion>`_.
- Build the plugin by running the following command in the root directory of the repository:

  .. code-block:: bash

    GOOS=windows GOARCH=amd64 go build -o ./build/scion-caddy-forward./cmd/scion-caddy-forward

- or (if you only want to build the forward and reverse proxy)

  .. code-block:: bash

    GOOS=windows GOARCH=amd64 go build -o ./build/scion-caddy ./cmd/scion-caddy

Then, you can follow the steps below to install the plugin:

- Ensure that you are running the scion-endhost stack as described in the `SCION documentation <https://docs.scion.org/projects/scion-applications/en/latest/applications/access.html>`_.

- Add a data directory for the plugin to store its data (in a PowerShell terminal):

  .. code-block:: bash

    mkdir -p AppData\\scion\\caddy-scion

- You can use the ``forward.json`` file in `examples <https://github.com/scionproto-contrib/http-proxy/blob/main/_examples/scion-caddy-forward-proxy.json>`__ folder as reference configuration file.
  The configuration is passed using the ``-config`` flag when running the binary.
  Next, modify the JSON configuration file to point to the correct paths for the plugin data directory. Mainly, **replace** ``/usr/share/scion/caddy-scion`` with ``C:\\Users\\<username>\\AppData\\scion\\caddy-scion``.

- Run the binary with the configuration file:

  .. code-block:: bash

    .\\scion-caddy run -conf \\path\\to\\your\\scion-caddy-forward-proxy.json

- If you are running the **forward proxy as a local proxy**, please follow the localhost configuration `instructions <#running-the-scion-http-forward-proxy-locally>`_ to integrate it with your browser.

.. warning::
  The SCION endhost stack is not officially supported on Windows, but it can be built and run with some limitations.
  Mainly, the dispatcher is not supported on Windows, but you can run SCION applications in environments that do not require the dispatcher.
  This is applicable if your network provider runs SCION version > 0.11.0, available from the `Releases <https://github.com/scionproto/scion/releases>`_.


Configuration
-------------
The SCION HTTP Forward Proxy is configured via the Caddy JSON config. The location of the JSON config is specified in the systemd service file or when running the binary via the ``-conf`` flag.

You can find examples of JSON configurations in the `examples <https://github.com/scionproto-contrib/http-proxy/tree/main/_examples>`__ folder of the repository. For more information on how to configure Caddy, see the `Caddy documentation <https://caddyserver.com/docs/json>`_.

Session Key for Cookie Storage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Our implementation uses `gorilla session <https://github.com/gorilla/sessions>` to manage session cookies.
A session key can be provided in the system environment variable ``SESSION_KEY`` to achieve persistence upon system restarts, i.e., existing session cookies
will remain valid and the user will not have to log in again. It is the responsibility of the caddy administrator to handle this key securely, i.e., rotation, authorization, etc.
If no session key is provided, a random key will be generated upon each restart.

You may need to restart the service after setting the environment variable.

  .. code-block:: bash

    sudo systemctl daemon-reload
    sudo systemctl restart scion-caddy-forward-proxy.service

TLS Certificates
~~~~~~~~~~~~~~~~
The Caddy server allows for different certificates configurations that can be specified in the JSON configuration.
For more information, see the `Caddy TLS configuration <https://caddyserver.com/docs/json/apps/tls>`_ and `Caddy PKI configuration <https://caddyserver.com/docs/json/apps/pki/>`_.

Running the SCION HTTP Forward Proxy locally
--------------------------------------------
End users can run the SCION HTTP Forward Proxy locally by following the installation steps above.
To ensure interoperability with their browser navigation, the user is required to add an entry to resolve the configured name for the forward proxy to the local IP address, e.g., by adding the following line to the ``/etc/hosts`` file:

  .. code-block:: bash

    127.0.0.1 forward-proxy.scion

Most browsers or HTTPS clients will not trust the self-signed certificate used by the SCION HTTP Forward Proxy by default. To avoid certificate warnings, the user must either:
  - Import the root certificate use into the browser trust store. If the user has followed the installation examples in the `examples <https://github.com/scionproto-contrib/http-proxy/tree/main/_examples>`__ folder, the root certificate can be found in the ``/usr/share/scion/caddy-scion`` directory.
    For MacOS, the root certificate can be found in the ``/usr/local/scion/caddy-scion`` directory. Please, use the Keychain Access application to import the root certificate.
  - Disable certificate verification in the browser or client, e.g.:
    - Run chrome with, ``chrome --ignore-certificate-errors``
    - Use the ``--insecure`` and ``--proxy-insecure`` flag with curl, e.g.:

    .. code-block:: bash

      curl --insecure --proxy-insecure -x http://forward-proxy.scion:8080 https://www.example.org

Running the SCION HTTP Forward Proxy as in-network service
----------------------------------------------------------
The SCION HTTP Forward Proxy can be run as an in-network service out of the box.
Nonetheless, the local network administrator must:

- Implement a proper resolution for forward-proxy.scion to the IP address of the host running the SCION HTTP Forward Proxy.
  
  - This can be done by adding an entry to the local DNS server or by adding an entry to the /etc/hosts file of all the hosts in the network via some orchestrator.

- Disseminate the root certificate to all the hosts in the network.
  
  - This can be done by adding the root certificate to the trust store of all the hosts in the network or by using a configuration management tool to distribute the certificate.

.. note::
  We are working on a user-friendly solution that network operators can use as reference and implement in their networks to facilitate the deployment of the SCION HTTP Forward Proxy as an in-network service.
  Nonetheless, any solution that achieves the previous requirements is valid.

SCION address resolution
------------------------
The SCION HTTP Forward Proxy implements the following address resolution mechanism:
  - Inspect if a valid entry exists for the host name in ``etc/hosts`` and  ``/etc/scion/hosts`` file.
  - [Deprecated] Request a RAINS query for the host name. If a valid SCION address is found, it will be used.
  - Request a DNS TXT record for the host name. If a valid SCION address is found, it will be used.
  - It falls back to IPv4/6 using the default DNS mechanism for the underlay system.

For test purposes, the proxy administrator (or the user if running it locally) can add an entry to the ``/etc/scion/hosts`` file to resolve a domain to a SCION address, if no DNS TXT record is available, e.g.:

  .. code-block:: bash

    61-ffaa:0:1101,129.132.121.164 www.yourdomain.org

SCION enabled domains
--------------------------

We explained in section `SCION address resolution <#scion-address-resolution>`_ how the SCION HTTP Forward Proxy resolves SCION addresses.
The SCION-WWW ecosystem is currently spawning, this is why we provide a list of SCION-enabled domains that can be accessed through SCION.

.. note::
  We will try to keep this list updated as new domains are added to the SCION ecosystem. 
  Ideally, if you are trying to reach a SCION-enabled service, the DNS mechanism should do the job transparently.
  Otherwise, we provide some mappings that you can manually add to your ``/etc/scion/hosts`` file.

SCION production network
~~~~~~~~~~~~~~~~~~~~~~~~
    - https://ethz.ch

Other domains are also accessible:
    - https://www.ovgu.de
    - https://dfw.source.kernel.org
    - https://ucdb.br

If you are a regular user using an in-network proxy, you do not have to worry about the information below.

If you are running your own local proxy or you are the administrator for the in-network proxy, the domains have to be manually configured in the ``/etc/scion/hosts`` file:

  .. code-block:: bash

    71-2:0:4a,[141.44.25.151] ovgu.de www.ovgu.de
    71-2:0:48,[127.0.0.1]	dfw.source.kernel.org
    71-2:0:5c,[127.0.0.1]	ucdb.br

SCIONLab network
~~~~~~~~~~~~~~~~
    - https://www.scionlab.org
    - http://www.scion-architecture.net
    - https://www.netsys.ovgu.de
