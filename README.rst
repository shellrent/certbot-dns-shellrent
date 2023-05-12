certbot-dns-shellrent
=====================

Shellrent_ DNS Authenticator plugin for Certbot_

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using the Shellrent Remote API.

.. _Shellrent: https://www.shellrent.org/
.. _Certbot: https://certbot.eff.org/

Configuration of Shellrent
---------------------------

You will need your username and an API token for filling up the .ini configuration file. To generate your token you have to log in to https://manager.shellrent.com, then go to "My Profile" in the upper right corner, on the left click on "API Key" and finally on "Generate API token".

Remember that you need to set up your authorized IP access first, from the "Profile security" menu voice. Every IP that should use certbot with this plugin need to be added to the authorized ip access list. More info: https://guide.shellrent.com/controllo-degli-accessi-tramite-ip/

Installation
------------

::

    pip install certbot-dns-shellrent


Named Arguments
---------------

To start using DNS authentication for shellrent, pass the following arguments on
certbot's command line:

============================================================= ==============================================
``--authenticator dns-shellrent``          select the authenticator plugin (Required)

``--dns-shellrent-credentials``         shellrent Remote User credentials
                                                              INI file. (Required)

``--dns-shellrent-propagation-seconds`` | waiting time for DNS to propagate before asking
                                                              | the ACME server to verify the DNS record.
                                                              | (Default: 10, Recommended: >= 600)
============================================================= ==============================================

(Note that the verbose and seemingly redundant ``certbot-dns-shellrent:`` prefix
is currently imposed by certbot for external plugins.)


Credentials
-----------

An example ``credentials.ini`` file:

.. code-block:: ini

   dns_shellrent_username = myremoteuser
   dns_shellrent_token = verysecureremoteusertoken
   dns_shellrent_endpoint = https://manager.shellrent.com/api2

The path to this file can be provided interactively or using the
``--dns-shellrent-credentials`` command-line argument. Certbot
records the path to this file for use during renewal, but does not store the
file's contents.

**CAUTION:** You should protect these API credentials as you would the
token to your shellrent account. Users who can read this file can use these
credentials to issue arbitrary API calls on your behalf. Users who can cause
Certbot to run using these credentials can complete a ``dns-01`` challenge to
acquire new certificates or revoke existing certificates for associated
domains, even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

To acquire a single certificate for both ``example.com`` and
``*.example.com``, waiting 900 seconds for DNS propagation:

.. code-block:: bash

   certbot certonly \
     --authenticator dns-shellrent \
     --dns-shellrent-credentials /etc/letsencrypt/.secrets/domain.tld.ini \
     --dns-shellrent-propagation-seconds 900 \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'example.com' \
     -d '*.example.com'


Docker
------

In order to create a docker container with a certbot-dns-shellrent installation,
create an empty directory with the following ``Dockerfile``:

.. code-block:: docker

    FROM certbot/certbot
    RUN pip install certbot-dns-shellrent

Proceed to build the image::

    docker build -t certbot/dns-shellrent .

Once that's finished, the application can be run as follows::

    docker run --rm \
       -v /var/lib/letsencrypt:/var/lib/letsencrypt \
       -v /etc/letsencrypt:/etc/letsencrypt \
       --cap-drop=all \
       certbot/dns-shellrent certonly \
       --authenticator dns-shellrent \
       --dns-shellrent-propagation-seconds 900 \
       --dns-shellrent-credentials \
           /etc/letsencrypt/.secrets/domain.tld.ini \
       --no-self-upgrade \
       --keep-until-expiring --non-interactive --expand \
       --server https://acme-v02.api.letsencrypt.org/directory \
       -d example.com -d '*.example.com'

It is suggested to secure the folder as follows::
chown root:root /etc/letsencrypt/.secrets
chmod 600 /etc/letsencrypt/.secrets
