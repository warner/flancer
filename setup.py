from __future__ import absolute_import, print_function
from setuptools import setup

DESCRIPTION = """\
Use LetsEncrypt to create certificates for local (LAN) servers. Just like
(and steals code from) Glyph's 'lancer' package, but uses Foolscap to connect
to a dedicated server-side process that responds to the DNS queries. Instead
of giving your full Gandi/Cloudflare/libcloud password, you only give it
control over TXT records (so it only has the authority to register arbitrary
domains within the given zone, perhaps just sf.example.org). Uses
magic-wormhole for setup.

You'll need two computers: a server with a public IP address, and a local
client machine.

Configure your DNS to delegate the subzone to the public server by adding an
NS record (e.g. if your domain is example.com, and you have an office in
Cleveland, you might use `cleveland.example.com`, to create certs for
machines like `printer.cleveland.example.com`).

Then install `flancer` on that machine and run `twistd flancer-server`. This
will launch a background daemon, using `~/.flancer-server` to hold its state.
Arrange for this daemon to be launched the same way on each reboot, or use
some other daemonization strategy (e.g. write a systemd unit file that runs
the non-daemonzing `twist` command). Make sure the server can listen on port
53 (use authbind, or `setcap 'cap_net_bind_service=+ep' /usr/bin/python`, or
`sysctl net.ipv4.ip_unprivileged_port_start`).

Then, on the server, run `python -m flancer.server.invite`. That will print
an invitation code and wait for the client to accept it.

Now, on the client machine, install `flancer` and launch it as a daemon just
like the server (however it doesn't need acccess to port 53). Then run
`python -m flancer.client.accept ZONE` and type in the invitation code (tab
completion is available). This will put a `config.json` file into
`~/.flancer-client`. `ZONE` should be the subdomain under which you want to
make certificates, e.g. `cleveland.example.com`.

To start generating certificates for a specific domain, run `python -m
flancer.client.add NAME`, where NAME is something like
`printer.cleveland.example.com`.

The certificates and keys will be placed into ~/.flancer-client/NAME.pem ,
from which you can symlink or copy them into somewhere your webserver can
access. You can use the optional `exec_after` feature to run an external
command each time the certs are updated, with which you could scp them to
some other local machine or something.
"""

setup(
    name="flancer",
    description="get LetsEncrypt certificates for LAN-side servers",
    long_description=DESCRIPTION,
    license="MIT",
    package_dir={"": "src"},
    packages=[
        "flancer",
        "flancer.client",
        "flancer.server",
        "twisted.plugins",
        ],
    install_requires=[
        "twisted",
        "foolscap",
        "txacme", # only needed on client
        "magic-wormhole",
        ],
    version="0.0.1",
    )
