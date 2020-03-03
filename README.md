# Flancer

Get ACME certs on your LAN, like Glyph's lancer, but with foolscap
extensions.

Do you have local fileservers or applicances that need TLS certificates?
Tired of dismissing self-signed certificate warnings in your browser? Flancer
might be for you.

## What It Does

Flancer comes in two halves. The server half runs on a publically-accessible
machine, while the client half runs on a machine inside your LAN. The server
responds to Let's Encrypt challenges on behalf of the client. At the end of
the day, the client gets a valid TLS certificate for a machine that is only
visible on the LAN.

Flancer has the additional ability to update a dynamic DNS record for the
external address of your LAN's internet connection. If you use
port-forwarding to expose specific services from this address, you can use a
stable name (e.g. `gw.sf.example.com`) to connect to those forwarded ports,
despite your ISP changing this address (e.g. when your DHCP lease expires and
is renewed with a different address).

## Configuration

First, decide upon which DNS "Zone" or zones you'll be managing. For example,
if you control `example.com`, and you have sites in San Francisco and New
York, you might use `sf.example.com` for the first site, and `ny.example.com`
for the second. All the machines on the New York LAN will have names like
`name1.ny.example.com` and `name2.ny.example.com`. We'll be obtaining TLS
certifications from Let's Encrypt for `name1.ny.example.com` machines.

Second, find a machine that has a public IP address and is up all the time.
This will run the flancer server half, which is a daemon that needs to be
launched at boot, and left running all the time. It will respond to DNS
queries from the internet at large (and most specifically from the Let's
Encrypt challenge machines). It will also accept connections from the flancer
client half. We'll need to know the public DNS name of this machine, e.g.
`external.example.com`.

You must configure your `example.com` nameserver to delegate authority over
the zone (`sf.example.com` or `ny.example.com`) to this server machine. This
allows the Let's Encrypt queries for `name1.ny.example.com` to be sent to
(and answered by) this server.

Third, for each zone, choose a machine on the local LAN to run the flancer
client half. It does not need to be up all of the time, but it can only
obtain certificates while it's running, so try to let it run at least once a
week. If you use the dynamic DNS "gateway" name feature, you may want to keep
it running at all times, so the record can be updated promptly.

## Setting up the server

Run the server with Twisted's `twist` utility, telling it the hostname of the
server machine:

```
twist flancer-server --hostname=external.example.com
```

That will leave the process running in the current shell. You can use
`twistd` instead of `twist` to automatically daemonize it, or you can run it
in the background or under your favorite process-management tool (systemctl,
etc).

The server will store it's state in a "base directory", which defaults to
`~/.flancer-server/`. The primary state goes into a `config.json` in this
directory.

Once running, you'll interact with the server with a separate CLI tool. The
base directory holds additional files which help the CLI tool talk to the
running server.

### Adding a Zone

For each zone you want to add, run the following command on the server
machine:

`python -m flancer.server add-zone sf.example.com server.example.com`

The first argument (`sf.example.com`) is the zone being added. We're telling
the server to accept client certificate requests for names under this zone
(like `name1.sf.example.com`).

The second argument must be the globally-known hostname of the machine which
runs the flancer server. This will be used as the SOA ("source of authority")
record, which means it must match the hostname to which the zone has been
delegated by the parent zone.

## Setting up the client

On your selected LAN-side client machine, run the client daemon with:

```
twist flancer-client --really
```

If you omit `--really`, the certificates will come from the Let's Encrypt
staging server, which is appropriate for testing but won't help for real
certs.

As with the server, this leaves the process running in the current shell, so
you may wish to daemonize it somehow. The client daemon stores its state in
the `~/.flancer-client/` base directory by default. The state includes copies
of all the TLS certificates (and associated private keys) that are generated.

## Adding a new LAN hostname

To get a TLS certificate for a new host on your LAN, start by going to the
server and asking it for an invitation code:

```
server$ python -m flancer.server add-host name1.sf.example.com
```

This will display an "invitation code" (which uses [Magic
Wormhole](https://magic-wormhole.io/) under the hood), which takes the form
of NUMBER-WORD-WORD.

Next, on your client machine, run this command:

```
client$ python -m flancer.client add-host [CODE]
```

You can either provide the full invitation code as the last argument, or you
can omit it and then type in the code interactively. The interactive entry
can do tab-completion of the words.

Once added, the invitation code is used to establish a secure connection with
the server. The client then chooses the private key, creates the certificate
signing request, contacts the Let's Encrypt verification servers, and
requests an ACME dns-01 (`TXT` record) challenge. It receives the challenge
string, then contacts the flancer server and asks it to serve a new `TXT`
record for the new hostname. The Let's Encrypt verification server performs
the `TXT` lookup, which is delegated to the flancer server (because the
entire `sf.example.com` zone is delegated there), and retrieves the challenge
value, confirming that the client has control over the domain. With
verification complete, the Let's Encrypt server then returns the signed
certificate to the client directly. The flancer client then tells the flancer
server to remove the `TXT` record.

The flancer client writes the TLS files into its basedir, in files that end
in `.cert.pem`, `.chain.pem`, `.fullchain.pem`, `.pem`, and `.privkey.pem`.
For example, after adding `name1.sf.example.com`, we will find:

* `~/.flancer-client/name1.sf.example.com.cert.pem`
* `~/.flancer-client/name1.sf.example.com.chain.pem`
* `~/.flancer-client/name1.sf.example.com.fullchain.pem`
* `~/.flancer-client/name1.sf.example.com.pem`
* `~/.flancer-client/name1.sf.example.com.privkey.pem`

`cert.pem` contains the leaf certificate, while `chain.pem` contains the
Let's Encrypt intermediate cert. `fullchain.pem` contains both of these
concatenated together.

`privkey.pem` contains the private key, which must obviously be treated with
great care. The plain `.pem` file contains both `fullchain.pem` and
`privkey.pem` concatenated together. For many TLS servers, this last `.pem`
file is what you need.

You must arrange for these `.pem` files to be installed into your TLS/web
server.

(TODO): it is not implemented yet, but eventually the flancer client will pay
attention to a post-update hook file. When `name1.sf.example.com` has a new
certificate available, the client will look for
`~/.flancer-client/name1.sf.example.com.post-update-hook`. If this file is
present and executable, it will be run (with some arguments TBD).

## Certificate Renewals

The client will periodically check all configured certificates (perhaps
daily). It will renew any that need updating. In practice this gets a new
certificate every two months, and certificates are generally valid for three
months.

(TODO) Once the post-update hook is implemented, the hook will be executed
each time the certificate is renewed.

Note that many TLS/web servers only read the certificate file once, at
startup, so you may need to restart or reload the server config after
renewal.


## Adding a dyndns name

You can configure the server to maintain a DNS name that points at the
client's external IP address. For example you might want `gw.sf.example.com`
to point to the `sf` LAN's router's external address. The dynamic name must
be a member of the managed zone (so e.g. `gw.other.sf.example.com` or
`gw.other.com` would not work).

To do this, start on the flancer server machine, and run:

```
server$ python -m flancer.server add-dyndns gw.sf.example.com
```

This will create an invitation code, as before. Then, on your client machine,
run this command:

```
client$ python -m flancer.client add-dyndns [CODE]
```

This will configure the client to initiate and maintain a connection to the
server. The server will check the source address of this connection, and use
it to create the dynamic DNS name record. Both sides will ping this
connection every 60 seconds (to keep a NAT/firewall table entry in place),
and will attempt to reestablish a connection if this ping is rejected or if
roughly five minutes pass without a response.

The dynamic DNS name is not currently removed if/when the client connection
is lost: the server will continue to advertise the most recently known IP
address. However the address is not stored on disk, so when the server is
restarted, it will not advertise the dynamic name at all until the client
establishes the connection.

(TODO) In the future, the dynamic DNS name might be unregistered when the
client connection is lost, under the theory that if the server can't reach
it, the rest of the world won't be able to either. This is not implemented
yet.
