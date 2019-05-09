from __future__ import print_function
import os
import json
import hashlib
import attr
from pem import parse
from zope.interface import implementer
from operator import methodcaller
from twisted.internet import reactor
from twisted.python import usage
from twisted.application.service import MultiService
#from twisted.application.internet import TimerService
from foolscap.api import Tub, Referenceable

from functools import partial

from twisted.internet.defer import inlineCallbacks, returnValue, succeed, maybeDeferred
from twisted.python.filepath import FilePath
#from twisted.logger import globalLogBeginner, textFileLogObserver

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from josepy.jwk import JWKRSA
from josepy.jwa import RS256
from josepy.b64 import b64encode

from txacme.service import AcmeIssuingService
from txacme.client import Client
from txacme.urls import LETSENCRYPT_DIRECTORY, LETSENCRYPT_STAGING_DIRECTORY
from txacme.util import generate_private_key
from txacme.errors import NotInZone
from txacme.interfaces import ICertificateStore


LONGDESC = """\
Flancer client-side daemon.

Launch with 'twist flancer-client' and leave it running, or use twistd.

Control with 'python -m flancer.client SUBCOMMAND':

* python -m flancer.client add-host

"""

def _split_zone(server_name, zone_name):
    """
    Split the zone portion off from a DNS label.

    :param str server_name: The full DNS label.
    :param str zone_name: The zone name suffix.
    """
    server_name = server_name.rstrip(u'.')
    zone_name = zone_name.rstrip(u'.')
    if not (server_name == zone_name or
            server_name.endswith(u'.' + zone_name)):
        raise NotInZone(server_name=server_name, zone_name=zone_name)
    return server_name[:-len(zone_name)].rstrip(u'.')

def _validation(response):
    """
    Get the validation value for a challenge response.
    """
    h = hashlib.sha256(response.key_authorization.encode("utf-8"))
    return b64encode(h.digest()).decode()

@attr.s
@implementer(ICertificateStore)
class FlancerCertificateStore(object):
    # ~/.flancer-client/HOSTNAME.pem
    # if HOSTNAME.post-update-hook is present and executable, it is run
    # after each update

    _data = attr.ib()
    _path = attr.ib(convert=methodcaller('asTextMode')) # .../certs/

    def _get(self, server_name):
        if server_name not in self._data["hosts"]:
            raise KeyError(server_name)
        pem = self._path.child(server_name+".pem")
        if pem.isfile():
            return parse(pem.getContent())
        return parse(b"")

    def get(self, server_name):
        return maybeDeferred(self._get, server_name)

    @inlineCallbacks
    def store(self, server_name, pem_objects):
        self._path.child(server_name+".privkey.pem").setContent(pem_objects[0].as_bytes())
        self._path.child(server_name+".cert.pem").setContent(pem_objects[1].as_bytes())
        chain_certs = pem_objects[2:]
        if chain_certs:
            self._path.child(server_name+".chain.pem").setContent(b''.join(o.as_bytes() for o in chain_certs))
        fullchain = b''.join(o.as_bytes() for o in pem_objects[1:])
        self._path.child(server_name+".fullchain.pem").setContent(everything)

        everything = b''.join(o.as_bytes() for o in pem_objects)
        self._path.child(server_name+".pem").setContent(everything)

        h = self._path.child(server_name+".post-update-hook")
        if h.isfile() and h.getPermissions().user.execute:
            yield self._run_hook(h)
        returnValue(None)

    def _run_hook(self, h):
        print("pretending to run post-update-hook")

    def as_dict(self):
        return succeed( { h: self._get(h)
                          for h in self._data["hosts"].keys() } )

class Options(usage.Options):
    synopsis = "[options..]"
    longdesc = LONGDESC

    optFlags = [
        ("really", None, "use real certs, not staging"),
        ]
    optParameters = [
        ("basedir", None, "~/.flancer-client", "directory to hold config.json"),
        ]


def maybe_key(pem_path):
    acme_key_file = pem_path.child(u'client.key')
    if acme_key_file.exists():
        key = serialization.load_pem_private_key(
            acme_key_file.getContent(),
            password=None,
            backend=default_backend()
        )
    else:
        key = generate_private_key(u'rsa')
        acme_key_file.setContent(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    acme_key = JWKRSA(key=key)
    return acme_key


#globalLogBeginner.beginLoggingTo([textFileLogObserver(sys.stdout)])

@attr.s
class Data(dict):
    _fn = attr.ib(convert=methodcaller('asTextMode')) # BASEDIR/config.json

    def __attrs_post_init__(self):
        if not self._fn.isfile():
            self["hosts"] = {}
            self._fn.setContent(json.dumps(self).encode("utf-8")+"\n")
        for k,v in json.loads(self._fn.getContent().decode("utf-8")).items():
            self[k] = v

    def save(self):
        self._fn.setContent(json.dumps(self).encode("utf-8")+"\n")

@attr.s
class FlancerResponder(object):
    challenge_type = u"dns-01"

    _tub = attr.ib()
    _data = attr.ib()

    @inlineCallbacks
    def start_responding(self, server_name, challenge, response):
        # This 'server_name' is like test1.sf.example.com
        print("start_responding", server_name)
        validation = _validation(response)
        full_name = challenge.validation_domain_name(server_name)
        # full_name is _acme-challenge.$SERVERNAME
        subdomain = _split_zone(full_name, server_name)
        # subdomain should always just be _acme-challenge
        #print("full_name", full_name)
        furl = self._data["hosts"][server_name].encode("ascii")
        rr = yield self._tub.getReference(furl)
        yield rr.callRemote("set_txt", subdomain, validation.encode("ascii"))

    @inlineCallbacks
    def stop_responding(self, server_name, challenge, response):
        print("stop_responding", server_name)
        full_name = challenge.validation_domain_name(server_name)
        subdomain = _split_zone(full_name, server_name)
        furl = self._data["hosts"][server_name].encode("ascii")
        rr = yield self._tub.getReference(furl)
        yield rr.callRemote("delete_txt", subdomain)

def start_dyndns_canary(tub, furl):
    class Canary(Referenceable):
        pass
    def connected(rref):
        rref.callRemote("connect", Canary())
    tub.connectTo(furl, connected)

@attr.s(cmp=False)
class Controller(Referenceable, object):
    _tub = attr.ib()
    _data = attr.ib()
    _issuer = attr.ib()

    @inlineCallbacks
    def remote_accept_add_host(self, furl):
        rr = yield self._tub.getReference(furl)
        hostname = yield rr.callRemote("get_hostname")
        print("adding hostname '%s'" % hostname)
        # add furl and hostname to config, to remember that we want a cert
        self._data["hosts"][hostname] = furl
        try:
            self._data.save()
        except:
            from twisted.python.failure import Failure
            print(Failure())
            raise
        # and provoke the issuer to get a cert right away
        yield self._issuer.issue_cert(hostname)
        returnValue(hostname)

    @inlineCallbacks
    def remote_accept_add_dyndns(self, furl):
        self._data["dyndns_furl"] = furl
        try:
            self._data.save()
        except:
            from twisted.python.failure import Failure
            print(Failure())
            raise
        start_dyndns_canary(self._tub, furl)
        returnValue("ok")
        yield 0 # must be a generator

def makeService(config, reactor=reactor):
    parent = MultiService()
    basedir = FilePath(os.path.expanduser(config["basedir"]))
    basedir.makedirs(ignoreExistingDirectory=True)
    basedir.chmod(0o700)

    data = Data(basedir.child("config.json"))

    certFile = basedir.child("tub.data").path
    tub = Tub(certFile=certFile)
    tub.setOption("keepaliveTimeout", 60) # ping after 60s of idle
    tub.setOption("disconnectTimeout", 5*60) # disconnect/reconnect after 5m
    tub.listenOn("tcp:6319:interface=127.0.0.1")
    tub.setLocation("tcp:127.0.0.1:6319")
    tub.setServiceParent(parent)

    acme_path = basedir.asTextMode()
    acme_key = maybe_key(acme_path)
    cert_store = FlancerCertificateStore(data, basedir)
    staging = not config["really"]
    if staging:
        print("STAGING mode")
        le_url = LETSENCRYPT_STAGING_DIRECTORY
    else:
        print("REAL CERTIFICATE mode")
        le_url = LETSENCRYPT_DIRECTORY
    client_creator = partial(Client.from_url, reactor=reactor,
                             url=le_url,
                             key=acme_key, alg=RS256)
    r = FlancerResponder(tub, data)
    issuer = AcmeIssuingService(cert_store, client_creator, reactor, [r])
    issuer.setServiceParent(parent)

    if "dyndns_furl" in data:
        start_dyndns_canary(tub, data["dyndns_furl"].encode("ascii"))

    c = Controller(tub, data, issuer)
    tub.registerReference(c, furlFile=basedir.child("controller.furl").path)

    #TimerService(5*60.0, f.timerUpdateStats).setServiceParent(parent)
    return parent
