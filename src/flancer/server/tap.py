import os
import attr
import json
from operator import methodcaller
from twisted.internet import reactor
from twisted.python import usage
from twisted.python.filepath import FilePath
from twisted.application.service import MultiService
from twisted.application.internet import UDPServer, TCPServer
#from twisted.application.internet import TimerService
from twisted.internet.defer import inlineCallbacks, returnValue
#from twisted.names import tap, authority, dns, resolve
from twisted.names.server import DNSServerFactory
from twisted.names import authority, dns
from twisted.names.resolve import ResolverChain
from twisted.names import client as dns_client
from twisted.names.error import DNSNameError
from foolscap.api import Tub, Referenceable
from foolscap.appserver.cli import make_swissnum

LONGDESC = """\
Respond to ACME dns-01 challenges (TXT records).
"""

class Options(usage.Options):
    synopsis = "--hostname=HOSTNAME [options..]"
    longdesc = LONGDESC

    optParameters = [
        ("basedir", None, "~/.flancer-server", "directory to hold config.json"),
        ("dns-port", None, "53", "port (integer) to listen for DNS queries, only override if you have some exotic port-forwarding in place for both TCP and UDP"),
        ("dns-interface", None, "", "Interface to which to bind the DNS server ports"),
        ("foolscap-port", None, "tcp:6318", "port (endpoint string) for the Foolscap server"),
        ("hostname", None, None, "hostname (required) for the Foolscap port)"),
        ]

    def postOptions(self):
        if not self["hostname"]:
            raise usage.UsageError("--hostname= is required: how should the client contact this server?")

def extract_zone(name):
    return name.split(".", 1)[1]

# we want something very similar to a FileAuthority, but with some
# dynamically-generated records

class DynamicAuthority(authority.FileAuthority):
    def __init__(self, zone, soa, initial_records={}):
        authority.FileAuthority.__init__(self, None)
        self.soa = (zone, soa)
        self.records = initial_records
    def loadFile(self, _):
        pass

    def setTXT(self, hostname, txtname, data):
        assert type(data) is type(b""), (type(data), data)
        # hostname is like 'test1.sf.example.com'
        print "setTXT", hostname, txtname, data
        fullname = "%s.%s" % (txtname, hostname)
        self.records[fullname] = [dns.Record_TXT(data, ttl=5)]

    def deleteTXT(self, hostname, txtname):
        print "deleteTXT", hostname, txtname
        fullname = "%s.%s" % (txtname, hostname)
        del self.records[fullname]

    def _lookup(self, name, cls, type, timeout = None):
        print "LOOKUP: %s %s %s" % (name, dns.QUERY_CLASSES.get(cls, cls),
                                    dns.QUERY_TYPES.get(type, type))
        d = authority.FileAuthority._lookup(self, name, cls, type, timeout)
        def _log(res):
            print "-> %s" % (res,)
            return res
        d.addBoth(_log)
        return d

@attr.s
class Data(dict):
    _fn = attr.ib(convert=methodcaller('asTextMode')) # BASEDIR/config.json

    def __attrs_post_init__(self):
        if not self._fn.isfile():
            self["zones"] = {}
            self._fn.setContent(json.dumps(self).encode("utf-8")+"\n")
        for k,v in json.loads(self._fn.getContent().decode("utf-8")).items():
            self[k] = v

    def save(self):
        self._fn.setContent(json.dumps(self).encode("utf-8")+"\n")

@attr.s(cmp=False)
class HostController(Referenceable, object):
    _hostname = attr.ib()
    _server = attr.ib()

    def remote_get_hostname(self):
        return self._hostname # e.g. test1.sf.example.com
    def remote_set_txt(self, txtname, data):
        self._server.add_txt(self._hostname, txtname, data)
    def remote_delete_txt(self, txtname):
        self._server.delete_txt(self._hostname, txtname)


@attr.s(cmp=False)
class Controller(Referenceable, object):
    _data = attr.ib()
    _server = attr.ib()
    _furl_prefix = None

    def set_furl_prefix(self, furl_prefix):
        self._furl_prefix = furl_prefix

    def lookup(self, name):
        for z, zd in self._data["zones"].items():
            for (hostname, swissnum) in zd["hostname_swissnums"]:
                if swissnum == name:
                    return HostController(hostname, self._server)

    @inlineCallbacks
    def remote_add_zone(self, zone_name, server_name):
        assert isinstance(zone_name, type(u""))
        assert isinstance(server_name, type(u""))
        print(self._data["zones"])
        if zone_name in self._data["zones"]:
            print("already present")
            returnValue("already present")
        self._data["zones"][zone_name] = { "server_name": server_name,
                                           "hostname_swissnums": [], # tuples of (hostname, swissnum)
                                           }
        self._server.update_records()
        try:
            yield self._server.test_zone(zone_name)
        except:
            del self._data["zones"][zone_name]
            raise
        self._data.save()
        returnValue("added")

    @inlineCallbacks
    def remote_add_host(self, hostname):
        zone = extract_zone(hostname)
        d = self._data["zones"][zone]["hostname_swissnums"]
        swissnum = make_swissnum()
        d.append( (hostname, swissnum) )
        self._data.save()
        assert self._furl_prefix
        furl = self._furl_prefix + swissnum
        returnValue(furl)
        yield 0

@attr.s
class Server(object):
    _data = attr.ib()
    _dns_server = attr.ib()

    def __attrs_post_init__(self):
        self._records = {}
        self._authorities = {}

    def update_records(self):
        resolvers = []
        self._da = {}
        for z,zd in self._data["zones"].items():
            soa = dns.Record_SOA(
                mname=zd["server_name"],
                rname="root." + z, # what is this for?
                serial=1, # must be int, fit in struct.pack("L") so 32-bits
                refresh="1M",
                retry="1M",
                expire="1M",
                minimum="1M",
                )
            ns = dns.Record_NS(zd["server_name"])
            records = {
                z: [soa, ns],
                }
            da = DynamicAuthority(z, soa, records)
            resolvers.append(da)
            self._authorities[z] = da
        print(self._dns_server.resolver)
        self._dns_server.resolver = ResolverChain(resolvers)

    def add_txt(self, hostname, txtname, data):
        # hostname is like 'test1.sf.example.com'
        # but 'sf.example.com' is what's in self._authorities
        zone = hostname.split(".", 1)[1]
        if zone not in self._authorities:
            raise KeyError("zone '%s' not in authorities %s" %
                           (zone, self._authorities.keys()))
        self._authorities[zone].setTXT(hostname, txtname, data)

    def delete_txt(self, hostname, txtname):
        zone = hostname.split(".", 1)[1]
        if zone not in self._authorities:
            raise KeyError("zone '%s' not in authorities %s" %
                           (zone, self._authorities.keys()))
        self._authorities[zone].deleteTXT(hostname, txtname)

    @inlineCallbacks
    def test_zone(self, zone_name):
        print("testing new zone %s" % zone_name)
        hostname = "_flancer_test.%s" % zone_name
        txtname = "_flancer_txtname"
        fullname = "%s.%s" % (txtname, hostname)
        test_data = "flancer_txt"
        self.add_txt(hostname, txtname, test_data)
        try:
            res = yield dns_client.lookupText(fullname)
        except DNSNameError as e:
            print("failure to test zone: is there an NS record pointing to us?")
            print(e)
            self.delete_txt(hostname, txtname)
            raise ValueError("failure to test zone: DNS error. Is there an NS record pointing to us?")
        #print("result", res)
        (answer, authority, additional) = res
        for r in answer:
            #print("R", r, dir(r))
            if r.type == dns.TXT:
                #print("TXT", r.payload.data[0])
                if r.payload.data[0] == test_data:
                    print("success")
                    self.delete_txt(hostname, txtname)
                    returnValue(True)
        print("failure to test zone: is there an NS record pointing to us?")
        self.delete_txt(hostname, txtname)
        raise ValueError("failure to test zone: is there an NS record pointing to us?")

def makeService(config, reactor=reactor):
    parent = MultiService()
    basedir = FilePath(os.path.expanduser(config["basedir"]))
    basedir.makedirs(ignoreExistingDirectory=True)
    basedir.chmod(0o700)

    data = Data(basedir.child("config.json"))

    dns_server = DNSServerFactory(verbose=0)
    s1 = UDPServer(int(config["dns-port"]), dns.DNSDatagramProtocol(dns_server),
                   interface=config["dns-interface"])
    s1.setServiceParent(parent)
    s2 = TCPServer(int(config["dns-port"]), dns_server,
                   interface=config["dns-interface"])
    s2.setServiceParent(parent)

    s = Server(data, dns_server)
    s.update_records()

    certFile = basedir.child("tub.data").path
    #furlFile = basedir.child("server.furl").path
    t = Tub(certFile=certFile)
    #t.setOption("logLocalFailures", True)
    #t.setOption("logRemoteFailures", True)
    #t.unsafeTracebacks = True
    fp = config["foolscap-port"]
    if not fp.startswith("tcp:"):
        raise usage.UsageError("I don't know how to handle non-tcp foolscap-port=")
    port = int(fp.split(":")[1])
    assert port > 1
    t.listenOn(fp)
    t.setLocation("tcp:%s:%d" % (config["hostname"], port))

    c = Controller(data, s)
    cf = t.registerReference(c, furlFile=basedir.child("controller.furl").path)
    furl_prefix = cf[:cf.rfind("/")+1]
    c.set_furl_prefix(furl_prefix)
    t.registerNameLookupHandler(c.lookup)

    t.setServiceParent(parent)
    return parent
