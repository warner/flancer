from __future__ import print_function

import os

from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.python import usage
from twisted.python.filepath import FilePath
from foolscap.api import Tub
import wormhole

class AddZoneOptions(usage.Options):
    synopsis = "<zone_name> <server_hostname>"
    def parseArgs(self, zone_name, server_hostname):
        self.zone_name = zone_name.decode("utf-8")
        self.server_hostname = server_hostname.decode("utf-8")

class AddHostOptions(usage.Options):
    synopsis = "<hostname>"
    def parseArgs(self, host_name):
        self.host_name = host_name.decode("utf-8")

class Options(usage.Options):
    synopsis = "[options..]"

    optParameters = [
        ("basedir", None, "~/.flancer-server", "directory to hold config.json"),
        ]

    subCommands = [
        ("add-zone", None, AddZoneOptions, "Add a new DNS zone like sf.example.com"),
        ("add-host", None, AddHostOptions, "Add a new hostname like printer.sf.example.com"),
        ]


def getController(reactor, controllerFurl):
    t = Tub()
    #t.setOption("logLocalFailures", True)
    #t.setOption("logRemoteFailures", True)
    t.startService()
    return t.getReference(controllerFurl)

MAILBOX_URL = u"ws://relay.magic-wormhole.io:4000/v1"
APPID = u"lothar.com/flancer/add-host/v1"

@inlineCallbacks
def run(reactor, opts):
    basedir = FilePath(os.path.expanduser(opts["basedir"]))
    controllerFurl = basedir.child("controller.furl").getContent()
    if not opts.subCommand:
        raise usage.UsageError("pick a command")
    so = opts.subOptions
    if opts.subCommand == "add-zone":
        c = yield getController(reactor, controllerFurl)
        resp = yield c.callRemote("add_zone", so.zone_name, so.server_hostname)
        print("zone '%s': %s" % (so.zone_name, resp))
        return
    if opts.subCommand == "add-host":
        c = yield getController(reactor, controllerFurl)
        furl = yield c.callRemote("add_host", so.host_name)
        print("host '%s': %s" % (so.host_name, furl))
        w = wormhole.create(APPID, MAILBOX_URL, reactor)
        w.allocate_code()
        code = yield w.get_code()
        print("")
        print("Please run 'python -m flancer.client add-host' on your LAN-side machine")
        print("and provide the following invitation code:")
        print()
        print("  %s" % code)
        print()
        print("(waiting for invitation to be accepted...)")
        w.send_message(furl)
        ack = yield w.get_message()
        if ack == "ok":
            print("invitation accepted, certificate issued")
        else:
            print("error: %s" % ack)
        yield w.close()

opts = Options()
opts.parseOptions()
react(run, (opts,))
