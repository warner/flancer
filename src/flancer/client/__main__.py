from __future__ import print_function

import os

from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.python import usage
from twisted.python.filepath import FilePath
from foolscap.api import Tub
from wormhole import create, input_with_completion

class AddHostOptions(usage.Options):
    synopsis = "[invitation-code]"
    def parseArgs(self, code=None):
        self.code = code

class Options(usage.Options):
    synopsis = "[options..]"

    optParameters = [
        ("basedir", None, "~/.flancer-client", "client basedir"),
        ]

    subCommands = [
        ("add-host", None, AddHostOptions, "Accept an add-host invitation code to add a new hostname"),
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
    if opts.subCommand == "add-host":
        w = create(APPID, MAILBOX_URL, reactor)
        if so.code:
            w.set_code(so.code)
        else:
            input_with_completion("Invitation code: ", w.input_code(), reactor)
        yield w.get_code()
        furl = yield w.get_message()
        c = yield getController(reactor, controllerFurl)
        hostname = yield c.callRemote("accept_add_host", furl)
        print("hostname '%s' added" % hostname)
        print("if you want to configure a post-update hook, edit:")
        print("  %s" % basedir.child(hostname).child("post-update-hook").path)
        print("(and make it executable)")
        w.send_message("ok")
        yield w.close()

opts = Options()
opts.parseOptions()
react(run, (opts,))
