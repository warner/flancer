from twisted.application.service import ServiceMaker

Flancer = ServiceMaker(
    "Foolscap-based Lancer cert generation, server side",
    "flancer.server.tap",
    "Generate LetsEncrypt certs for local domains, via foolscap.",
    "flancer-server")
