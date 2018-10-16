from twisted.application.service import ServiceMaker

FlancerClient = ServiceMaker(
    "Foolscap-based Lancer cert generation, client side",
    "flancer.client.tap",
    "Generate LetsEncrypt certs for local domains, via foolscap.",
    "flancer-client")
