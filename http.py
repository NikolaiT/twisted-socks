#! /usr/bin/env python

# Copyright (c) 2011-2013, The Tor Project
# See LICENSE for the license.

import sys
from urlparse import urlparse
from twisted.internet import reactor, endpoints
from socksclient import SOCKSv4ClientProtocol, SOCKSWrapper
from twisted.web import client

class TestClass:
    def __init__(self):
        self.npages = 0
        self.timestamps = {}

    def wrappercb(self, proxy):
        print "connected to proxy", proxy

    def clientcb(self, content):
        print "ok, got: %s" % content[:120]
        print "timetamps " + repr(self.timestamps)
        self.npages -= 1
        if self.npages == 0:
            reactor.stop()

    def sockswrapper(self, proxy_config, url):
        dest = urlparse(url)
        assert dest.port is not None, 'Must specify port number.'
        endpoint = endpoints.TCP4ClientEndpoint(reactor, dest.hostname, dest.port)
        return SOCKSWrapper(reactor, endpoint, proxy_config, timestamps=self.timestamps)


def main():
    thing = TestClass()

    # Mandatory first argument is a URL to fetch over Tor (or whatever
    # SOCKS proxy that is running on localhost:9050).
    url = sys.argv[1]

    proxy_config = {
        'host': '127.0.0.1',
        'port': 1080,
        'version': '4',
        'version_specific': {
            'rdns': True, # Enforce resolving hostnames remotely (Only supported by version 4a and 5)
            'cmd': b'\x01', # this may be CONNECT, BIND and UDP in version 5. In 4 and 4a, it's always CONNECT or BIND
            'username': 'socksuser', # Enables simple username/password authentication mechanism in version 5
            'password': 'coder'
        }
    }

    proxy_config2 = {
        'host': '212.224.92.182',
        'port': 7777,
        'version': '5',
        'version_specific': {
            'rdns': True, # Enforce resolving hostnames remotely (Only supported by version 4a and 5)
            'cmd': b'\x01', # this may be CONNECT, BIND and UDP in version 5. In 4 and 4a, it's always CONNECT or BIND
            'username': 'someuser', # Enables simple username/password authentication mechanism in version 5
            'password': 'somepass'
        }
    }
    # From http://fastproxyservers.org/socks5-servers.htm
    proxy_config3 = {
        'host': '202.84.44.129',
        'port': 1080,
        'version': '4',
        'version_specific': {
            'rdns': True, # Enforce resolving hostnames remotely (Only supported by version 4a and 5)
            'cmd': b'\x01', # this may be CONNECT, BIND and UDP in version 5. In 4 and 4a, it's always CONNECT or BIND
            'username': '', # Enables simple username/password authentication mechanism in version 5
            'password': ''
        }
    }

    f = client.HTTPClientFactory(url)
    f.deferred.addCallback(thing.clientcb)

    sw = thing.sockswrapper(proxy_config2, url)
    d = sw.connect(f)
    d.addCallback(thing.wrappercb)
    thing.npages += 1

    reactor.run()

if '__main__' == __name__:
    main()
