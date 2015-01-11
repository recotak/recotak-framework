#!/usr/bin/env python2

from recotak import *
import socket

desc = {
    'cli': {},

    'defaults': {},

    "plgclass": ["connect"],

    #plgin name
    "plgname": "tcp_connect",

    # description
    "desc": "simple tcp connector",

    #root?
    "gainroot": False,

    #interaktiv
    "interactive": True,

    #direct connection
    "direct": False,

    #rank
    "rank": "experimental",
}


def main(dbh, target=None, port=None, **kwargs):

    print 'Connecting to %s:%d' % (target, port)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, port))

    while True:
        inp = raw_input('> ')
        s.send(inp)


def register():
    plugin = Plugin2(**desc)
    plugin.execute = main
    return plugin
