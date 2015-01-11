#!/usr/bin/env python2

# this module contains classes for predifined input arguments

class rHost(object):

    """
    host specification

    for:
        * ip addresses
        * hostnames

    contains:
        * ip address
        * fqdn
        * and domain

    does:
        * resolve dns
        * resolve ip
        * extract domain
    """

    def __init__(self, ip='', fqdn='', domain=''):
        """
        initialize host
        Input:
            ip      ip address
            fqdn    ...
            domain  ...
        """

        self.ip = ip
        self.fqdn = fqdn
        self.domain = domain


class rTarget(object):

    """
    target specification

    cointains:
        * host
        * target port

    does:
        * check reachability
    """

    def __init__(self, host, port):
        """
        initialize target
        Input:
            host    rHost instance
            port    target port
        """

        self.host = host

    def is_up(self):
        """
        check if target is reachable
        """
        pass
