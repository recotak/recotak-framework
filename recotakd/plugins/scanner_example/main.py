#!/usr/bin/env python2

from recotak import *
import socket

# this function is called from the recotak framework
# in it's prototype, we have to specify a subset of the
# commandline parameters provided by default and our additinal parameters,
# that we want to use in our plugin as keyword arguments.
# The dbh parameter always has to be specified at first position.
# Via dbh the recotak server passes the database handler, which can
# be used by your plugin to store results your plugin may produce in
# a persistent database

def main(dbh,            # the datbase handler
         target=None,    # input generator for -t/--target parameter
         port=[],        # input generator for -p/--port parameter
         timeout=60,     # input from the  -to/--timeout value
         verbose=False,  # input from the -v/--verbose parameter
         **kwargs):      # just to be sure catch any additional parameters, that recotak might try to pass to you

    # target holds a generator object, which creates items on the fly
    # this preserves memory in case you want to scan large ip ranges
    for t in target:
        ip = t[0]
        # rLog.log holds the logging instance for all recotak plugins
        # the default destination for all plugin logs is /var/log/ccd/plugins.log
        # via -v/--verbose console output of the log messages can be activated
        rLog.log.info('Scanning target: %s', ip)
        fqdn = ''.join(t[1])

        # port also holds a generator
        for p in port:
            rLog.log.info('Scanning target: %s:%d', ip, p)

            state = 'closed'

            # create a socket and try to connect to the target
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((ip, p))
                # if the connection attemp was succesful, change the state
                # accordingly
                state = 'open'
            except Exception as e:
                rLog.log.debug('%s', e)

            if state == 'open' or verbose:
                print '%s:%d %s' % (ip, p, state)

            # make our finding persitent, store them in the database
            # since our plugin is a scanner type, it is automatically
            # registered to write into the appropriate service table
            dbh.add(
                ServiceResult(
                    ip=ip,
                    fqdn=fqdn,
                    port=p,
                    state=state,
                    protocol='tcp'
                )
            )


desc = {
    # execfunc has to be set to the function, which will be called by the
    # recotak server
    # this attribute can also be set after the plugin object has been created,
    # but in that case the cmd line parameters can not be adjustet to match
    # the prototype of your execfunc
    'execfunc': main,

    # we need no additional cmd line parameters
    'cli': {},

    # default values
    'defaults': {
        'Port': '1-100',
        'Target': '127.0.0.1',
    },

    # the class of this plugin
    "plgclass": ["scanner"],

    #plgin name
    "plgname": "simple_tcp_portscan",

    # who wrote this
    "plgauthor": "file",

    # description
    "desc": "try to connect to tcp ports",

    #root?
    "gainroot": False,

    #interaktiv
    "interactive": False,

    #direct connection
    "direct": False,

    #rank
    "rank": "experimental",
}


def register():
    plugin = Plugin2(**desc)
    return plugin
