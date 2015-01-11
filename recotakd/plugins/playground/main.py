#!/usr/bin/env python2

from recotak import *
import sqlalchemy as sql

class PlaygroundResult2(ServiceResult):
    columns = [
        sql.Column("test_data1", sql.Integer),
        sql.Column("test_data2", sql.String),
    ]

    def __init__(self,
                 ip='0.0.0.0',
                 fqdn='',
                 domain='',
                 root_zone='',
                 port=0,
                 state='',
                 protocol='',
                 service='',
                 version='',
                 info='',
                 test_data1='', test_data2=''):

        super(PlaygroundResult2, self).__init__(
            ip=ip,
            fqdn=fqdn,
            domain=domain,
            root_zone=root_zone,
            port=port,
            state=state,
            protocol=protocol,
            service=service,
            version=version,
            info=info)

        self.test_data1 = test_data1
        self.test_data2 = test_data2


class PlaygroundResult(object):
    columns = [
        sql.Column("test_data1", sql.Integer),
        sql.Column("test_data2", sql.String),
    ]

    def __init__(self, test_data1='', test_data2=''):
        self.test_data1 = test_data1
        self.test_data2 = test_data2


#perfectDesc is the main control dictionary for the plugin
#das dictionary wird ausgewertet, dabei werden <n> listen gefunden
desc = {
    #cli1 ist nur der dict name und kann weitestgehend beliebig gewaehlt
    #werden, wichtig ist was im type steht. cli steht hier fuer
    #commandlineinterface und gibt im normalfall die argumente an die
    #hinzugefuegt werden sollen
    "cli": {

        "cli1": {
            "name_or_flags": ["-r", "--registry"],
            "help": "change registry"
        },
        #was man ueberlegen kann ist auch beim namen festzulegen das der erste
        #teil zu heissen hat wie ein type, dh. in dem fall "cli" und dahinter die
        #ziffer die position des arguments bestimmt, in dem fall waere es
        #nuetzlich um zu sagen: die option -e wird in der help erst _nach_ der
        #option -r ausgegeben
        "cli2": {
            "name_or_flags": ["-e", "--entry"],
            "help": "name of the entry to change/add"
        },

        "cli2": {
            "name_or_flags": ["-i", "--input"],
            "help": "additional input",
            "action": InputAction
        },

    },

    'defaults': {
        'Port': [22],
        'Target': ['127.0.0.1'],
    },

    'extra_data': PlaygroundResult2,

    # klasse des plugins
    # brute bekommt dann automatisch --thread, --delay -u/--user --pass
    #-U/--userlist -P/--passlist, -t/--target,-T/--targetlist,-p/--port
    #"plgclass": "brute",

    # andere klassenbeispiele
    # bekommt automatisch die funktionen und flags: -u/--user
    #-p/--password,-t/--target,-p/--port
    #"plgclass": "login",

    # andere klassenbeispiele
    # bekommt automatisch die funktionen und flags:
    #-t/--target,-p/--port,--thread,--delay,-f/--file
    "plgclass": ["scanner"],

    #plgin name
    "plgname": "playground",

    # description
    "desc": "playground for testing",

    #root?
    "gainroot": False,

    #interaktiv
    "interactive": False,

    #direct connection
    "direct": False,

    #rank
    "rank": "experimental",
}

def main(dbh, target=None, port=None, user=None, password=None, cli1=None, cli2=None, cli3=None, **kwargs):
    rLog.log.debug("blubb")
    print repr(cli1)
    print repr(cli2)
    print repr(cli3)
    print repr(target)
    print repr(port)
    print repr(user)
    print repr(password)
    print repr(kwargs)

    try:
        for t in target:
            print 'target: ' + repr(t)
            if isinstance(t[1], str):
                fqdn = t[1]
            else:
                fqdn = t[1][0]

            try:
                for p in port:
                    print 'port: ' + repr(p)
                    #sr = ServiceResult(
                    pgr = PlaygroundResult2(
                        ip=t[0],
                        fqdn=fqdn,
                        port=int(p),
                        state='??',
                        protocol='tcp',
                        version='0.0',
                        test_data1=1,
                        test_data2='x'
                    )
                    #dbh.add(sr)
                    #pgr = PlaygroundResult(1, 'b')
                    dbh.add(pgr)
            except Exception as e:
                print e

#            tr = TargetResult(ip=t[0], fqdn=t[1][0])
#            print repr(tr)
#            dbh.add(tr)

    except Exception as e:
        print str(e)

    try:
        for p in port:
            print p
    except:
        pass

    try:
        for p in password:
            print p
    except:
        pass

    try:
        for p in cli2:
            print p
    except:
        pass

    try:
        for p in cli3:
            print p
    except:
        pass

    try:
        for p in cli1:
            print p
    except:
        pass

    try:
        for p in user:
            print p
    except:
        pass

def register():
    plugin = Plugin2(**desc)
    plugin.execute = main
    return plugin

if __name__ == '__main__':
    import sys
    main(None, sys.argv[1:])
