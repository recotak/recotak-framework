import argparse
import json
import os
import exrex
import sys
import itertools as it
from ctools import cTuples
from ctools import cUtil
from ctools import dns


class Cli(object):

    CLI = {
        'verbose': {
            'name_or_flags': ['-v', '--verbose'],
            'action': 'store_true',
            'help': 'verbose'
        },
        'timeout': {
            'name_or_flags': ['-to', '--timeout'],
            'type': float,
            'default': 30.0,
            'help': 'socket timeout',
        }
    }

    def __init__(self, plgname, desc, examples, cli, defaults, argspec=[]):
        self.plgname = plgname
        self.cli = Cli.CLI.copy()
        self.cli.update(cli)
        self.desc = desc
        self.defaults = defaults
        self.argspec = argspec
        self.actions = []
        #if examples:
        #    self.desc += "\n\nExamples:\n"
        #    for example in examples:
        #        self.desc += "\n\texec %s.plg %s" % (self.plgname, example)

    def make_parser(self):
        #print '-' * 80
        #print
        arg_examples = []
        max_ex = 0
        for dest, ospec in self.cli.items():

            if self.argspec and dest.lower() not in self.argspec:
                continue

            try:
                ex = ospec['example']
                if max_ex < len(ex):
                    max_ex = len(ex)
            except KeyError:
                pass

        for dest, ospec in self.cli.items():

            if self.argspec and dest.lower() not in self.argspec:
                continue

            #print dest
            #print 'Spec: ' + repr(ospec)
            try:
                ex = ospec['example'][:]
                #print 'Appending Example: ' + repr(ex)
                if 'required' in ospec.keys() and \
                        not 'default' in ospec.keys():
                    c_ex = it.cycle(ex)
                    for _ in range(len(ex), max_ex):
                        ex.append(c_ex.next())
                arg_examples.append(ex)
            except KeyError:
                pass
            except Exception as e:
                print repr(e)

        #print 'arg_examples: ' + repr(arg_examples)

        try:
            if arg_examples:
                combined_examples = it.izip_longest(*arg_examples, fillvalue='')
                #print 'combined exaples: ' + repr(combined_examples)
                self.desc += '\n\nExamples:\n'
                for ce in combined_examples:
                    ce = filter(lambda t: t, ce)
                    #print 'ce: ' + repr(ce)
                    self.desc += '\texec %s.plg ' % self.plgname
                    self.desc += ' '.join(ce)
                    self.desc += '\n'
        except Exception as e:
            print repr(e)

        #print self.desc

        parser = argparse.ArgumentParser(
            prog=self.plgname,
            description=self.desc,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        #print
        #print '-' * 80
        #print self.plgname
        #print repr(self.argspec)

        for dest, ospec in self.cli.items():

            #print dest
            if self.argspec and dest.lower() not in self.argspec:
                #print 'removing default argument %s' % dest
                continue

            spec = ospec.copy()

            try:
                del spec['example']
            except:
                pass

            name_or_flags = spec.pop('name_or_flags')
            default = None
            try:
                default = self.defaults[dest]
                spec['default'] = default
            except KeyError:
                pass

            if 'default' in spec.keys() and 'help' in spec.keys():
                default = spec['default']
                if hasattr(default, '__iter__'):
                    spec['help'] += ' (DEFAULT: %s)' % ', '.join(map(str, spec['default']))
                else:
                    spec['help'] += ' (DEFAULT: %s)' % str(default)


            if 'default' in spec.keys():
                try:
                    del spec['required']
                except:
                    pass


            try:
                action = parser.add_argument(
                    *name_or_flags,
                    **spec
                )
                try:
                    if action.always_exec:
                        self.actions.append(action)
                except AttributeError:
                    pass

            except Exception as e:
                logger.warning('Could not add argument %s: %s', dest, e)

        return parser

    def update(self, cli):
        self.cli.update(cli)

    def to_json(self):
        return json.dumps(self.cli)


class TargetAction(argparse.Action):

    always_exec = True

    def __init__(self, option_strings, dest, nargs=None, **kwargs):

        if nargs is not None:
            raise ValueError("nargs not allowed")

        super(TargetAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        filenames = []
        data = []
        inpts = values.split(',')
        for inp in inpts:
            inp = inp.rstrip()
            if not inp:
                continue
            # we have a file
            try:
                fd = openany(inp, 'r')
                fd.close()
                filenames.append(inp)
            except:
                if dns.validate.is_ip(inp) or dns.validate.is_domain(inp):
                    data.append(inp)
                else:
                    print 'ERROR: invalid target: %s' % inp
                    sys.exit(1)

            try:
                targets = cTuples.cInputGenerator(
                    filenames=filenames,
                    data=data,
                    circle=False,
                    expand_cb=cUtil.mkIP2,
                )
            except cTuples.ENoInput:
                print 'ERROR: target not specified'
                sys.exit(1)

        targets.setDaemon(True)
        targets.start()
        setattr(namespace, self.dest, targets)


class PortAction(argparse.Action):

    always_exec = True

    def __init__(self, option_strings, dest, nargs=None, **kwargs):

        if nargs is not None:
            raise ValueError("nargs not allowed")

        super(PortAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        filenames = []
        data = []
        inpts = values.split(',')
        for inp in inpts:
            inp = inp.rstrip()
            if not inp:
                continue
            try:
                fd = openany(inp, 'r')
                fd.close()
                filenames.append(inp)
            except:
                data.append(inp)

        try:
            ports = cTuples.cInputGenerator(
                filenames=filenames,
                data=data,
                circle=True,
                expand_cb=cUtil.mkPort
            )
        except cTuples.ENoInput:
            print 'ERROR: port not specified'
            sys.exit(1)

        ports.setDaemon(True)
        ports.start()
        setattr(namespace, self.dest, ports)


class InputAction(argparse.Action):

    always_exec = True

    def __init__(self, option_strings, dest, nargs=None, **kwargs):

        if nargs is not None:
            raise ValueError("nargs not allowed")

        super(InputAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        filenames = []
        data = []
        inpts = values.split(',')
        for inp in inpts:
            inp = inp.rstrip()
            if not inp:
                continue
            try:
                fd = openany(inp, 'r')
                fd.close()
                filenames.append(inp)
            except:
                data.append(inp)

        expand_cb = None

        if namespace.wildcards:
            expand_cb = lambda t: exrex.generate(t)

        inputs = cTuples.cInputGenerator(
            filenames=filenames,
            data=data,
            circle=True,
            expand_cb=expand_cb,
            prepare_cb=lambda t: t.rstrip() or None,
        )
        inputs.setDaemon(True)
        inputs.start()
        setattr(namespace, self.dest, inputs)


class CliDns(Cli):

    CLI = {
        'Target': {
            'name_or_flags': ['-t', '--target'],
            'help': 'target ip, list of ips, iprange, netmask, or file containing the aforementioned',
            'action': TargetAction,
            'example': ['-t 192.168.1.1,192.168.2.0/24', '-t google.com,192.168.1.0/24', '-t ips.txt,192.198.1.0-192.168.1.255'],
            'required': True
        },
        'Threads': {
            'name_or_flags': ['-n', '--nthreads'],
            'help': 'Number of threads to be used',
            'type': int,
            'default': 64,
            'example': ['-n 1', '-n 100']
        },
        'Delay': {
            'name_or_flags': ['-d', '--delay'],
            'help': 'Delay between requests to server',
            'type': float,
            'default': -1.0,
            'example': ['-d 0.1', '-d 60']
        }
    }

    EXAMPLES = [
        '-t 127.0.0.1,192.168.1.0/24 -nt 100 -d 30',
        '--target 192.168.1.1-192.168.2.255,targets.txt',
    ]

    def __init__(self, plgname, desc, defaults, argspec=[]):
        super(CliDns, self).__init__(
            plgname,
            desc,
            CliScanner.EXAMPLES,
            CliScanner.CLI,
            defaults,
            argspec
        )


class CliScanner(Cli):
    CLI = CliDns.CLI.copy()
    CLI.update({
        'Port': {
            "name_or_flags": ['-p', '--port'],
            'help': 'port, list of ports, port range or file containing the aforementioned',
            'action': PortAction,
            #'example': ['-p 80,22', '-p 1-1000,ports.txt'],
            'required': True

        },
    })

    EXAMPLES = [dns_ex + ' ' + scan_ex for dns_ex, scan_ex in zip(CliDns.EXAMPLES, [
        '-p 80,22',
        '--port 1-1000,ports.txt',
    ])]

    def __init__(self, plgname, desc, defaults, argspec=[]):
        super(CliScanner, self).__init__(
            plgname,
            desc,
            CliScanner.EXAMPLES,
            CliScanner.CLI,
            defaults,
            argspec
        )


class CliConnect(Cli):

    CLI = {
        'Target': {
            'name_or_flags': ['-t', '--target'],
            'help': 'target ip or url',
            'example': ['-t 192.168.1.1', '-t mydomain.org'],
            'required': True
        },
        'Port': {
            "name_or_flags": ['-p', '--port'],
            'help': 'port',
            'type': int,
            'example': ['-p 80'],
            'required': True
        },
    }

    EXAMPLES = [
        '-t 127.0.0.1,192.168.1.0/24 -nt 100 -d 30 --port 1-1000,ports.txt',
        '--target 192.168.1.1-192.168.2.255,targets.txt -p 80,22',
    ]

    def __init__(self, plgname, desc, defaults, argspec=[]):
        super(CliConnect, self).__init__(
            plgname,
            desc,
            CliConnect.EXAMPLES,
            CliConnect.CLI,
            defaults,
            argspec
        )


class CliExploit(Cli):

    CLI = {
        'Target': {
            'name_or_flags': ['-t', '--target'],
            'help': 'target ip or url',
            'example': ['-t 192.168.1.1', '-t mydomain.org'],
            'required': True
        },
        'Port': {
            "name_or_flags": ['-p', '--port'],
            'help': 'port',
            'type': int,
            'example': ['-p 80'],
            'required': True
        },
        'Payload': {
            "name_or_flags": ['-pl', '--payload'],
            'help': 'payload',
        },

    }

    EXAMPLES = [
        '-t 127.0.0.1,192.168.1.0/24 -nt 100 -d 30 --port 1-1000,ports.txt -pl payload.txt',
        '--target 192.168.1.1-192.168.2.255,targets.txt -p 80,22',
    ]

    def __init__(self, plgname, desc, defaults, argspec=[]):
        super(CliExploit, self).__init__(
            plgname,
            desc,
            CliExploit.EXAMPLES,
            CliExploit.CLI,
            defaults,
            argspec
        )


class CliBruteforcer(Cli):

    CLI = CliScanner.CLI.copy()
    CLI.update({
        'Wildcards': {
            'name_or_flags': ['-w', '--wildcards'],
            'help': 'enable wildcards, expand strings according to python regex',
            'action': 'store_true',
        },

        'user': {
            'name_or_flags': ['-u', '--user'],
            'help': 'username, list of usernames, or file containing the aforementioned',
            'action': InputAction,
            'example': ['-u root,www,git,users.txt', '-w -u test\\d'],
            'required': True
        },

        'password': {
            "name_or_flags": ['-pw', '--password'],
            'help': 'password, list of passwords, or file containing the aforementioned',
            'action': InputAction,
            'example': ['-pw pass,toor,test,pass.txt', '-w -pw test\\d'],
            'required': True
        },
    })

    EXAMPLES = [
        '-t 127.0.0.1,192.168.1.0/24 -nt 100 -d 30 --port 1-1000,ports.txt -pl payload.txt -u user1,user2 -w -pw pass\\d',
        '--target 192.168.1.1-192.168.2.255,targets.txt -p 80,22 -u user.txt -pw pass.txt',
    ]

    def __init__(self, plgname, desc, defaults, argspec=[]):
        super(CliBruteforcer, self).__init__(
            plgname,
            desc,
            CliBruteforcer.EXAMPLES,
            CliBruteforcer.CLI,
            defaults,
            argspec
        )


def get_cli(plgclass, plgname, desc, defaults, argspec=[]):
    if plgclass == ['scanner']:
        return CliScanner(plgname, desc, defaults, argspec)
    elif plgclass == ['dns']:
        return CliDns(plgname, desc, defaults, argspec)
    elif plgclass == ['connect']:
        return CliConnect(plgname, desc, defaults, argspec)
    elif plgclass == ['exploit']:
        return CliExploit(plgname, desc, defaults, argspec)
    elif plgclass == ['bruteforce']:
        return CliBruteforcer(plgname, desc, defaults, argspec)
    else:
        raise Exception('Unknown Plugin class')
