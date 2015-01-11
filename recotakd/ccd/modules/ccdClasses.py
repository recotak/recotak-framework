from ccdCli import *
import inspect

# Copyright (c) 2014, curesec GmbH
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
# conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
# of conditions and the following disclaimer in the documentation and/or other materials
# provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used
# to endorse or promote products derived from this software without specific prior written
# permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

class Category():

    """ A category contains different plugins. It can be seen as pseudo
        directory which can be navigated through.
    """

    def __init__(self, name):
        self.name = name
        self._content = []

    def listContent(self):
        return self._content

    def __contains__(self, name):
        for c in self._content:
            if c.name == name:
                r = True
                break
        else:
            r = False

        return r


class Plugin():
    """
    A plugin is a server side tool that is executed in its own ccd
    context. The plugin is added to database and can be executed.

    It consists of
        name            the name of the plugin
        categories      Each plugin can be assigned multiple categories. The
                        structure is similar to a path. For instance, this is a
                        list of one category: ["scanner/dns"] every
                        sub'directory' is a sub category. Hence the plugin is
                        assigned the dns category, which is a sub category of
                        scanner. Categories that do not exist, are
                        automatically created.
        dbtemplate      Every plugin has write access to a database. To
                        indicate the database which the plugin wants to write
                        to, it needs to pass the corresponding template. The
                        following list registers for acces to the dnsscan
                        table: [ccd.Tmpl.DNSSCAN]
        help            help text of the plugin. The help text is shown by the
                        client on behalf of the plugin in case of a "--help"
                        plugin's argument

    """

    def __init__(self,
                 name,
                 categories=[],
                 dbtemplate=[],
                 help=""):
        self.name = name
        self.categories = categories
        self.interactive = False
        self.runasroot = False
        self.direct = False
        self.dbtemplate = dbtemplate
        self.help = help
        self.cli = {}
        self.extra = {}

    def execute(self):
        """ need to be overwritten """
        raise Exception("Plugin's execute method is not overwritten.")


class Plugin2(Plugin):
    """
    A plugin is a server side tool that is executed in its own ccd
    context. The plugin is added to database and can be executed.

    It consists of
        name            the name of the plugin
        categories      Each plugin can be assigned multiple categories. The
                        structure is similar to a path. For instance, this is a
                        list of one category: ["scanner/dns"] every
                        sub'directory' is a sub category. Hence the plugin is
                        assigned the dns category, which is a sub category of
                        scanner. Categories that do not exist, are
                        automatically created.
        dbtemplate      Every plugin has write access to a database. To
                        indicate the database which the plugin wants to write
                        to, it needs to pass the corresponding template. The
                        following list registers for acces to the dnsscan
                        table: [ccd.Tmpl.DNSSCAN]
        help            help text of the plugin. The help text is shown by the
                        client on behalf of the plugin in case of a "--help"
                        plugin's argument

    """

    def __init__(self,
                 execfunc=None,
                 plgname='',
                 plgclass='',
                 plgauthor='unknown',
                 desc='',
                 gainroot=False,
                 interactive=False,
                 direct=False,
                 rank='experimental',
                 cli={},
                 defaults={},
                 extra_data=None):

        if not plgclass:
            raise Exception('ERROR: no plugin class specified')

        if not plgname:
            raise Exception('ERROR: no plugin name specified')

        self.execute = execfunc

        # those are handled by the framework
        argspec = ['verbose', 'timeout', 'delay', 'threads', 'wildcards']
        if self.execute is not None:
            argspec.extend(inspect.getargspec(self.execute).args)
            argspec = map(lambda t: t.lower(), argspec)
        else:
            argspec = []

        #print
        #print '-' * 80
        #print plgname
        #print repr(execfunc)
        #print repr(argspec)
        #print '-' * 80
        #print

        self.name = plgname
        self.categories = plgclass
        self.plgauthor = plgauthor
        self.desc = desc
        self.interactive = interactive
        self.runasroot = gainroot
        self.direct = direct
        self.dbtemplate = get_tmpl(plgclass)
        self.help = ''

        self.cli = get_cli(plgclass, plgname, desc, defaults, argspec)
        self.cli.update(cli)
        self.parser = self.cli.make_parser()
        self.extra = extra_data
        self.extra_class = self.extra.__class__

    def execute(self):
        """ need to be overwritten """
        raise Exception("Plugin's execute method is not overwritten.")


class CCDError(Exception):
    def __init__(self, f):
        self.value = f

    def __str__(self):
        return self.value


class MissingFileError(CCDError):
    pass


class InvalidArgumentError(CCDError):
    pass


def get_tmpl(plgclass):
    if plgclass == ['scanner']:
        return [Tmpl.TARGETDNS, Tmpl.TARGET, Tmpl.TARGET_DNS_REL, Tmpl.SERVICE]
    elif plgclass == ['dns']:
        return [Tmpl.TARGETDNS, Tmpl.TARGET, Tmpl.TARGET_DNS_REL]
    elif plgclass == ['bruteforce']:
        return [Tmpl.TARGETDNS, Tmpl.TARGET, Tmpl.TARGET_DNS_REL, Tmpl.SERVICE, Tmpl.BRUTEFORCE2]
    elif plgclass == ['single_bruteforce']:
        return [Tmpl.TARGETDNS, Tmpl.TARGET, Tmpl.TARGET_DNS_REL, Tmpl.SERVICE, Tmpl.BRUTEFORCE2]
    elif plgclass == ['exploit']:
        return [Tmpl.TARGETDNS, Tmpl.TARGET, Tmpl.TARGET_DNS_REL]
    elif plgclass == ['connect']:
        return [Tmpl.TARGETDNS, Tmpl.TARGET, Tmpl.TARGET_DNS_REL]
    else:
        raise Exception('Unknown Plugin class')

#####################################################
#           database functionality                  #
#####################################################

class Tmpl:
    ###################
    ## NEW DB LAYOUT ##
    ###################
    TARGET = 1001
    TARGETDNS = 1002
    TARGET_DNS_REL = 1003
    SERVICE = 2001
    LOGIN = 3001
    BRUTEFORCE2 = 4001

    #############
    ## SCANNER ##
    #############
    PORTSCAN = 101
    DNSSCAN = 102
    WHOIS = 103
    RIPESCAN = 104
    RPCINFO = 105
    DIRSCAN = 106
    SHOWMOUNT = 107
    TRACEROUTE = 108
    FINGERPRINT = 109
    SSL_INFO = 110
    HEARTBLEED = 111
    ZONETRANSFER = 112
    DNSVERSION = 113
    GEOIP = 114
    SSHBANNER = 115

    ###################
    ## SEARCHENGINES ##
    ###################
    SE_LINK_CRAWLER = 201

    ################
    ## BRUTEFORCE ##
    ################
    BRUTEFORCE = 300
    SSH_BRUTEFORCE = 301
    FTP_BRUTEFORCE = 302
    MYSQL_BRUTEFORCE = 303
    TELNET_BRUTEFORCE = 304
    HTTP_BRUTEFORCE = 305
    RLOGIN_BRUTEFORCE = 306
    RSH_BRUTEFORCE = 307

    MAIL_ACCOUNT = 401
    SMTPUSER_BRUTEFORCE = 402
    DIR_BRUTEFORCE = 403
    SSH_USER_ENUM = 404


# database errors
class InvalidDBEntryError(CCDError):
    def __init__(self, e):
        self.value = "Invalid entry type: %s!" % e


class InvalidDBTableError(CCDError):
    def __init__(self, t):
        self.value = "Invalid table: %s!" % t


class InvalidDBTemplateError(CCDError):
    def __init__(self, t):
        self.value = "Invalid template type:%s" % t


class RipescanResult(object):
    """ Result of ripescan. RipescanResult are passed to database handlers
        to make ripescanning results persistent.
    """
    def __init__(self, ip, search):
        self.ip = ip
        self.search = search


class DnsscanResult(object):
    """ Result of dnsscan. DnsscanResult are passed to database handlers
        to make dnsscanning results persistent.
    """
    def __init__(self, ip, fqdn):
        self.ip = ip
        self.fqdn = fqdn


class SELinkResult(object):
    """
    Result of search engine link crawler
    """

    def __init__(self, qid, host, query, count, link, success):
        self.queryid = qid
        self.host = host
        self.query = query
        self.count = count
        self.link = link
        self.success = success


class MailAccountResult(object):

    def __init__(self, protocol, cryptolayer, user, password, ip, port, fqdn=''):
        self.protocol = protocol
        self.cryptolayer = cryptolayer
        self.user = user
        self.password = password
        self.ip = ip
        self.fqdn = fqdn
        self.port = port


class PortscanResult(object):
    """ Result of portscan. PortscanResult are passed to database handlers
        to make portscanning results persistent.
    """

    def __init__(self, ip, fqdn, port, state, protocol="", service="", version=""):
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.version = version
        self.fqdn = fqdn


class WhoisResult(object):

    def __init__(self, ip, adminhandle="", techhandle="", country="",
                 inetnum="", netname=""):
        self.ip = ip
        self.adminhandle = adminhandle
        self.techhandle = techhandle
        self.country = country
        self.inetnum = inetnum
        self.netname = netname


class SshUserEnumResult(object):
    def __init__(self, user, ip, port, fqdn=''):
        self.user = user
        self.ip = ip
        self.fqdn = fqdn
        self.port = port


class SshBannerResult(object):
    def __init__(self, banner, ip, port, fqdn=''):
        self.banner = banner
        self.ip = ip
        self.fqdn = fqdn
        self.port = port


class SshBruteforceResult(object):
    def __init__(self, user, password, host, port):
        self.user = user
        self.password = password
        self.host = host
        self.port = port


class DirBruteforceResult(object):
    def __init__(self, netloc, status, path, filename, info, ip='0.0.0.0', fqdn=''):
        self.ip = ip
        self.fqdn = fqdn
        self.netloc = netloc
        self.status = status
        self.path = path
        self.filename = filename
        self.info = info


class FtpBruteforceResult(object):
    def __init__(self, user, password, host, port):
        self.user = user
        self.password = password
        self.host = host
        self.port = port


class HttpBruteforceResult(object):
    def __init__(self, user, password, path, ip, port, fqdn=''):
        self.user = user
        self.password = password
        self.ip = ip
        self.port = port
        self.fqdn = fqdn
        self.path = path


class MysqlBruteforceResult(object):
    def __init__(self, user, password, host, port):
        self.user = user
        self.password = password
        self.host = host
        self.port = port


class RshBruteforceResult(object):
    def __init__(self, host, lport, rport, localusername, remoteusername):
        self.host = host
        self.lport = lport
        self.rport = rport
        self.localusername = localusername
        self.remoteusername = remoteusername


class RloginBruteforceResult(object):
    def __init__(self, host, lport, rport, localusername, remoteusername, password):
        self.host = host
        self.lport = lport
        self.rport = rport
        self.localusername = localusername
        self.remoteusername = remoteusername
        self.password = password


class TelnetBruteforceResult(object):
    def __init__(self, user, password, host, port):
        self.user = user
        self.password = password
        self.host = host
        self.port = port


class RpcinfoResult(object):
    def __init__(self, program, program_id, version, protocol, ip, port, fqdn=''):
        self.ip = ip
        self.fqdn = fqdn
        self.port = port
        self.program = program
        self.program_id = program_id
        self.version = version
        self.protocol = protocol


class ShowmountResult(object):
    def __init__(self, export, client, ip, port, fqdn=''):
        self.ip = ip
        self.port = port
        self.fqdn = fqdn
        self.export = export
        self.client = client


class TracerouteResult(object):
    def __init__(self, start, end, hops):
        self.start = start
        self.stop = end
        self.hops = hops


class FingerprintResult(object):
    def __init__(self, banner, ip, port, fqdn=''):
        self.host = ip
        self.port = port
        self.banner = banner


class DirscanResult(object):
    def __init__(self, osvdb, uri, comment, ip, port, fqdn=''):
        self.port = port
        self.ip = ip
        self.fqdn = fqdn
        self.osvdb = osvdb
        self.uri = uri
        self.comment = comment


class SmtpUserEnumResult(object):
    def __init__(self, command, username, ip, port, fqdn=''):
        self.port = port
        self.ip = ip
        self.fqdn = fqdn
        self.command = command
        self.username = username


class SslInfoResult(object):
    def __init__(self, cs, ip, port, fqdn=''):
        self.ip = ip
        self.port = port
        self.fqdn = fqdn
        self.cs = cs


class HeartbleedResult_NV(object):
    def __init__(self, tlsv, ip, port, fqdn='', risk=0):
        self.ip = ip
        self.port = port
        self.fqdn = fqdn
        self.tlsv = tlsv
        self.risk = risk


class HeartbleedResult(object):
    def __init__(self, sample, tlsv, ip, port, fqdn='', risk=0):
        self.ip = ip
        self.port = port
        self.fqdn = fqdn
        self.sample = sample
        self.tlsv = tlsv
        self.risk = risk


class DnsRecordResult(object):
    def __init__(self, domainame='', ttl=0, rclass='', rtype='', rdata=''):
        self.domainame = domainame  # the domain name of the object
        self.ttl = ttl  # time to live
        self.rclass = rclass  # protocoll class [IN, CH, HS, CS]
        self.rtype = rtype  # resource record type [A, AAAA, MX, ...]
        self.rdata = rdata  # resource data


class DnsVersionResult(object):
    def __init__(self, bindversion, ip, port, fqdn=''):
        self.bindversion = bindversion
        self.ip = ip
        self.port = port
        self.fqdn = fqdn


class GeoipResult(object):
    def __init__(self,
                 ip='0.0.0.0',
                 iprange='',
                 geoname_id=0,
                 continent_code=0,
                 continent_name='',
                 country_iso_code=0,
                 country_name='',
                 subdivision_iso_code=0,
                 subdivision_name='',
                 city_name='',
                 metro_code=0,
                 time_zone='',
                 **kwargs
                 ):
        self.ip = ip
        self.iprange = iprange
        self.geoname_id = geoname_id
        self.continent_code = continent_code
        self.continent_name = continent_name
        self.country_iso_code = country_iso_code
        self.country_name = country_name
        self.subdivision_iso_code = subdivision_iso_code
        self.subdivision_name = subdivision_name
        self.city_name = city_name
        self.metro_code = metro_code
        self.time_zone = time_zone
        self.extra = ', '.join(['%s: %s' % (k,str(v)) for k, v in kwargs.items()])


###################
## NEW DB LAYOUT ##
###################

class TargetResult(object):
    def __init__(self,
                 ip='0.0.0.0',
                 info='',
                 fqdn='',
                 ):
        self.ip = ip
        self.info = info
        self.fqdn = fqdn

class TargetDnsResult(object):
    def __init__(self,
                 fqdn='',
                 domain='',
                 root_zone='',
                 info='',
                 ip=None,
                 ):
        self.ip = ip
        self.fqdn = fqdn
        self.domain = domain
        self.root_zone = root_zone
        self.info = info

class ServiceResult(object):

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
                 ):
        # target
        self.ip = ip
        self.fqdn = fqdn
        self.domain = domain
        self.root_zone = root_zone

        # service
        self.port = port
        self.state = state
        self.protocol = protocol
        self.service = service
        self.version = version
        self.info = info


class TargetDnsRelResult(object):
    def __init__(self,
                 target_id,
                 targetdns_id):
        pass


class BruteforceResult(object):
    def __init__(self,
                 username='',
                 password='',
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
                 ):

        # target
        self.ip = ip
        self.fqdn = fqdn
        self.domain = domain
        self.root_zone = root_zone

        # service
        self.port = port
        self.state = state
        self.protocol = protocol
        self.service = service
        self.version = version
        self.info = info

        # bruteforce
        self.username = username
        self.password = password

class BruteforceResult2(object):
    def __init__(self,
                 username='',
                 password='',
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
                 ):

        # target
        self.ip = ip
        self.fqdn = fqdn
        self.domain = domain
        self.root_zone = root_zone

        # service
        self.port = port
        self.state = state
        self.protocol = protocol
        self.service = service
        self.version = version
        self.info = info

        # bruteforce
        self.username = username
        self.password = password
