#!/usr/bin/env python2

# http://nmap.org/nsedoc/scripts/vmauthd-brute.html
# /usr/share/nmap/scripts/vmauthd-brute.nse

# When testing VMware Workstation:
# Port 902: SSL required
# Port 912: SSL not required

# When testing port 902, the conversation (which required SSL) looked like this (\r and \n omitted):
# < 220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported
# > USER User
# < 331 Password required for User.
# > PASS password
# < 230 User User logged in.

# Or:
# < 220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported
# > USER User
# < 331 Password required for User.
# > PASS wrongpassword
# [Timeout]

# On port 912, the server banner was this (indicating no SSL required):
# < 220 VMware Authentication Daemon Version 1.0, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , ,


from recotak import *
from datetime import datetime
import socket
import ssl

def vmware_authenticate(target, port, username, password, timeout=60, verbose=False):
    ip = target[0]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.settimeout(vmware_authenticate.timeout)
        m = s.recv(1024)
    except Exception as e:
        rLog.log.error("Could not initiate socket.")
        rLog.log.exception(e)
        s.close()

    if vmware_authenticate.verbose:
        rLog.log.debug("Received: %s", m.strip())

    if not m.startswith("220 VMware Authentication Daemon"):
        rLog.log.warning("Error: Received unexpected response from server.")
        s.close()
        raise StopIteration

    if "SSL Required" in m:
        try:
            if vmware_authenticate.verbose:
                rLog.log.debug("Switching to SSL")
            s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1, server_side=False)
        except socket.error as e:
            rLog.log.exception(e)
            s.close()
            raise StopIteration

    m = "USER %s\r\n" % username
    if vmware_authenticate.verbose:
        rLog.log.debug("Sending: %s", m.strip())
    try:
        s.send(m)
    except socket.error as e:
        rLog.log.warning("Could not send data to server.")
        if vmware_authenticate.verbose:
            rLog.log.exception(e)
        raise StopIteration

    try:
        m = s.recv(1024)
    except socket.error as e:
        rLog.log.error("Socket error")
        if vmware_authenticate.verbose:
            rLog.log.exception(e)
        raise StopIteration
    if vmware_authenticate.verbose:
        rLog.log.debug("Received: %s", m.strip())

    if not m.startswith("331"):
        rLog.log.error("Error: Received unexpected response from server.")
        s.close()
        raise StopIteration

    m = "PASS %s\r\n" % password
    if vmware_authenticate.verbose:
        rLog.log.debug("Sending: %s", m.strip())
    try:
        s.send(m)
    except socket.error as e:
        rLog.log.error("Could not send data to server.")
        if vmware_authenticate.verbose:
            rLog.log.exception(e)
        raise StopIteration

    try:
        m = s.recv(1024)
    except socket.error as e:
        # A timeout might occur when the password is wrong
        # (The other possibility is a "Login incorrect" message.)
        # Originally, I used socket.timeout but this does not work with SSL
        if vmware_authenticate.verbose:
            rLog.log.exception(e)
        rLog.log.error("Failed: %s:%s", username, password)
        s.close()
        raise StopIteration
    if vmware_authenticate.verbose:
        rLog.log.debug("Received: %s", m.strip())
    if m.startswith("230"):
        rLog.log.debug("Success: %s:%s", username, password)
        yield(target, port, username, password)
    else:
        # when I did some testing, there was a timeout when the password was wrong
        # however, there also might be a "Login incorrect" message here
        rLog.log.info("Failed: %s:%s", username, password)

    s.close()

def init(dbh, target=[], port=[], user=[], password=[], verbose=False, timeout=60, **kwargs):

    if verbose:
        rLog.set_verbosity_console('vvvv')

    vmware_authenticate.verbose = verbose
    vmware_authenticate.timeout = timeout

    tuples = cTuples.cTuples(inputs=[target, port, user, password],
                             prep_callback=vmware_authenticate,
                             )
    tuples.start()

    start_time = datetime.now()

    row_fmt = "{:30} {:30} {:30}"
    print 'Bruteforcing vmware logins ...'
    print '-' * 80
    print row_fmt.format('password', 'username', 'server')
    print '-' * 80
    for target, port, username, password in tuples.tuple_q:
        ip = target[0]
        fqdn = ''.join(target[1])
        print row_fmt.format(password, username, ip + ':' + str(port))
        if dbh:
            br = BruteforceResult2(
                ip=ip,
                fqdn=fqdn,
                port=int(port),
                username=username,
                password=password,
                service='vmware',
                state='open',
                protocol='tcp'
            )
            dbh.add(br)

    tuples.join()

    print '-' * 80
    print "Finished in %fs" % cUtil.secs(start_time)

desc = {

    'defaults': {
        'Port': '902',
    },

    "plgclass": ["bruteforce"],

    #plugin name
    "plgname": "vmwarebf",

    #plugin author
    "plgauthor": "willi",

    # description
    "desc": "vmware bruteforcer",

    #root?
    "gainroot": False,

    #interaktiv
    "interactive": False,

    #direct connection
    "direct": False,

    #rank
    "rank": "experimental",

    "execfunc": init,
}

def register():
    plugin = Plugin2(**desc)
    return plugin
