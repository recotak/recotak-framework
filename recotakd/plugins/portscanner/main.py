from ctools import cScanner as cs
from ctools import cProbeparse
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
import ccdClasses as ccd
import argparse
import socket
import sys

DESCRIPTION = "ps port scanner scans ports."
PORTS = "80"

timeout = 5  # socket timeout
blocking = True  # socket blocking
probing = False  # banner grabbing

dbhandler = None  # ccd database handler

def do_scan(target):
    info = None
    addr, hostname = target
    if isinstance(addr, tuple):
        ip = addr[0]
        port = addr[1]

        addr_string = "%s:%d (%s) " % (ip, port, hostname)

    else:
        ip = addr
        port = hostname
        hostname = ""

        addr_string = "%s:%d " % (ip, port)

    if not probing:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        try:
            s.connect((ip, port))
            print(addr_string)
            info = ["", "", ""]
        except (socket.timeout, socket.error):
            pass
        finally:
            s.close()

    else:
        ps = cProbeparse.Probeparser(port)
        requests = ps.get_requests()
        for r in requests:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(timeout)
                s.connect((ip, port))
            except (socket.timeout, socket.error):
                break

            try:
                s.sendall(r.decode("string-escape"))
                banner = s.recv(4096)
            except (socket.timeout, socket.error):
                continue
            finally:
                s.close()

            if banner:
                info = ps.parse(banner)
                if info:
                    print(addr_string + " ".join(info))
                    break

    if info and dbhandler:
        pr = ccd.PortscanResult(
            ip=ip,
            port=port,
            state="open",
            protocol=info[0],
            service=info[1],
            version=info[2],
            fqdn=hostname,
        )
        try:
            dbhandler.add(pr)
        except ccd.InvalidDBEntryError as e:
            print("Failed to store result:'%s'." % str(e))

        if hostname:
            dnsr = ccd.DnsscanResult(
                ip=ip,
                fqdn=hostname,
            )
            try:
                dbhandler.add(dnsr)
            except ccd.InvalidDBEntryError as e:
                print("Failed to store result:'%s'." % str(e))


def main(dbh, args):
    global dbhandler
    global timeout
    global probing
    global blocking

    dbhandler = dbh
    try:
        args = main.parser.parse_args(args)
    except:
        main.parser.print_help()
        sys.exit(1)

    if not (args.targets or args.targetfile):
        main.parser.print_help()
        return

    timeout = args.timeout
    blocking = args.blocking
    probing = args.probing

    ps = cs.cScanner(cb_scan=do_scan,
                     max_threads=args.threads,
                     dns_resolve=args.probing)
    ps.set_ports(args.ports.split(","))
    if args.targets:
        ps.add_targets(args.targets)

    if args.targetfile:
        ps.add_target_file(args.targetfile)
    ps.set_randomness(args.randomness)

    try:
        ps.start()
        ps.join()
    except KeyboardInterrupt:
        ps.terminate()

def register():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("-A",
                        help="make fingerprint and resolve dns",
                        action="store_true",
                        dest="probing")
    parser.add_argument("-p",
                        help="port list to scan (e.g. -p80,443) (default %s)" % str(PORTS),
                        dest="ports",
                        default=PORTS)
    parser.add_argument("-nb",
                        action="store_true",
                        dest="blocking",
                        help="set socket to non-blocking (default: blocking)")
    parser.add_argument("--timeout",
                        help="set socket timemout (default: 5)",
                        type=float,
                        default=5)
    parser.add_argument("--threads",
                        help="max amount of threads that should scan (default: 64)",
                        type=int,
                        default=64)
    parser.add_argument("--randomness",
                        help="the higher the number, the more random are "
                             "targets scanned (1 no randomness, 2 easy "
                             "randomn, 10 default, >100 incredible "
                             "randomness with slow performance) (default 10)",
                        type=int,
                        default=10)

    group = parser.add_argument_group("targets",
                                      description="passing ips or hosts is "
                                                  "done via the '-t' or '-i'")

    group.add_argument("-t",
                        help="whitespace separated list of ips or hostnames "
                             "to scan (e.g -t google.de heise.de)",
                        nargs="+",
                        dest="targets")
    group.add_argument("-i",
                        help="File containing targets. (e.g. -i /tmp/ips.txt)",
                        dest="targetfile")

    setattr(main, "parser", parser)



    plugin = ccd.Plugin(
        # plugin name
        "ps",
        # categories the plugin ought to be listed in
        ["scanner/ports"],
        # database template to store data
        dbtemplate=[ccd.Tmpl.PORTSCAN, ccd.Tmpl.DNSSCAN],
        # help string
        help=parser.format_help()
    )
    plugin.execute = main
    #plugin.direct = True
    return plugin

if __name__ == "__main__":
    register()
    main(None, sys.argv[1:])
