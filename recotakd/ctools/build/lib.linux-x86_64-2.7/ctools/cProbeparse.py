import re
import sys
import os

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
__author__ = "curesec"

def valid_port(port, probe):
    return ("ports" not in probe) or (port in probe["ports"])

def to_int(port):
    """
    convert a port string to a list of ports

    input:
        port    port string. e.g:

                    "40" or
                    "1000-1024"

    output:
        ports   list of ports that contains integers. e.g:

                    [40] or
                    [1000, 1001, 1002, 1003, ..]

    """
    ports = []

    try:
        ports.append(int(port))

    except ValueError:
        if "-" in port:
            port = map(int, port.split("-"))
            for p in range(port[0], port[1]):
                ports.append(p)

    return ports

def _get_expression(char, text):
    """
    function extracts the special expression from line, gets
    corresponding options and returns the new line without the
    expression

    input:
        char    identifies the string type
        text    text to examine

    output:
        expr    the reqexpr which is extracted in text
        options regex options which must be applied
        newtext text minus extracted information

    """
    options = []
    newline = expression = ""

    # text needs to start with char:
    # e.g. 'm|ABC XY| ZCD..'
    if not text.startswith(char):
        return expression, options, text

    # get delimiter char (eg: /,|,=)
    # first character after char
    delimiter = text[1]

    # expression is surrounded by delimiter
    splitted = text.split(delimiter)
    expression = splitted[1]
    newline = delimiter.join(splitted[2:]).rstrip()

    # get options
    while newline:
        option = newline[0]
        newline = newline[1:]
        if option == " ":
            break
        else:
            options.append(option)


    return expression, options, newline

def _parse_probe_file(fn="/usr/probes/nmap-service-probes"):
    """
    The probe file must have a format like it is given with the nmap-service-
    probes. For details about the format see:

        http://nmap.org/book/vscan-fileformat.html

    Note: The probeparser is only parses for TCP banners. Other stuff will be
          ignored or do not return a proper result.

    input:
        fn      file name of the probes files

    output:
        a dictionary that contains the parsed information

    the probe dictionary looks like this:

        probes = {

            # a certain probe (e.g. GenericLines)
            GenericLines = {

                # the request that ought to trigger a service banner
                request = '\r\n\r\n',

                # ports that request is usually sent to
                ports = [21, 23, 35, 43, ...],

                # list of reqexpr that match a certain service (e.g. http)
                http = [(regexpr,
                        regex option,
                        productname,
                        version,
                        hostname,
                        info)]

            }

        }

    """
    probes = {}

    try:
        f = open(fn, "r")
    except (OSError, IOError):
        fn = os.path.join(sys.prefix, 'probes/nmap-service-probes')
        f = open(fn, "r")

    try:
        for line in f:
            # find TCP probe section
            if not line.startswith("Probe TCP "):
                continue

            # get name of the probe
            line = line[len("Probe TCP "):]
            probename = line.split()[0]

            # get request
            line = line[len(probename)+1:]
            probestring, options, line = _get_expression("q", line)

            # add new probe
            if not probename in probes:
                probes[probename] = dict(request=probestring)

            probe = probes[probename]

            # now iter lines within probe
            for line in f:

                # check for comment that heads a
                # new probe section
                if line.startswith("#") and "###NEXT PROBE###" in line:
                    break

                # add ports to probe
                if line.startswith("ports "):
                    ports = []
                    for port in line[len("ports "):].split(","):
                        ports.extend(to_int(port))

                    probe["ports"] = ports
                    continue

                # add totalwaitms used by null probe
                elif line.startswith("totalwaitms "):
                    probe["totalwaitms"] = int(line[len("totalwaitms "):])

                # add fallback directive
                elif line.startswith("fallback "):
                    probe["fallback"] = line[len("fallback "):].split(",")
                    continue

                # rarity directive
                elif line.startswith("rarity "):
                    probe["rarity"] = int(line[len("rarity "):])
                    continue

                # from here on, we are interested in match directives
                elif (not line.startswith("match ") and not
                      line.startswith("softmatch ")):
                    continue

                org = line
                if line.startswith("match "):
                    line = line[len("match "):]
                else:
                    line = line[len("softmatch "):]

                # get service
                service = line.split()[0]
                line = line[len(service)+1:]

                # get pattern
                pattern, options, line = _get_expression("m", line)

                # check for matching options 'i' (case-sensitivity)
                # and 's' (including newsline into .)
                option = 0
                for o in options:
                    if o == "i":
                        option |= re.IGNORECASE
                    elif o == "s":
                        option |= re.DOTALL


                # get name
                # Includes the vendor and often service name and is of the form
                # Sun Solaris rexecd, ISC BIND named, or Apache httpd
                name, options, line = _get_expression("p", line)

                # get version
                # The application version number, which may include
                # non-numeric characters and even multiple words.
                version, options, line = _get_expression("v", line)

                # get hostname
                # The hostname (if any) offered up by a service. This is common
                # for protocols such as SMTP and POP3 and is useful because
                # these hostnames may be for internal networks or otherwise
                # differ from the straightforward reverse DNS responses.
                hostname, options, line = _get_expression("h", line)

                # get info
                # Miscellaneous further information which was immediately
                # available and might be useful. Examples include whether an X
                # server is open to unauthenticated connections, or the
                # protocol number of SSH servers.
                info, options, line = _get_expression("i", line)


                # finally add the new service to probe
                if not service in probe:
                    probe[service] = []

                fields = (pattern, option, name, version, info, hostname)
                probe[service].append(fields)

    finally:
        f.close()

    return probes


class Probeparser():
    """
    A probeparser is a class that parses network service banners. To do so,
    is parses a probe file. The probe file must
    have a format like it is given with the nmap-service-probes. For details
    about the format see:

        http://nmap.org/book/vscan-fileformat.html

    The port is specific for a probeparser in order parse the corresponding
    probes.

    Note: The probeparser is only parses for TCP banners. Other stuff will be
          ignored or do not return a proper result.

    a short portscanner example:

            ps = cProbeparse.Probeparser(port=port)
            requests = ps.get_requests()

            for r in requests:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.settimeout(timeout)
                    s.connect((ip, port))
                    s.sendall(r.decode("string-escape"))
                    banner = s.recv(4096)
                except socket.timeout:
                    continue
                except socket.error as e:
                    if e.errno == errno.ECONNREFUSED:
                        continue
                    else:
                        raise
                finally:
                    s.close()

                if banner:
                    info = ps.parse(banner)
                    if info:
                        print("%s:%d - " % (ip, port) + " ".join(info))
                        break



    """
    def __init__(self, port):
        """
        create a new probeparser

        input:
            port    the port to be scanned

        """
        self._probes = _parse_probe_file()
        self._port = port
        self._sent_probes = []

    def get_requests(self):
        """
        returns the request that should be sent in order to get a service
        banner. the list is sortet by nmap rarity. the rare results that
        usually result in a more precise answer. the last elements usually
        return at least something. In order to get a nice result, the order
        should be maintained during the scan.

        output:
            a list of requests to sent

        """
        requests = []

        def sort((k, v)):
            return v["rarity"] if "rarity" in v else -1

        # sort by rarity
        sorted_probes = reversed(sorted(self._probes.iteritems(), key=sort))

        for pname, probe in sorted_probes:

            # if ports a given for that probe, the input port must match
            if not valid_port(self._port, probe):
                continue

            requests.append(probe["request"])
            self._sent_probes.append(probe)

        return requests

    def _get_information(self, banner):
        """
        iterate of all probes and return information that corresponds to given
        banner and port

        input:
            banner      service banner return by server

        output:
            information a tuple that contains the relevant information
            findings    a list of results

        """
        findings = list()
        information = tuple()

        # first, get a probe that actually has the passed port assigned
        for probe in self._sent_probes:

            # we iterator over all probe properties that represent a
            # service
            for key, value in probe.items():
                if key in ("fallback", "ports", "totalwaitms", "request",
                           "rarity"):
                    # they do not represent any service
                    continue

                for regex, option, name, version, info, hostname in value:
                    findings = re.findall(regex, banner, option)

                    # ok, great - we found something so stop here
                    if findings and findings[0]:
                        information = key, name, version, info, hostname
                        break
                else:
                    continue

                break

            else:
                continue

            break

        return findings, information

    def parse(self, banner):
        """
        parse the passed banner to extract information

        input:
            banner      the actual banner returned by server

        output:
            service     name of the service
            version     version of the service
            info        additional information
            hostname    some services return a hostname. return that
                        information

        """
        service = ""
        version = ""
        info = ""
        hostname = ""

        findings, information = self._get_information(banner)

        if not information or not findings:
            return None

        service, name, version, info, hostname = information

        # parse information
        # extract additional information like 'version'
        # and 'info'. We need to replace them within
        # the pattern provided by the nmap database
        if isinstance(findings[0], tuple):

            for k, l in enumerate(findings[0]):
                name = name.replace("$%d"%(k+1), l)
                version = version.replace("$%d"%(k+1), l)
                info = info.replace("$%d"%(k+1), l)
                hostname = hostname.replace("$%d"%(k+1), l)

        else:
                name = name.replace("$1", findings[0])
                version = version.replace("$1", findings[0])
                info = info.replace("$1", findings[0])
                hostname = hostname.replace("$1", findings[0])

        return service, name, version, info, hostname


