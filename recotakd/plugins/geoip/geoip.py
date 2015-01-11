#!/usr/bin/env python2

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
# Download databases from:
# http://dev.maxmind.com/geoip/geoip2/geolite2/
# http://geolite.maxmind.com/download/geoip/database/GeoLite2-City-CSV.zip
# http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip

# Examples:
# ./geoip-v02.py -ipcountry 87.162.33.167
# ./geoip-v02.py -ipcity 87.162.33.167
# ./geoip-v02.py -city Berlin"
# ./geoip-v02.py -city "New York"
# ./geoip-v02.py -country Germany

from __future__ import with_statement
import argparse
from ctools import cUtil
import sys
import os
from difflib import SequenceMatcher
import ccdClasses as ccd


RAT_LIMIT = 0.7


class GeoIP(object):
    countryblockfile = "GeoLite2-Country-CSV_20141104/GeoLite2-Country-Blocks.csv"
    countrylocationfile = "GeoLite2-Country-CSV_20141104/GeoLite2-Country-Locations.csv"
    cityblockfile = "GeoLite2-City-CSV_20141104/GeoLite2-City-Blocks.csv"
    citylocationfile = "GeoLite2-City-CSV_20141104/GeoLite2-City-Locations.csv"

    @staticmethod
    def print_geoip(geoip_result):

        """ Print information form one line of parsed geoip db data

        Input:
            geoip_result    ccdClasses.GeoipResult instance
        """

        fmt = '{:30}:{:}'
        print fmt.format('ip', str(geoip_result.ip))
        print fmt.format('iprange', str(geoip_result.iprange))
        print fmt.format('geoip_result', str(geoip_result.geoname_id))
        print fmt.format('continent_code', str(geoip_result.continent_code))
        print fmt.format('continent_name', str(geoip_result.continent_name))
        print fmt.format('untry_iso_code', str(geoip_result.country_iso_code))
        print fmt.format('country_name', str(geoip_result.country_name))
        print fmt.format('subdivision_iso_code', str(geoip_result.subdivision_iso_code))
        print fmt.format('subdivision_name', str(geoip_result.subdivision_name))
        print fmt.format('city_name', str(geoip_result.city_name))
        print fmt.format('metro_code', str(geoip_result.metro_code))
        print fmt.format('time_zone', str(geoip_result.time_zone))

    @staticmethod
    def iptoname(ip, blockfile, locationfile):
        # network_start_ip,network_mask_length,geoname_id,...
        headerline = GeoIP.getheaderline(blockfile)
        ip, iprange, blockline = GeoIP.getlinefromip(ip, blockfile)
        if not blockline:
            print("Error: IP address not found")
            return
        splits1 = headerline.split(",")
        splits2 = blockline.split(",")
        gip_dict = dict(zip(splits1, splits2))
        gip_dict['ip'] = ip
        gip_dict['iprange'] = iprange
        gip_result = ccd.GeoipResult(**gip_dict)
        GeoIP.print_geoip(gip_result)
        #print(splits1[2] + ": " + splits2[2])
        #print(splits1[3] + ": " + splits2[3])
        #print(splits1[4] + ": " + splits2[4])
        #print(splits1[5] + ": " + splits2[5])
        #print(splits1[6] + ": " + splits2[6])
        #print(splits1[7] + ": " + splits2[7])
        #print(splits1[8] + ": " + splits2[8])
        #print(splits1[9] + ": " + splits2[9])
        # geoname_id,continent_code,continent_name,country_iso_code,country_name,...
        headerline = GeoIP.getheaderline(locationfile)
        locationline = GeoIP.getinfofromid(splits2[2], locationfile)
        splits1 = headerline.split(",")
        splits2 = locationline.split(",")
        gip_dict = dict(zip(splits1, splits2))
        gip_result = ccd.GeoipResult(**gip_dict)
        print
        GeoIP.print_geoip(gip_result)
        #print(splits1[0] + ": " + splits2[0])
        #print(splits1[1] + ": " + splits2[1])
        #print(splits1[2] + ": " + splits2[2])
        #print(splits1[3] + ": " + splits2[3])
        #print(splits1[4] + ": " + splits2[4])
        #print(splits1[5] + ": " + splits2[5])
        #print(splits1[6] + ": " + splits2[6])
        #print(splits1[7] + ": " + splits2[7])
        #print(splits1[8] + ": " + splits2[8])
        #print(splits1[9] + ": " + splits2[9])

    @staticmethod
    def getlinefromip(ip, blockfile):
        with openany(blockfile, "r") as f:
            # skip header line
            f.readline()
            for line in f:
                # a line looks like this:
                # ::ffff:1.0.128.0,113,1605651,1605651,,,,,0,0
                startip = line.split(",")[0].split(":")[-1]
                # some lines contain ip6 but not ip4 addresses
                if not startip:
                    continue
                # I don't understand the logic behind subtracting 96 but it works
                netrange = int(line.split(",")[1]) - 96
                # http://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python
                #if IPAddress(ip) in IPNetwork(startip + "/" + str(netrange)):
                if cUtil.ip_in_netmask(ip, (startip, netrange)):
                    #print("range: " + startip + "/" + str(netrange))
                    return ip, startip + '/' + str(netrange), line.strip()
        return ""

    @staticmethod
    def getinfofromid(id, locationfile):
        with openany(locationfile, "r") as f:
            headerline = f.readline()
            for line in f:
                # a line looks like this:
                # 2921044,EU,Europe,DE,Germany,,,,,
                if line.startswith(id + ","):
                    return line.strip()
        return ""

    @staticmethod
    def getheaderline(path):
        with openany(path, "r") as f:
            line = f.readline().strip()
        return line

    @staticmethod
    # mytype is either "country" or "city"
    def nametoip(mytype, name, blockfile, locationfile):
        myid = GeoIP.getidfromname(mytype, name, locationfile)
        if not isinstance(myid, str):
            if mytype == "country":
                print("Error: County not found")
            else:
                print("Error: City not found")
            if isinstance(myid, dict) and myid.keys():
                print "Did you mean: %s ?" % ", ".join(myid.keys())
            return
        GeoIP.getrangesfromid(myid, blockfile)

    @staticmethod
    def getidfromname(mytype, name, locationfile):
        similar = {}
        with openany(locationfile, "r") as f:
            # skip header line
            headerline = f.readline()
            for line in f:
                line = line.strip()
                splits = line.split(",")
                if mytype == "country":
                    if len(splits) < 5:
                        continue
                    # some names are saved with double quotes
                    # 2921044,EU,Europe,DE,Germany,,,,,
                    # 6252001,NA,"North America",US,"United States",,,,,
                    country = splits[4].replace('\"', '')
                    match_ratio = SequenceMatcher(None, country.lower(), name.lower()).ratio()
                    if match_ratio == 1.0:
                        return splits[0]
                    elif match_ratio > RAT_LIMIT:
                        similar[country] = match_ratio
                else:
                    # city names containing space characters are saved with underscore characters
                    # 4776222,NA,"North America",US,"United States",VA,Virginia,Norfolk,544,America/New_York
                    name = name.replace(" ", "_")
                    city = splits[-1].split('/')[-1]
                    match_ratio = SequenceMatcher(None, city.lower(), name.lower()).ratio()
                    if match_ratio == 1.0:
                        return splits[0]
                    elif match_ratio > RAT_LIMIT:
                        similar[city] = match_ratio
        return similar

    @staticmethod
    def getrangesfromid(myid, blockfile):
        with openany(blockfile, "r") as f:
            # skip header line
            f.readline()
            for line in f:
                # a line looks like this:
                # ::ffff:1.0.128.0,113,1605651,1605651,,,,,0,0
                splits = line.split(",")
                geoid = splits[2]
                if geoid == myid:
                    startip = splits[0].split(":")[-1]
                    # some lines do not contain ip4 addresses
                    if not startip:
                        continue
                    # I don't understand the logic behind subtracting 96
                    netrange = int(splits[1]) - 96
                    print(startip + "/" + str(netrange))

    @staticmethod
    def checkiffileexists(path):
        try:
            fd = openany(path, "r")
            fd.close()
        except IOError:
            print("Unable to open " + path)
            exit(1)


def parse(argv):
    description = \
        """
    Get geological location of an IP address. Or get IP addresses belonging to a city or country.
    Based on the databases from:
        http://dev.maxmind.com/geoip/geoip2/geolite2/
        http://geolite.maxmind.com/download/geoip/database/GeoLite2-City-CSV.zip
        http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip

    Examples:

        exec geoip.plg -ipcountry 91.250.101.170
        exec geoip.plg -ipcity 91.250.101.170
        exec geoip.plg -city Berlin
        exec geoip.plg -city "New York"
        exec geoip.plg -country Germany
        """

    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-db',
                        help='Path to geoip database directory, which has to contain the following file paths: \n' \
                        '  - GeoLite2-Country-CSV_20141104/GeoLite2-Country-Blocks.csv\n' \
                        '  - GeoLite2-Country-CSV_20141104/GeoLite2-Country-Locations.csv\n' \
                        '  - GeoLite2-City-CSV_20141104/GeoLite2-City-Blocks.csv\n' \
                        '  - GeoLite2-City-CSV_20141104/GeoLite2-City-Locations.csv',
                        )

    group = parser.add_mutually_exclusive_group(required="True")
    group.add_argument('-ipcountry', dest='ipcountry',
                       help='Get country associated with ip',
                       )
    group.add_argument('-ipcity', dest='ipcity',
                       help='Get city associated with ip',
                       )
    group.add_argument('-country', dest='country',
                       help='Get all ip addressed belonging to country',
                       )
    group.add_argument('-city', dest='city',
                       help='Get all ip addressed belonging to city',
                       )

    if len(argv) == 0:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(argv)

    if args.db:
        GeoIP.countryblockfile = os.path.join(args.db, GeoIP.countryblockfile)
        GeoIP.checkiffileexists(GeoIP.countryblockfile)

        GeoIP.countrylocationfile = os.path.join(args.db, GeoIP.countrylocationfile)
        GeoIP.checkiffileexists(GeoIP.countrylocationfile)

        GeoIP.cityblockfile = os.path.join(args.db, GeoIP.cityblockfile)
        GeoIP.checkiffileexists(GeoIP.cityblockfile)

        GeoIP.citylocationfile = os.path.join(args.db, GeoIP.citylocationfile)
        GeoIP.checkiffileexists(GeoIP.citylocationfile)

    if args.ipcountry:
        GeoIP.iptoname(args.ipcountry, GeoIP.countryblockfile, GeoIP.countrylocationfile)
    elif args.ipcity:
        GeoIP.iptoname(args.ipcity, GeoIP.cityblockfile, GeoIP.citylocationfile)
    elif args.country:
        GeoIP.nametoip("country", args.country, GeoIP.countryblockfile, GeoIP.countrylocationfile)
    else:
        GeoIP.nametoip("city", args.city, GeoIP.cityblockfile, GeoIP.citylocationfile)

    return args

