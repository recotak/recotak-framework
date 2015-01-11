""" methods to read config file """

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
import ConfigParser
import logging
import os.path
from pwd import getpwnam
from grp import getgrnam

logger = logging.getLogger("ccd.%s" % __name__)

FILE = "log"
FILE_PLG_DBG = "plg_debug_output.log"

class Config(object):
    pass

def read_config(config_fn):
    """
    read config file and set member variable

    input:
        config_fn       filename of config file

    output:
        option          object that contains extracted configurations

    """
    logger.info("reading config file %s", config_fn)

    config = ConfigParser.RawConfigParser()
    config.read(config_fn)

    # cache to return options
    options = Config()

    # logging
    options.log_level = config.getint("Logging", "level")
    options.log_dir = config.get("Logging", "file")  # directory
    options.log_dest = os.path.join(options.log_dir, FILE)  # file
    options.log_plg_fn = os.path.join(options.log_dir, FILE_PLG_DBG)  # plugin

    # database
    #FIXME BASE64 encoding for url parameters
    dialect = config.get("Database", "dialect")
    user = config.get("Database", "user")
    password = config.get("Database", "password")
    location = config.get("Database", "location")
    database = config.get("Database", "database")
    options.db_url = "{dialect}://{user}:{password}@{location}/{database}".\
                     format(
                         dialect=dialect,
                         user=user,
                         password=password,
                         location=location,
                         database=database
                     )
    options.db_psql_url = "{dialect}://{user}:{password}@{location}".\
                          format(
                              dialect=dialect,
                              user=user,
                              password=password,
                              location=location
                          )
    options.db_psql_db = "postgres"

    # to enable the ccd to use a proxy chain, get servers from
    # config file and store them in a list
    options.useSocks = config.getboolean('Connection', 'useSocks')
    socksserver = []

    _servers = config.get("Connection", "socksServer").split(";")
    for _s in _servers:
        _addr = _s.split(":")
        socksserver.append((_addr[0], int(_addr[1])))

    options.socksserver = socksserver

    # the addr to listen for clients
    _addr = config.get("Connection", "bind").split(":")
    if len(_addr) != 2:
        raise Exception("fatal: Invalid bind option in config!")

    options.addr = (_addr[0], int(_addr[1]))
    options.listenmax = config.getint("Connection", "listenmax")
    options.cert = config.get("Connection", "cert")
    options.cert_key = config.get("Connection", "key")
    options.client_fingerprint = config.get("Connection",
                                            "client_fingerprint").split(",")
    options.ssl_version = config.getint("Connection", "ssl_version")
    options.ssl_enabled = config.getboolean("Connection", "ssl_enabled")

    # plugin
    options.plugindir = config.get("Plugins", "dir")
    _addr_dbg = config.get("Plugins", "bind").split(":")
    if len(_addr_dbg) != 2:
        raise Exception("fatal: Invalid plugin bind option in config!")

    options.addr_dbg = (_addr_dbg[0], int(_addr_dbg[1]))
    options.listenmax_dbg = config.getint("Plugins", "listenmax")
    options.runAsUser = config.get("Plugins", "runas_user")
    options.runAsGroup = config.get("Plugins", "runas_group")

    options.runAsUid = getpwnam(options.runAsUser).pw_uid
    options.runAsGid = getgrnam(options.runAsGroup).gr_gid

    # user
    options.userdir = config.get("User", "dir")
    options.shared_directory = config.get("User", "shared")

    # superadmin
    options.sa_name = config.get("Superadmin", "name")
    options.sa_pwd = config.get("Superadmin", "password")
    options.sa_mail = config.get("Superadmin", "mail")

    options.monitoring = config.getboolean("Monitoring", "activated")

    return options
