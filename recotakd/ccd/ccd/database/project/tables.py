"""
createing projectdb tables and inserting data.
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

Working with project tables is internally handled via  class __ProjectTable.
Inserting data is done in database.project.db via

    for t in projectdb.all_tables:
        if t.validate(entry):
            t.insert(conn, meta, entry, scanid)
            break

Here, it iterated over all project tables and verified that an insertion is
valid. If so, the table's insert method is called.

This module also provides meta information for the project tables, which were
stored in __table_meta. This table holds for instance a description text or a
solution text.

"""

from database.ccdErrors import NotFoundError
from ctools.dns.exceptions import BadUrl, DomainNotFound
from ccdClasses import Tmpl, InvalidDBTemplateError
from ctools.dns import domain as ctools_domain
from ccdClasses import TargetResult
from ccdClasses import TargetDnsRelResult
from ccdClasses import TargetDnsResult
from ccdClasses import ServiceResult
from ccdClasses import RloginBruteforceResult
from ccdClasses import HttpBruteforceResult
from ccdClasses import RshBruteforceResult
from ccdClasses import HeartbleedResult_NV
from sqlalchemy.dialects import postgresql
from ccdClasses import SmtpUserEnumResult
from ccdClasses import FingerprintResult
from ccdClasses import MailAccountResult
from ccdClasses import SshUserEnumResult
from ccdClasses import BruteforceResult
from ccdClasses import BruteforceResult2
from ccdClasses import HeartbleedResult
from ccdClasses import TracerouteResult
from ccdClasses import DnsVersionResult
from ccdClasses import DnsRecordResult
from ccdClasses import SshBannerResult
from ccdClasses import ShowmountResult
from ccdClasses import RipescanResult
from ccdClasses import PortscanResult
from ccdClasses import DnsscanResult
from ccdClasses import RpcinfoResult
from ccdClasses import DirscanResult
from ccdClasses import SslInfoResult
from ccdClasses import SELinkResult
from ccdClasses import WhoisResult
from ccdClasses import GeoipResult
from ccdClasses import DirBruteforceResult
from strings import get_string
import sqlalchemy as sql
import logging

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)

#: some db constraints
MAX_LEN_DOMAIN = 255

#: project tables meta information table name
__table_meta = "_meta_information"


class __ProjectTable(object):
    """
    The project table acts as interface to the project table. It is used
    for creating a table or for querying it.

    major properties:
        name        name of the table to create
        template    which template must be assigned by a plugin to get access
                    is table
        result_type the data passed to insert query must be of this type
        constructor method to create table
        insert      method to insert data into table
        id_desc     integer id of the description. the id is used as reference
                    in the language text file
        id_sol      integer id of the solution. id is used as reference in the
                    language text file
        grouping    a string that indicates a by which column the table should
                    be grouped in case of report generation. the string is
                    formated as follows: <table>:<column> (e.g.
                    dnsscan:domain)

    """

    def __init__(self,
                 name,
                 template,
                 result_type,
                 constructor,
                 insert,
                 id_desc=None,
                 id_sol=None,
                 grouping=None):

        self.name = name
        self.template = template
        self.result_type = result_type
        self._create_table = constructor
        self.insert = insert
        self.id_desc = id_desc
        self.id_sol = id_sol
        self.grouping = grouping

    def create(self, conn, meta):
        """ first, create table. second, add meta information """
        self._create_table(meta)
        self._add_meta_information(conn, meta)

    def _add_meta_information(self, conn, meta):
        """ add information to meta table (eg. description and solution) """
        if not (self.id_desc or self.id_sol or self.grouping):
            return

        try:
            _insert_meta_information(conn,
                                     meta,
                                     self.name,
                                     self.id_desc,
                                     self.id_sol,
                                     self.grouping)

        except sql.exc.IntegrityError as sqlerror:
            if ('duplicate key value violates unique constraint '
                    '"_meta_information_result_table_name_key"' in str(sqlerror)):
                # if table does exist, everything is fine
                pass
            else:
                # otherwise raise the exception
                raise

    def validate(self, entry):
        #print '%s: Entrytype %s -- %s Resulttype' % (self.name, repr(type(entry)), repr(self.result_type))
        if type(entry) == self.result_type:
        #if isinstance(entry, self.result_type):
            return True
        return False


def create_tables(dbconn, dbmeta, templates):
    """ Create the tables in the project database the plugins
        registers for.

        input:
            dbconn      connection object
            dbmeta      sql metadata object
            templates   templates the plugin registers for

    """
    logger.info("creating tables for project")
    create_meta_table(dbmeta)

    # create tables
    for t in templates:
        for table in all_tables:
            if table.template == t:
                table.create(dbconn, dbmeta)
                break
        else:
            raise InvalidDBTemplateError(t)

    return templates

def create_meta_table(meta):
    """
    The meta table contains information about other tables.

    id                  primary key
    result_table_name   name of table to add information about
    description         <int> that represents the description text in strings
                        module
    solution            <int> that represents the description text in strings
                        module
    grouping            grouping information, string

    """

    if __table_meta in meta.tables:
        return

    table = sql.Table(__table_meta, meta,
                      sql.Column("id",
                                 sql.Integer,
                                 primary_key=True,
                                 autoincrement=True),
                      sql.Column("result_table_name",
                                 sql.String,
                                 unique=True,
                                 nullable=False),
                      sql.Column("description",
                                 sql.Integer,
                                 nullable=True),
                      sql.Column("solution",
                                 sql.Integer,
                                 nullable=True),
                      sql.Column("grouping",
                                 sql.String,
                                 nullable=True)

                      )

    table.create(checkfirst=True)


def _insert_meta_information(dbconn, dbmeta, table_name, id_desc, id_sol,
                             grouping):
    """
    Inserts meta information about a result table.

    input:
        conn        database connection
        meta        sqlalchemy meta object
        table_name  name of table to add information about
        id_desc     id of description text
        id_sol      id of solution text
        grouping    grouping information

    """
    values = dict(result_table_name=table_name)

    if id_desc:
        values.update(dict(description=id_desc))

    if id_sol:
        values.update(dict(solution=id_sol))

    if grouping:
        values.update(dict(grouping=grouping))

    with dbconn.begin():
        ins = dbmeta.tables[__table_meta].insert().values(values)
        dbconn.execute(ins)

def get_meta_information(db, table_name):
    """
    Returns the database meta informations.

    input:
        db          tuple containg database meta object and connection
        table_name  name of table to get information from

    output:
        res         database entry

    """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_meta]
        sel = sql.select([tbl.c.description,
                          tbl.c.solution,
                          tbl.c.grouping
                          ]).\
            where(tbl.c.result_table_name == table_name)
        res = conn.execute(sel).fetchone()

    return res

def get_grouping_information_text(db, table_name):
    """
    Get the content of the grouping column in the database with the given name.

    input:
        table_name  name of table to get grouping information of

    output:
        grouping information

    """
    res = get_meta_information(db, table_name)
    return res[2]

def get_meta_information_text(db, table_name, language):
    """
    Gets the meta data information from database and reads actual strings
    from file.

    input:
        db          tuple containg database meta object and connection
        table_name  name of table to get information from
        language    language of the strings

    output:
        desc        description information of the table
        sol         solution information of the table

    """
    desc = ""
    sol = ""

    # get information from database
    res = get_meta_information(db, table_name)
    if not res or (not res[0] and not res[1]):
        logger.warning("No meta data found in db!")
        return desc, sol

    id_desc = res[0]
    id_sol  = res[1]

    # get data from string file
    try:
        desc = get_string(id_desc, language)
    except NotFoundError as nf:
        logger.error(nf)
        pass

    try:
        sol = get_string(id_sol, language)
    except NotFoundError:
        logger.error(nf)
        pass

    return desc, sol

def __create_table_whois(meta):
    """ Create whois result table. """
    logger.debug("creating whois result table")
    table = sql.Table(table_whois.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      #sql.Column("ip", sql.String, nullable=False),
                      sql.Column("ip", postgresql.INET, nullable=False),
                      sql.Column("adminhandle", sql.String, nullable=True),
                      sql.Column("techhandle", sql.String, nullable=True),
                      sql.Column("country", sql.String, nullable=True),
                      sql.Column("inetnum", sql.String, nullable=True),
                      sql.Column("netname", sql.String, nullable=True),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      extend_existing=True
                      )
    table.create(checkfirst=True)

def __create_table_geoip(meta):
    """ Create geoip result table. """
    logger.debug("creating geoip result table")
    table = sql.Table(table_geoip.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column("ip", postgresql.INET, nullable=False),
                      sql.Column("iprange", sql.String, nullable=True),
                      sql.Column("geoname_id", sql.String, nullable=True),
                      sql.Column("continent_code", sql.Integer, nullable=True),
                      sql.Column("continent_name", sql.String, nullable=True),
                      sql.Column("country_iso_code", sql.Integer, nullable=True),
                      sql.Column("country_name", sql.String, nullable=True),
                      sql.Column("subdivision_iso_code", sql.Integer, nullable=True),
                      sql.Column("subdivision_name", sql.String, nullable=True),
                      sql.Column("city_name", sql.String, nullable=True),
                      sql.Column("metro_code", sql.Integer, nullable=True),
                      sql.Column("timezone", sql.String, nullable=True),
                      sql.Column("extra", sql.String, nullable=True),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      extend_existing=True
                      )
    table.create(checkfirst=True)


def __create_table_ripescan(meta):
    """ Create ripe result table. Return table object. """
    logger.debug("creating ripe result table")
    table = sql.Table(table_ripescan.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column("ip", postgresql.INET, index=True),
                      sql.Column("search", sql.String),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      extend_existing=True
                      )
    table.create(checkfirst=True)


def __create_table_dnsscan(meta):
    """ Create dns result table. Return table object. """
    logger.debug("creating dns result table")
    table = sql.Table(table_dnsscan.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column("ip", postgresql.INET),
                      sql.Column("fqdn", sql.String(MAX_LEN_DOMAIN)),
                      sql.Column("domain", sql.String(MAX_LEN_DOMAIN)),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      extend_existing=True
                      )
    table.create(checkfirst=True)

def __create_table_portscan(meta):
    """ Create portscan result table. """
    logger.debug("creating portscan result table")

    #TODO constraint to have at least Ip or fqdn
    table = sql.Table(table_portscan.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column("port", sql.Integer, nullable=False),
                      sql.Column("ip", postgresql.INET, nullable=True, index=True),
                      sql.Column("fqdn", sql.String, nullable=True),
                      sql.Column("protocol", sql.String),
                      sql.Column("state", sql.String, nullable=False),
                      sql.Column("service", sql.String),
                      sql.Column("version", sql.String),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      extend_existing=True
                      )
    table.create(checkfirst=True)

def __create_table_selink(meta):
    """
    Create search engine result table and the table containing the queries.

    """
    logger.debug("creating search engine query table")
    table_queries = sql.Table(__table_se_link_queries, meta,
                              sql.Column("id", sql.Integer, primary_key=True),
                              sql.Column("queryid", sql.String, unique=True, nullable=False),
                              #sql.Column("ip", postgresql.INET, nullable=False),
                              #sql.Column("fqdn", sql.String, nullable=True),
                              sql.Column("host", sql.String, nullable=False),
                              sql.Column("query", sql.String, nullable=False),
                              sql.Column('created', sql.DateTime, default=sql.func.now()),
                              sql.Column("count", sql.Integer, nullable=False),
                              sql.Column("scanid", sql.Integer, nullable=False),
                              extend_existing=True
                              )
    logger.debug("table_queries:%s", table_queries)
    table_queries.create(checkfirst=True)

    logger.debug("creating search engine result table")
    table = sql.Table(table_selink.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True),
                      sql.Column("qid", sql.String,
                                 sql.ForeignKey(table_queries.c.queryid),
                                 nullable=False
                                 ),
                      sql.Column("link", sql.String, nullable=False),
                      sql.Column("success", sql.Boolean, nullable=False),
                      extend_existing=True
                      )
    table.create(checkfirst=True)

def __create_table_mail(meta):
    logger.debug("creating result table %s", table_mail.name)
    table_mailaccount = sql.Table(table_mail.name, meta,
                                  sql.Column("id", sql.Integer, primary_key=True),
                                  sql.Column("protocol", sql.String, nullable=False),
                                  sql.Column("cryptolayer", sql.String, nullable=False),
                                  sql.Column("username", sql.String, nullable=False),
                                  sql.Column("password", sql.String, nullable=False),
                                  sql.Column("ip", postgresql.INET, nullable=False),
                                  sql.Column("fqdn", sql.String, nullable=True),
                                  #sql.Column("host", sql.String, nullable=False),
                                  sql.Column("port", sql.Integer, nullable=False),
                                  sql.Column("created", sql.DateTime, default=sql.func.now()),
                                  sql.Column("scanid", sql.Integer, nullable=False),
                                  extend_existing=True
                                  )

    logger.debug("table_account: %s", table_mailaccount)
    table_mailaccount.create(checkfirst=True)

def __create_table_ssh_banner(meta):
    logger.debug("creating result table %s", table_ssh_banner.name)
    tbl = sql.Table(table_ssh_banner.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("banner", sql.String, nullable=False),
                    #sql.Column("host", sql.String, nullable=False),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_ssh_user_enum(meta):
    logger.debug("creating result table %s", table_ssh_user_enum.name)
    tbl = sql.Table(table_ssh_user_enum.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("username", sql.String, nullable=False),
                    #sql.Column("host", sql.String, nullable=False),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_bruteforce(meta):
    logger.debug("creating bruteforce result table %s", table_bruteforce.name)
    tbl = sql.Table(table_bruteforce.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("username", sql.String, nullable=False),
                    sql.Column("password", sql.String, nullable=False),
                    sql.Column("service", sql.String, nullable=False),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("ip", postgresql.INET, nullable=True, index=True),
                    #sql.Column("ip", sql.String, nullable=True),
                    sql.Column("fqdn", sql.String, nullable=True),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_fingerprint(meta):
    logger.debug("creating result table %s", table_fingerprint.name)
    tbl = sql.Table(table_fingerprint.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    #sql.Column("host", sql.String, nullable=False),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("banner", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_dirbruteforce(meta):
    logger.debug("creating result table %s", table_dirbruteforce.name)
    tbl = sql.Table(table_dirbruteforce.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    sql.Column("netloc", sql.String, nullable=False),
                    sql.Column("path", sql.String, nullable=False),
                    sql.Column("filename", sql.String, nullable=False),
                    sql.Column("info", sql.String, nullable=False),
                    sql.Column("status", sql.Integer, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_dirscan(meta):
    logger.debug("creating result table %s", table_dirscan.name)
    tbl = sql.Table(table_dirscan.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    #sql.Column("host", sql.String, nullable=False),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("osvdb", sql.Integer, nullable=False),
                    sql.Column("uri", sql.String, nullable=False),
                    sql.Column("comment", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)

def __create_table_smtp_user_enum(meta):
    logger.debug("creating result table %s", table_smtp_user_enum.name)
    tbl = sql.Table(table_smtp_user_enum.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    #sql.Column("host", sql.String, nullable=False),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("username", sql.String, nullable=False),
                    sql.Column("command", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_rlogin_bruteforce(meta):
    logger.debug("creating result table %s", table_rlogin_bruteforce.name)
    tbl = sql.Table(table_rlogin_bruteforce.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("host", sql.String, nullable=False),
                    sql.Column("lport", sql.Integer, nullable=False),
                    sql.Column("rport", sql.Integer, nullable=False),
                    sql.Column("localusername", sql.String, nullable=False),
                    sql.Column("remoteusername", sql.String, nullable=False),
                    sql.Column("password", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_rsh_bruteforce(meta):
    logger.debug("creating result table %s", table_rsh_bruteforce.name)
    tbl = sql.Table(table_rsh_bruteforce.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("host", sql.String, nullable=False),
                    sql.Column("lport", sql.Integer, nullable=False),
                    sql.Column("rport", sql.Integer, nullable=False),
                    sql.Column("localusername", sql.String, nullable=False),
                    sql.Column("remoteusername", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_http_bruteforce(meta):
    logger.debug("creating result table %s", table_http_bruteforce.name)
    tbl = sql.Table(table_http_bruteforce.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("username", sql.String, nullable=False),
                    sql.Column("password", sql.String, nullable=False),
                    #sql.Column("host", sql.String, nullable=False),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("path", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )
    tbl.create(checkfirst=True)


def __create_table_rpcinfo(meta):
    logger.debug("creating result table %s", table_rpcinfo.name)
    tbl = sql.Table(table_rpcinfo.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    sql.Column("port", sql.Integer, nullable=False),
                    #sql.Column("host", sql.String, nullable=False),
                    sql.Column("program", sql.String, nullable=False),
                    sql.Column("program_id", sql.Integer, nullable=False),
                    sql.Column("version", sql.Integer, nullable=False),
                    sql.Column("protocol", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_showmount(meta):
    logger.debug("creating result table %s", table_showmount.name)
    tbl = sql.Table(table_showmount.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    #sql.Column("ip", sql.String, nullable=False),
                    sql.Column("export", sql.String, nullable=False),
                    sql.Column("client", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )
    tbl.create(checkfirst=True)


def __create_table_sslinfo(meta):
    logger.debug("creating result table %s", table_sslinfo.name)
    tbl = sql.Table(table_sslinfo.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    #sql.Column("ip", sql.String, nullable=False),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("cs", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_traceroute(meta):
    logger.debug("creating result table %s", table_traceroute.name)
    tbl = sql.Table(table_traceroute.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("start", sql.String, nullable=False),
                    sql.Column("stop", sql.String, nullable=False),
                    sql.Column("hops", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_heartbleed_nv(meta):
    logger.debug("creating result table %s", table_heartbleed_nv.name)
    tbl = sql.Table(table_heartbleed_nv.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    #sql.Column("target", sql.String, nullable=False),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("tlsv", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("risk", sql.Integer, default=0, nullable=False),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_heartbleed(meta):
    logger.debug("creating result table %s", table_heartbleed.name)
    tbl = sql.Table(table_heartbleed.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    #sql.Column("target", sql.String, nullable=False),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("tlsv", sql.String, nullable=False),
                    sql.Column("sample", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("risk", sql.Integer, default=0, nullable=False),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)
    __create_table_heartbleed_nv(meta)


def __create_table_dnsrecord(meta):
    logger.debug("creating result table %s", table_dnsrecord.name)
    tbl = sql.Table(table_dnsrecord.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    sql.Column("domainame", sql.String, nullable=False),
                    sql.Column("ttl", sql.Integer, nullable=False),
                    sql.Column("rclass", sql.String, nullable=False),
                    sql.Column("rtype", sql.String, nullable=False),
                    sql.Column("rdata", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __create_table_dnsversion(meta):
    logger.debug("creating result table %s", table_dnsversion.name)
    tbl = sql.Table(table_dnsversion.name, meta,
                    sql.Column("id", sql.Integer, primary_key=True),
                    #sql.Column("nameserver", sql.String, nullable=False),
                    sql.Column("ip", postgresql.INET, nullable=False),
                    sql.Column("port", sql.Integer, nullable=False),
                    sql.Column("fqdn", sql.String, nullable=True),
                    sql.Column("bindversion", sql.String, nullable=False),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    sql.Column("scanid", sql.Integer, nullable=False),
                    extend_existing=True
                    )

    tbl.create(checkfirst=True)


def __insert_whois(dbconn, dbmeta, wsr, scanid):
    """ store whois result in database.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            wsr     whois result object

    """
    values = dict(
        ip=wsr.ip,
        adminhandle=wsr.adminhandle,
        techhandle=wsr.techhandle,
        country=wsr.country,
        inetnum=wsr.inetnum,
        netname=wsr.netname,
        scanid=scanid
    )

    with dbconn.begin():
        ins = dbmeta.tables[table_whois.name].insert().values(values)
        dbconn.execute(ins)

def __insert_geoip(dbconn, dbmeta, result, scanid):
    """ store geoip result in database.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            result  geoip result object

    """
    values = dict(
        ip=result.ip,
        iprange=result.iprange,
        geoname_id=result.geoname_id,
        continent_code=result.continent_code,
        continent_name=result.continent_name,
        country_iso_code=result.country_iso_code,
        country_name=result.country_name,
        subdivision_iso_code=result.subdivision_iso_code,
        subdivision_name=result.subdivision_name,
        city_name=result.city_name,
        metro_code=result.metro_code,
        timezone=result.timezone,
        extra=result.extra,
        scanid=scanid
    )

    with dbconn.begin():
        ins = dbmeta.tables[table_geoip.name].insert().values(values)
        dbconn.execute(ins)


def __insert_mail(dbconn, dbmeta, selr, scanid):

    values_mailaccount = dict(
        protocol=selr.protocol,
        cryptolayer=selr.cryptolayer,
        username=selr.user,
        password=selr.password,
        ip=selr.ip,
        fqdn=selr.fqdn,
        port=selr.port,
        scanid=scanid
    )

    with dbconn.begin():
        ins = dbmeta.tables[table_mail.name].insert().values(
            values_mailaccount
        )
        dbconn.execute(ins)

def __query_in_db(dbconn, dbmeta, queryid):
    """ return True if queryid is already in table_se_link_queries """
    tbl = dbmeta.tables[__table_se_link_queries]
    sel_query = tbl.select().where(tbl.c.queryid == queryid)
    found = False

    logger.debug("querying id %s in se_link_queries table", queryid)

    with dbconn.begin():
        res = dbconn.execute(sel_query)
        if res and res.fetchone():
            found = True

    logger.debug("found=%s", found)
    return found

def __insert_selink(dbconn, dbmeta, selr, scanid):
    """
    store search engine link result

    input:
        dbconn  database connection
        dbmeta  sql metadata object
        selr    search engine link crawl result object
        scanid

    """
    values_query = dict(
        queryid=selr.queryid,
        host=selr.host,
        query=selr.query,
        count=selr.count,
        scanid=scanid
    )

    # only add query if not already in database
    if not __query_in_db(dbconn, dbmeta, selr.queryid):
        logger.debug("queryid (%s) not in db, so inserting", selr.queryid)
        query_table = dbmeta.tables[__table_se_link_queries]
        ins_query = query_table.insert().values(values_query)

        with dbconn.begin():
            dbconn.execute(ins_query)

    # add the link that is returned by the search engine
    values_link = dict(
        qid=selr.queryid,
        link=selr.link,
        success=selr.success,
    )

    logger.debug("inserting link (%s) for queryid %s", selr.link, selr.queryid)
    link_table = dbmeta.tables[table_selink.name]
    ins_link = link_table.insert().values(values_link)

    with dbconn.begin():
        dbconn.execute(ins_link)

    logger.debug("link %s successfully stored", selr.link)

def __insert_ripescan(dbconn, dbmeta, dsr, scanid):
    """ store  ripe scanning result.

        input:
            dbconn  connection for database
            dbmeta  sql metadata object
            dsr     ripescan result object
            scan id

    """

    values = dict(
        ip=dsr.ip,
        search=dsr.search,
        scanid=scanid
    )

    with dbconn.begin():
        ins = dbmeta.tables[table_ripescan.name].insert().values(values)
        dbconn.execute(ins)


def __insert_dnsscan(dbconn, dbmeta, dsr, scanid):
    """ store  dns scanning result.

        input:
            dbconn  connection for database
            dbmeta  sql metadata object
            dsr     dnsscan result object
            scan id

    """
    if not (dsr.ip and dsr.fqdn):
        return

    try:
        if dsr.fqdn:
            domain = ctools_domain.get_domain(dsr.fqdn)

    except (BadUrl, DomainNotFound):
        domain = ""

    values = dict(
        ip=dsr.ip,
        fqdn=dsr.fqdn,
        domain=domain,
        scanid=scanid
    )

    with dbconn.begin():
        ins = dbmeta.tables[table_dnsscan.name].insert().values(values)
        dbconn.execute(ins)

def __insert_portscan(dbconn, dbmeta, psr, scanid):
    """ store port scanning result.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            psr     portsscan result object
            scanid  scan id

    """
    tbl = dbmeta.tables[table_portscan.name]

    with dbconn.begin():
        if psr.ip:
            ins = tbl.insert().values(
                port=psr.port,
                ip=psr.ip,
                protocol=psr.protocol,
                state=psr.state,
                service=psr.service,
                fqdn=psr.fqdn,
                version=psr.version,
                scanid=scanid
            )
        else:
            ins = tbl.insert().values(
                port=psr.port,
                protocol=psr.protocol,
                state=psr.state,
                service=psr.service,
                fqdn=psr.fqdn,
                version=psr.version,
                scanid=scanid
            )
        dbconn.execute(ins)

def __insert_ssh_banner(dbconn, dbmeta, bsr, scanid):
    """ store ssh banner result.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            bsr     ssh banner result object
            scanid  scan id

    """
    logger.debug('inserting sshB result: %s@%s%d',
                 bsr.banner, bsr.host, int(bsr.port))
    tbl = dbmeta.tables[table_ssh_banner.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            banner=bsr.banner,
            port=bsr.port,
            host=bsr.host,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_ssh_user_enum(dbconn, dbmeta, bsr, scanid):
    """ store ssh user_enum result.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            bsr     ssh user_enum result object
            scanid  scan id

    """
    logger.debug('inserting sshB result: %s@%s:%d',
                 bsr.user, bsr.ip, int(bsr.port))
    tbl = dbmeta.tables[table_ssh_user_enum.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            username=bsr.user,
            port=bsr.port,
            ip=bsr.ip,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_bruteforce(dbconn, dbmeta, br, scanid):
    """ store bruteforce result.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            br     bruteforce result object
            scanid  scan id

    """
    if not br.ip and not br.fqdn:
        raise Exception('No Target specified')

    logger.debug('inserting Bruteforce result: %s/%s@%s%d',
                 br.password, br.username, br.ip, int(br.port))
    tbl = dbmeta.tables[table_bruteforce.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            username=br.username,
            password=br.password,
            service=br.service,
            port=br.port,
            ip=br.ip,
            fqdn=br.fqdn,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_fingerprint(dbconn, dbmeta, result, scanid):
    logger.debug('inserting FingerprintResult result: %s:%d %s',
                 result.host, int(result.port), result.banner)
    tbl = dbmeta.tables[table_fingerprint.name]

    logger.debug('Adding fprint sql')
    with dbconn.begin():
        logger.debug('Adding fprint sql 2')
        ins = tbl.insert().values(
            port=result.port,
            ip=result.ip,
            fqdn=result.fqdn,
            banner=result.banner,
            scanid=scanid
        )
        dbconn.execute(ins)

def __insert_dirbruteforce(dbconn, dbmeta, result, scanid):
    logger.debug('inserting DirscanResult result')
    tbl = dbmeta.tables[table_dirbruteforce.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            ip=result.ip,
            fqdn=result.fqdn,
            netloc=result.netloc,
            path=result.path,
            filename=result.filename,
            info=result.info,
            status=int(result.status),
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_dirscan(dbconn, dbmeta, result, scanid):
    logger.debug('inserting DirscanResult result')
    tbl = dbmeta.tables[table_dirscan.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            ip=result.ip,
            fqdn=result.fqdn,
            port=int(result.port),
            osvdb=int(result.osvdb),
            uri=result.uri,
            comment=result.comment,
            scanid=scanid
        )
        dbconn.execute(ins)

def __insert_smtp_user_enum(dbconn, dbmeta, result, scanid):
    logger.debug('inserting SmtpUserEnumResult result')
    tbl = dbmeta.tables[table_smtp_user_enum.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            port=result.port,
            ip=result.ip,
            fqdn=result.fqdn,
            username=result.username,
            command=result.command,
            scanid=scanid
        )
        dbconn.execute(ins)

def __insert_rsh_bruteforce(dbconn, dbmeta, bsr, scanid):
    logger.debug('inserting RshBruteforceResult result')
    tbl = dbmeta.tables[table_rsh_bruteforce.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            host=bsr.host,
            lport=bsr.lport,
            rport=bsr.rport,
            localusername=bsr.localusername,
            remoteusername=bsr.remoteusername,
            scanid=scanid
        )
        dbconn.execute(ins)

def __insert_rlogin_bruteforce(dbconn, dbmeta, bsr, scanid):
    logger.debug('inserting RloginBruteforceResult result')
    tbl = dbmeta.tables[table_rlogin_bruteforce.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            host=bsr.host,
            lport=bsr.lport,
            rport=bsr.rport,
            localusername=bsr.localusername,
            remoteusername=bsr.remoteusername,
            password=bsr.password,
            scanid=scanid
        )
        dbconn.execute(ins)

def __insert_http_bruteforce(dbconn, dbmeta, result, scanid):
    logger.debug('inserting HttpBruteforce result')
    tbl = dbmeta.tables[table_http_bruteforce.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            username=result.user,
            password=result.password,
            port=result.port,
            ip=result.ip,
            path=result.path,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_rpcinfo(dbconn, dbmeta, result, scanid):
    logger.debug('inserting Tpcinfo result')
    tbl = dbmeta.tables[table_rpcinfo.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            ip=result.ip,
            fqdn=result.fqdn,
            port=result.port,
            program=result.program,
            program_id=result.program_id,
            version=result.version,
            protocol=result.protocol,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_traceroute(dbconn, dbmeta, bsr, scanid):
    logger.debug('inserting TracerouteSQL result: %s %s %s',
                 bsr.start, bsr.end, bsr.hops)
    tbl = dbmeta.tables[table_traceroute.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            host=bsr.start,
            export=bsr.stop,
            client=bsr.hops,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_sslinfo(dbconn, dbmeta, result, scanid):
    logger.debug('inserting SslInfoSQL result')
    tbl = dbmeta.tables[table_sslinfo.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            ip=result.ip,
            fqdn=result.fqdn,
            port=result.port,
            cs=result.cs,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_showmount(dbconn, dbmeta, result, scanid):
    logger.debug('inserting ShowmountSQL result')
    tbl = dbmeta.tables[table_showmount.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            ip=result.ip,
            fqdn=result.fqdn,
            export=result.export,
            client=result.client,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_heartbleed_nv(dbconn, dbmeta, result, scanid):
    tbl = dbmeta.tables[table_heartbleed_nv.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            ip=result.ip,
            fqdn=result.fqdn,
            port=result.port,
            tlsv=result.tlsv,
            risk=result.risk,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_heartbleed(dbconn, dbmeta, result, scanid):
    tbl = dbmeta.tables[table_heartbleed.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            ip=result.ip,
            fqdn=result.fqdn,
            port=result.port,
            tlsv=result.tlsv,
            sample=result.sample,
            risk=result.risk,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_dnsrecord(dbconn, dbmeta, bsr, scanid):
    logger.debug('inserting DnsRecordSQL result')
    tbl = dbmeta.tables[table_dnsrecord.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            domainame=bsr.domainame,
            ttl=bsr.ttl,
            rclass=bsr.rclass,
            rtype=bsr.rtype,
            rdata=bsr.rdata,
            scanid=scanid
        )
        dbconn.execute(ins)


def __insert_dnsversion(dbconn, dbmeta, result, scanid):
    logger.debug('inserting DnsVersion result')
    tbl = dbmeta.tables[table_dnsversion.name]

    with dbconn.begin():
        ins = tbl.insert().values(
            #nameserver=bsr.nameserver,
            ip=result.ip,
            port=result.port,
            fqdn=result.fqdn,
            bindversion=result.bindversion,
            scanid=scanid
        )
        dbconn.execute(ins)

# database tables
table_portscan = __ProjectTable("result_portscan",
                                Tmpl.PORTSCAN,
                                PortscanResult,
                                __create_table_portscan,
                                __insert_portscan,
                                grouping="fqdn")

table_dnsscan = __ProjectTable("result_dnsscan",
                               Tmpl.DNSSCAN,
                               DnsscanResult,
                               __create_table_dnsscan,
                               __insert_dnsscan,
                               id_desc=2,
                               id_sol=3,
                               grouping="domain")

table_ripescan = __ProjectTable("result_ripescan",
                                Tmpl.RIPESCAN,
                                RipescanResult,
                                __create_table_ripescan,
                                __insert_ripescan)

table_geoip = __ProjectTable("result_geoip",
                             Tmpl.GEOIP,
                             GeoipResult,
                             __create_table_geoip,
                             __insert_geoip)

table_whois = __ProjectTable("result_whois",
                             Tmpl.WHOIS,
                             WhoisResult,
                             __create_table_whois,
                             __insert_whois)

table_selink = __ProjectTable("result_se_link",
                              Tmpl.SE_LINK_CRAWLER,
                              SELinkResult,
                              __create_table_selink,
                              __insert_selink)

__table_se_link_queries = "result_se_link_queries"

table_mail = __ProjectTable("result_mail_account",
                            Tmpl.MAIL_ACCOUNT,
                            MailAccountResult,
                            __create_table_mail,
                            __insert_mail)

table_bruteforce = __ProjectTable("result_bruteforce",
                                  Tmpl.BRUTEFORCE,
                                  BruteforceResult,
                                  __create_table_bruteforce,
                                  __insert_bruteforce)

table_ssh_user_enum = __ProjectTable("result_ssh_user_enum",
                                     Tmpl.SSH_USER_ENUM,
                                     SshUserEnumResult,
                                     __create_table_ssh_user_enum,
                                     __insert_ssh_user_enum)

table_ssh_banner = __ProjectTable("result_ssh_banner",
                                  Tmpl.SSHBANNER,
                                  SshBannerResult,
                                  __create_table_ssh_banner,
                                  __insert_ssh_banner)

table_rpcinfo = __ProjectTable("result_rpcinfo",
                               Tmpl.RPCINFO,
                               RpcinfoResult,
                               __create_table_rpcinfo,
                               __insert_rpcinfo)

table_showmount = __ProjectTable("result_showmount",
                                 Tmpl.SHOWMOUNT,
                                 ShowmountResult,
                                 __create_table_showmount,
                                 __insert_showmount)

table_http_bruteforce = __ProjectTable("result_http_bruteforce",
                                       Tmpl.HTTP_BRUTEFORCE,
                                       HttpBruteforceResult,
                                       __create_table_http_bruteforce,
                                       __insert_http_bruteforce)

table_rsh_bruteforce = __ProjectTable("result_rsh_bruteforce",
                                      Tmpl.RSH_BRUTEFORCE,
                                      RshBruteforceResult,
                                      __create_table_rsh_bruteforce,
                                      __insert_rsh_bruteforce)

table_rlogin_bruteforce = __ProjectTable("result_rlogin_bruteforce",
                                         Tmpl.RLOGIN_BRUTEFORCE,
                                         RloginBruteforceResult,
                                         __create_table_rlogin_bruteforce,
                                         __insert_rlogin_bruteforce)

table_fingerprint = __ProjectTable("result_fingerprint",
                                   Tmpl.FINGERPRINT,
                                   FingerprintResult,
                                   __create_table_fingerprint,
                                   __insert_fingerprint)

table_dirbruteforce = __ProjectTable("result_dirbruteforce",
                                     Tmpl.DIR_BRUTEFORCE,
                                     DirBruteforceResult,
                                     __create_table_dirbruteforce,
                                     __insert_dirbruteforce)

table_dirscan = __ProjectTable("result_dirscan",
                               Tmpl.DIRSCAN,
                               DirscanResult,
                               __create_table_dirscan,
                               __insert_dirscan)

table_smtp_user_enum = __ProjectTable("result_smtp_user_enum",
                                      Tmpl.SMTPUSER_BRUTEFORCE,
                                      SmtpUserEnumResult,
                                      __create_table_smtp_user_enum,
                                      __insert_smtp_user_enum)

table_sslinfo = __ProjectTable("result_sslinfo",
                               Tmpl.SSL_INFO,
                               SslInfoResult,
                               __create_table_sslinfo,
                               __insert_sslinfo)

table_heartbleed = __ProjectTable("result_01_heartbleed_vulnerable",
                                  Tmpl.HEARTBLEED,
                                  HeartbleedResult,
                                  __create_table_heartbleed,
                                  __insert_heartbleed)

table_heartbleed_nv = __ProjectTable("result_02_heartbleed_not_vulnerable",
                                     Tmpl.HEARTBLEED,
                                     HeartbleedResult_NV,
                                     __create_table_heartbleed,
                                     __insert_heartbleed_nv)

table_dnsrecord = __ProjectTable("result_dnsrecord",
                                 Tmpl.ZONETRANSFER,
                                 DnsRecordResult,
                                 __create_table_dnsrecord,
                                 __insert_dnsrecord)

table_dnsversion = __ProjectTable("result_dnsversion",
                                  Tmpl.DNSVERSION,
                                  DnsVersionResult,
                                  __create_table_dnsversion,
                                  __insert_dnsversion)

table_traceroute = __ProjectTable("result_traceroute",
                                  Tmpl.TRACEROUTE,
                                  TracerouteResult,
                                  __create_table_traceroute,
                                  __insert_traceroute)

###################
## NEW DB LAYOUT ##
###################

def __create_table_target_dns_rel(meta):
    """ create target dns association table """

    logger.debug("creating table %s", table_target_dns_rel.name)

    table = sql.Table(table_target_dns_rel.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column("target_id", sql.Integer, nullable=False),
                      sql.Column("targetdns_id", sql.Integer, nullable=False),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      sql.ForeignKeyConstraint(['target_id'], ['result_target.id']),
                      sql.ForeignKeyConstraint(['targetdns_id'], ['result_targetdns.id']),
                      sql.UniqueConstraint('target_id', 'targetdns_id'),
                      extend_existing=True
                      )
    table.create(checkfirst=True)


def __insert_target_dns_rel(dbconn, dbmeta, target_id, targetdns_id, scanid):
    """ store target result in database.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            target_id   db id of target entry
            targetdns_id   db id of targetdns entry

    """
    values = dict(
        target_id=target_id,
        targetdns_id=targetdns_id,
        scanid=scanid
    )

    logger.info('Inserting into %s: %s', table_target_dns_rel.name, values)

    with dbconn.begin():
        try:
            ins = dbmeta.tables[table_target_dns_rel.name].insert().values(values)
            dbconn.execute(ins)
        except sql.exc.IntegrityError:
            # unique constraint violated
            pass


table_target_dns_rel = __ProjectTable('result_target_dns_rel',
                                      Tmpl.TARGET_DNS_REL,
                                      TargetDnsRelResult,
                                      __create_table_target_dns_rel,
                                      None)


def __create_table_target(meta):
    """ Create target result table. """

    logger.debug("creating table %s", table_target.name)

    table = sql.Table(table_target.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column("ip", postgresql.INET, nullable=True, index=True),
                      sql.Column("info", sql.String),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      sql.UniqueConstraint('ip'),
                      extend_existing=True
                      )
    table.create(checkfirst=True)


def __insert_target(dbconn, dbmeta, result, scanid):
    """ store target result in database.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            result  target result object

    """
    values = dict(
        ip=result.ip,
        info=result.info,
        scanid=scanid
    )

    logger.info('Inserting into %s: %s', table_target.name, values)

    res = None

    with dbconn.begin():
        try:
            ins = dbmeta.tables[table_target.name].insert().values(values)
            res = dbconn.execute(ins)
        except sql.exc.IntegrityError:
            # unique constraint violated
            pass

    target_id = None

    if res:
        try:
            target_id = res.last_inserted_ids()[0]
        except Exception as e:
            logger.warning('Failed to get last id for target: %s', e)

    if target_id is None:
        target_id = _get_target_id(dbconn, dbmeta, result.ip)

    logger.info('Inserting into %s: %s --> ID: %s', table_target.name, values, target_id)

    # if a fqdn is associated to this ip, add relation
    if result.fqdn:
        targetdns_id = _get_targetdns_id(
            dbconn,
            dbmeta,
            result.fqdn,
            result,
            scanid
        )
        if targetdns_id:
            __insert_target_dns_rel(dbconn, dbmeta, target_id, targetdns_id, scanid)

    return target_id


table_target = __ProjectTable('result_target',
                              Tmpl.TARGET,
                              TargetResult,
                              __create_table_target,
                              __insert_target)


def _get_target_id(dbconn, dbmeta, ip, targetdns_result=None, scanid=None):

    logger.info('Getting target id for ip: %s', ip)

    target_id = None

    with dbconn.begin():
        tbl = dbmeta.tables[table_target.name]
        sel = sql.select([tbl.c.id]).where(
            sql.and_(tbl.c.ip==ip)
        )
        res = dbconn.execute(sel).fetchone()
        if res:
            target_id = res[0]

    logger.info('Getting target id for ip: %s --> ID: %s', ip, target_id)

    if not res and targetdns_result and scanid is not None:
        target_id = __insert_target(dbconn,
                                    dbmeta,
                                    TargetResult(ip=ip, fqdn=targetdns_result.fqdn),
                                    scanid=scanid)

    return target_id


def _get_targetdns_id(dbconn, dbmeta, fqdn, target_result=None, scanid=None):

    logger.info('Getting targetdns id for fqdn: %s', fqdn)

    targetdns_id = None

    with dbconn.begin():
        tbl = dbmeta.tables[table_targetdns.name]
        sel = sql.select([tbl.c.id]).where(
            sql.and_(tbl.c.fqdn==fqdn)
        )
        res = dbconn.execute(sel).fetchone()
        if res:
            targetdns_id = res[0]

    logger.info('Getting targetdns id for fqdn: %s --> ID: %s', fqdn, targetdns_id)

    if not res and target_result and scanid is not None:
        targetdns_id = __insert_targetdns(dbconn,
                                          dbmeta,
                                          TargetDnsResult(fqdn=fqdn, ip=target_result.ip),
                                          scanid=scanid)
    return targetdns_id


def __create_table_targetdns(meta):
    """ Create target dns result table. """

    logger.debug("creating table %s", table_targetdns.name)

    #TODO constraint to have at least Ip or fqdn
    table = sql.Table(table_targetdns.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column("domain", sql.String, nullable=True),
                      sql.Column("fqdn", sql.String),
                      sql.Column("root_zone", sql.String),
                      sql.Column("info", sql.String),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      sql.UniqueConstraint('fqdn'),
                      extend_existing=True
                      )
    table.create(checkfirst=True)


def __insert_targetdns(dbconn, dbmeta, result, scanid):
    """ store target result in database.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            result  target dns result object

    """

    values = dict(
        domain=result.domain,
        fqdn=result.fqdn,
        root_zone=result.root_zone,
        scanid=scanid,
        info=result.info,
    )

    logger.info('Inserting into %s: %s', table_targetdns.name, values)

    res = None

    with dbconn.begin():
        try:
            ins = dbmeta.tables[table_targetdns.name].insert().values(values)
            res = dbconn.execute(ins)
        except sql.exc.IntegrityError:
            # unique constraint violated
            pass

    targetdns_id = None

    if res:
        try:
            targetdns_id = res.last_inserted_ids()[0]
        except Exception as e:
            logger.warning('Failed to get last id for targetdns: %s', e)

    if targetdns_id is None:
        targetdns_id = _get_targetdns_id(dbconn,
                                         dbmeta,
                                         result.fqdn)

    logger.info('Inserting into %s: %s --> ID: %s', table_targetdns.name, values, targetdns_id)

    # if a ip is associated to this domain, add relation
    if result.ip:
        target_id = _get_target_id(
            dbconn,
            dbmeta,
            result.ip,
            result
        )
        if target_id:
            __insert_target_dns_rel(dbconn, dbmeta, target_id, targetdns_id, scanid)

    return targetdns_id


table_targetdns = __ProjectTable('result_targetdns',
                                 Tmpl.TARGETDNS,
                                 TargetDnsResult,
                                 __create_table_targetdns,
                                 __insert_targetdns)


def __create_table_service(meta):
    """ Create service result table. """

    logger.debug("creating table %s", table_service.name)

    #TODO constraint to have at least Ip or fqdn
    table = sql.Table(table_service.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column('target_id', sql.Integer, nullable=False),
                      sql.Column("port", sql.Integer, nullable=True),
                      sql.Column("state", sql.String, nullable=True),
                      sql.Column("protocol", sql.String),
                      sql.Column("service", sql.String),
                      sql.Column("version", sql.String),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      sql.ForeignKeyConstraint(['target_id'], ['result_target.id']),
                      sql.UniqueConstraint('target_id', 'port', 'protocol'),
                      extend_existing=True
                      )
    table.create(checkfirst=True)

def _get_service_id(dbconn, dbmeta, target_id, port, protocol, target_result=None, scanid=None):

    logger.info('Getting service id for target_id: %s, port: %s, protocol: %s',
                target_id, port, protocol)

    service_id = None

    #print 'getting service id: %s, %s, %s' % (str(port), str(protocol), str(target_id))
    with dbconn.begin():
        tbl = dbmeta.tables[table_service.name]
        sel = sql.select([tbl.c.id]).where(
            sql.and_(target_id==int(target_id), tbl.c.port==int(port), tbl.c.protocol==tbl.c.protocol)
        )
        res = dbconn.execute(sel).fetchone()
        if res:
            service_id = res[0]

    logger.info('Getting service id for target_id: %s, port: %s, protocol: %s --> ID: %s',
                target_id, port, protocol, service_id)

    return service_id


def __insert_service(dbconn, dbmeta, result, scanid):
    """ store service result in database.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            result  service result object

    """

    target_id = __insert_target(dbconn, dbmeta, result, scanid)

    values = dict(
        target_id=target_id,
        port=result.port,
        state=result.state,
        protocol=result.protocol,
        service=result.service,
        version=result.version,
        scanid=scanid
    )

    logger.info('Inserting into %s: %s', table_service.name, values)

    res = None

    #print 'inserting into service: ' + repr(values)
    with dbconn.begin():
        try:
            ins = dbmeta.tables[table_service.name].insert().values(values)
            res = dbconn.execute(ins)
        except sql.exc.IntegrityError:
            # unique constraint violated
            pass

    service_id = None

    if res:
        try:
            service_id = res.last_inserted_ids()[0]
        except Exception as e:
            logger.warning('Failed to get last id for service: %s', e)

    if service_id is None:
        service_id = _get_service_id(dbconn, dbmeta, target_id, result.port, result.protocol)

    logger.info('Inserting into %s: %s --> ID: %s', table_service.name, values, service_id)
    #print 'ID: ' + repr(service_id)
    return service_id


table_service = __ProjectTable('result_service',
                               Tmpl.SERVICE,
                               ServiceResult,
                               __create_table_service,
                               __insert_service)


def __create_table_bruteforce2(meta):
    """ Create bruteforce result table. """

    logger.debug("creating table %s", table_bruteforce2.name)

    #TODO constraint to have at least Ip or fqdn
    table = sql.Table(table_bruteforce2.name, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column('service_id', sql.Integer, nullable=False),
                      sql.Column("username", sql.String, nullable=True),
                      sql.Column("password", sql.String),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      sql.ForeignKeyConstraint(['service_id'], ['result_service.id']),
                      sql.UniqueConstraint('service_id', 'username', 'password'),
                      extend_existing=True
                      )
    table.create(checkfirst=True)


def _get_bruteforce_id(dbconn, dbmeta, username, password, service_id, scanid=None):

    logger.info('Getting bruteforce id for username: %s, password: %s, service_id: %s',
                username, password, service_id)

    bruteforce_id = None

    with dbconn.begin():
        tbl = dbmeta.tables[table_bruteforce2.name]
        sel = sql.select([tbl.c.id]).where(
            sql.and_(service_id==service_id, tbl.c.password==password, tbl.c.username==tbl.c.username)
        )
        res = dbconn.execute(sel).fetchone()
        if res:
            bruteforce_id = res[0]

    logger.info('Getting bruteforce id for username: %s, password: %s, service_id: %s --> ID: %s',
                username, password, service_id, bruteforce_id)

    return bruteforce_id


def __insert_bruteforce2(dbconn, dbmeta, result, scanid):
    """ store bruteforce result in database.

        input:
            dbconn  database connection
            dbmeta  sql metadata object
            result  bruteforce result object

    """

    service_id = __insert_service(dbconn, dbmeta, result, scanid)

    values = dict(
        service_id=service_id,
        password=result.password,
        username=result.username,
        scanid=scanid
    )

    logger.info('Inserting into %s: %s', table_bruteforce2.name, values)

    #print 'inserting into bruteforce: ' + repr(values)
    res = None

    with dbconn.begin():
        try:
            ins = dbmeta.tables[table_bruteforce2.name].insert().values(values)
            res = dbconn.execute(ins)
        except sql.exc.IntegrityError as e:
            #print e
            # unique constraint violated
            pass

    bruteforce_id = None

    if res:
        try:
            bruteforce_id = res.last_inserted_ids()[0]
        except Exception as e:
            logger.warning('Failed to get last id for bruteforce: %s', e)

    if bruteforce_id is None:
        bruteforce_id = _get_bruteforce_id(dbconn, dbmeta, service_id, result.username, result.password)

    #print 'ID: ' + repr(bruteforce_id)

    logger.info('Inserting into %s: %s --> ID: %s', table_bruteforce2.name, values, bruteforce_id)

    return bruteforce_id


table_bruteforce2 = __ProjectTable('result_bruteforce2',
                                   Tmpl.BRUTEFORCE2,
                                   BruteforceResult2,
                                   __create_table_bruteforce2,
                                   __insert_bruteforce2)


def create_extra(meta, table_desc, plgname, plgclass):
    """ Create service result table. """

    tblname = 'result_' + plgname

    fgc = sql.ForeignKeyConstraint(['ref_id'], ['result_target.id'])
    if plgclass == ['scanner']:
        fgc = sql.ForeignKeyConstraint(['ref_id'], ['result_service.id'])
    elif plgclass == ['bruteforce']:
        fgc = sql.ForeignKeyConstraint(['ref_id'], ['result_service.id'])
    elif plgclass == ['dns']:
        fgc = sql.ForeignKeyConstraint(['ref_id'], ['result_dns.id'])

    table = sql.Table(tblname, meta,
                      sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
                      sql.Column('created', sql.DateTime, default=sql.func.now()),
                      sql.Column('ref_id', sql.Integer, nullable=False),
                      sql.Column("scanid", sql.Integer, nullable=False),
                      fgc,
                      )
    for c in table_desc.columns:
        table.append_column(c)

    table.create(checkfirst=True)

    def insert_me(dbconn, dbmeta, result, scanid):
        # add super entry
        ref_id = None
        # get sql statement and check whether entry type is allowed
        for t in all_tables:
            if type(result) == t.result_type:
                continue
            if isinstance(result, t.result_type):
                ref_id = t.insert(dbconn, dbmeta, result, scanid)
                break

        values = dict(
            scanid=scanid,
            ref_id=ref_id
        )

        for c in table_desc.columns:
            values[c.name] = getattr(result, c.name)

        with dbconn.begin():
            try:
                ins = dbmeta.tables[tblname].insert().values(values)
                dbconn.execute(ins)
            except sql.exc.IntegrityError as e:
                # unique constraint violated
                pass
            except Exception as e:
                logger.exception(e)

    pt = __ProjectTable(tblname,
                        Tmpl.TARGET,
                        table_desc,
                        None,
                        insert_me)

    all_tables.append(pt)


#: a list of all table objects
all_tables = [_t for _n, _t in globals().items() if _n.startswith("table_")]
