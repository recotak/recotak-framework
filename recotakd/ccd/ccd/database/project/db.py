"""
This module contains database interactions that concern projects. Actual
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
database transactions are done in database.project.tables. However, this module
initialises the database and is responsible for converting a table to a
dictionary which can be used for report generation.

"""

from database.project import tables as projectdb
from ccdClasses import InvalidDBEntryError
from connection import ccdCrypto
import database.ccddb as ccddb
from urlparse import urlparse
from datetime import datetime
from threading import Lock
import sqlalchemy as sql
#from sqlalchemy_utils import dependent_objects
import logging

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)

#: locally cacha database connection
_cache = dict()

#: database engine options
ENGINE_ARGS = dict(encoding="utf-8", echo=False, pool_size=500)

#: fields which hold meta information about the result data and
#: should be excluded from reports and view requests
META_FIELDS = ['info', 'id', 'created', 'risk', 'scanid', 'target_id', 'targetdns_id']
META_TABLES = ['result_target_dns_rel', ]

def __get_real_table_name(tablename):
    """ extracts a table's real name by removing its prefix """
    underscore = tablename.find('_') + 1
    name = tablename[underscore:]
    return name

def init_project_db(db, dbh, pid, templates, psql_url, psql_db, tid, plg_id, extra={}, plgname=''):
    """ Create project database and its concerning templates and set up a
        connection the database.

        input:
            dbh         database handler of whom we just need the python id
            pid         project id
            templates   templates the plugin riegisters for
            psql_url    RFC-1738 conform url of the postgres server. To create
                        users and the database, without database
            psql_db     database name to connect to create db and user. will be
                        concatenated with 'psql_url'
            tid         task id
            plg_id      plugin id

        output:
            scanid

    """
    logger.info("initialising project db..")
    global _cache
    psql = "{url}/{db}".format(url=psql_url, db=psql_db)
    dbh_id = id(dbh)

    # get scan id for the following scan
    scanid = ccddb.insert_scan(db,
                               start=datetime.now(),
                               stop=None,
                               tid=tid,
                               plg_id=plg_id)

    # connect and return if project db already existing
    config = ccddb.get_projectdb_config(db, pid)
    if config:
        logger.debug("db configuration already in database")
        url = "{url}/{database}".format(
            url=psql_url,
            database=config[5]
        )
        dbengine, dbmeta, dbconn = __connect_to_projectdb(dbh_id, url, tid)

        # create tables
        allowed = projectdb.create_tables(dbconn, dbmeta, templates)

        username = "user_projectdb_%d" % pid
        __grant_project_db_priv(dbconn, username)

        # cache connection
        _cache[dbh_id] = (dbengine, dbmeta, dbconn, scanid, allowed)

        return scanid

    # connect to postgres. We use this connection for further database
    # and user creations.
    logger.debug("creating engine")
    dbengine = sql.create_engine(psql, **ENGINE_ARGS)
    tmp_conn = dbengine.connect()

    # create database
    dbname = "projectdb_%d" % pid
    dbmeta, dbconn = __create_db(tmp_conn, psql_url, dbname)

    # create tables
    allowed = projectdb.create_tables(dbconn, dbmeta, templates)

    if extra:
        projectdb.create_extra(dbmeta, extra, plgname, ['scanner'])

    #TODO write password to somewhere
    # create credentials
    username, password = __get_project_db_creds(dbconn, dbname)

    # store in database
    __store_project_config(db, pid, psql, username, password, dbname)

    # cache projectdb information for further validation and access
    _cache[dbh_id] = (dbengine, dbmeta, dbconn, scanid, allowed)
    logger.debug("_cache:%s", _cache)

    return scanid


def __store_project_config(db, pid, psql_url, username, password, dbname):
    """ store the project db information in ccddb

        input:
            psql_url    RFC-1738 conform url of the postgres server. To create
                        users and the database, connect to this database.
            username    The new username to connect with.
            password    The new password to connect with.
            dbname        name of the database to create

    """
    logger.debug("storing configuration %s", str(psql_url))
    parse_result = urlparse(psql_url)
    logger.debug("parse_result:%s", str(parse_result))
    ip = parse_result.hostname
    port = parse_result.port
    dialect = parse_result.scheme

    ccddb.store_projectdb_config(db, pid, dialect, username, password, ip,
                                 port, dbname)


def __create_db(tmp_conn, base_url, dbname):
    """ Create new database and connect to it. Return the new metadata and
        connection objects.

        input:
            tmp_conn    sql database connection object that is used to
                        create the database with
            base_url    RFC-1738 conform location postgresql is listing on (the
                        url must exclude the database!)
            dbname      name of the database to create

        output:
            meta    sql metadata object
            conn    sql database connection

    """
    logger.debug("creating project database")

    # The connection will still be inside a transaction, so you have to end
    # the open transaction with a commit
    tmp_conn.execute("commit")

    # Now create the database
    with tmp_conn.begin():
        try:
            tmp_conn.execute("CREATE DATABASE %s;" % dbname)
        except Exception as e:
            if "already exists" in str(e):
                logger.debug("database '%s' already exists", dbname)
            else:
                raise e

    # connect to new database
    db_url = "{url}/{database}".format(url=base_url, database=dbname)
    logger.debug("db_url:%s", db_url)
    engine = sql.create_engine(db_url, **ENGINE_ARGS)
    meta = sql.MetaData(engine)
    conn = engine.connect()

    return meta, conn


def __grant_project_db_priv(dbconn, username, privilege="SELECT"):
    logger.debug('Granted %s priv: %s', username, repr(privilege))
    with dbconn.begin():
        priv = "GRANT {privilege} ON ALL TABLES IN SCHEMA {scheme} TO "\
               "{user};".format(
                   privilege=privilege,
                   scheme="public",
                   user=username
               )
        dbconn.execute(priv)


def __get_project_db_creds(dbconn, dbname, n=10, privilege="SELECT"):
    """ Creates a new user for the project database. Grant set privileges
        to the new user..

        input:
            dbconn      A database connection that is used to create the new
                        postgresl user.
            dbname      Name of the project's database.
            n           Length of the password.
            privilege   Privileges to grant. Default is 'SELECT' (read).

        output:
            username    The new username to connect with.
            password    The new password to connect with.

    """
    logger.debug("creating db credentials..")
    username = "user_%s" % dbname
    password = ccdCrypto.getRandomBytes(n)
    logger.debug('Created %s with %s (priv: %s)',
                 username, password, repr(privilege))

    with dbconn.begin():
        #TODO sha1 hash of password
        create = "CREATE USER {user} WITH PASSWORD '{pwd}';".format(
            user=username,
            pwd=password
        )
        dbconn.execute(create)

    __grant_project_db_priv(dbconn, username, privilege=privilege)

    return username, password


def __connect_to_projectdb(dbh_id, url, tid):
    """ connect to project db and cache connection

        input:
            dbh_id  the python id of the database handler object
            url     RFC-1738 conform database url
            tid     task id

    """
    global _cache

    # if already connected return
    if dbh_id in _cache:
        dbengine, dbmeta, dbconn, _, _ = _cache[dbh_id]
        return dbengine, dbmeta, dbconn

    # connect to db
    logger.debug("Connecting to project db..")
    dbengine = sql.create_engine(url, **ENGINE_ARGS)

    dbmeta = sql.MetaData(dbengine)
    dbconn = dbengine.connect()

    # Load all available table definitions from the database.
    dbmeta.reflect()

    return dbengine, dbmeta, dbconn


def close(dbh):
    """
    close a database transaction

    input:
        dbh     database handler

    """
    logger.debug("closing database connection, dbh:%d", id(dbh))
    try:
        dbh_id = id(dbh)
        engine, _, conn, _, _ = _cache[dbh_id]
        logger.debug("closing database %s", conn)
        conn.close()
        engine.dispose()
    except KeyError:
        logger.warning("No connection stored for dbh_id:%d. Nothing to close! "
                       "The error might be caused by a failed connection to "
                       "database during projectdb creation. Check this!",
                       dbh_id)


def _DBTransaction_store(dbh_id, entry):
    """ Execute a database transaction. Verify that the transaction is
        executed on the correct table.

        input:
            dbh_id  the python id of the database handler object
            entry   entries to store in database

    """
    logger.debug("Committing database transactions.")

    # get metadata and connection
    logger.debug("_cache:%s", _cache)
    _, meta, conn, scanid, allowed = _cache[dbh_id]
    logger.debug("found metadata and connection in cache")

    # get sql statement and check whether entry type is allowed
    for t in projectdb.all_tables:
        if t.validate(entry):
            t.insert(conn, meta, entry, scanid)
            break
    else:
        logger.error("Failed to store entry. Invalid type %s", entry)
        raise InvalidDBEntryError(str(entry))


class DatabaseHandler(object):
    """
    The database handler is used by the plugin to interact with the
    database.

    """

    def __init__(self):
        self.lock = Lock()

    def add(self, entry):
        """ Store an entry in database. """
        #TODO some verification

        # store entry in database
        with self.lock:
            _DBTransaction_store(id(self), entry)

############################################################################
## table output ############################################################
############################################################################


def result_tables(db_pid=None, meta=None):
    """
    generator of result table object to be used for data view/show
    * table names are stripped of the result_ preceeding every
    * meta tables are excluded

    Input (needs one of both):
        db_pid  database, process id tuple (if specified, meta will be ignored)
        meta    db connection

    Output:
        Array of (table name, table object)
    """

    # if pid is specified meta will be overwritten
    if not db_pid is None:
        db, pid = db_pid
        # get database connection
        conf = ccddb.get_projectdb_config(db, pid)

        # no tables yet
        if not conf:
            logger.info('No results in project database')
            raise StopIteration

        addr = conf[0] + '://' + \
            conf[1] + ':' + conf[2] + '@' + \
            conf[3] + ':' + str(conf[4]) + '/' + \
            conf[5]
        _, meta, _ = __connect_to_projectdb(None, addr, 0)

    # sth went wrong or invalid input -> no tables
    if not meta:
        logger.warning('Database connection failed')
        raise StopIteration

    tables = {}
    # read the table names
    for tname, table in meta.tables.items():

        # we are only interested in plugin result tables
        # TODO: find a better way to distinguish those
        if not tname.startswith('result_'):
            continue

        if tname in META_TABLES:
            continue

        if tname == 'result_targetdns':
            targetdnsrel = meta.tables['result_target_dns_rel']
            for fk in targetdnsrel.foreign_keys:
                targetdnsrel.join(fk.column.table)
            table = targetdnsrel

        # if other tables are referenced via foreign keys,
        # we need to dereference those
        for fk in table.foreign_keys:
            table = table.join(fk.column.table)

        # clean up table name (we don't want/need the result_ in fron of every
        # table name
        tname = tname.replace('result_', '')

        #yield (tname, table)
        tables[tname] = table

    return tables


def get_table(db, pid, tname):
    """
    dump data from a table

    Input:
        db      database connection
        pid     project id
        tname   name of table to be dumped, without preceeding 'result_'

    output:
        (cc, rs) columns' names and results

    """

    logger.info('Getting data from table %s', tname)

    # get database connection
    conf = ccddb.get_projectdb_config(db, pid)
    if not conf:
        # no tables yet
        return []
    addr = conf[0] + '://' + \
        conf[1] + ':' + conf[2] + '@' + \
        conf[3] + ':' + str(conf[4]) + '/' + \
        conf[5]
    _, meta, conn = __connect_to_projectdb(None, addr, 0)

    #logger.info('Getting data from table: %s', tname)

    try:
        tbl = result_tables(meta=meta)[tname]
        #tbl = meta.tables[tname]
    except KeyError:
        logger.warning('Table %s not found', tname)
        return None

    #for fk in tbl.foreign_keys:
    #    tbl = tbl.join(meta.tables[fk.column.table.name])

    cc = [c.name for c in tbl.columns if c.name not in META_FIELDS]

    with conn.begin():
        s = sql.select(columns=cc).select_from(tbl)
        rs = conn.execute(s)

    return (cc, rs)


def get_tables(db, pid, columns_sel=[]):
    """
    get all table names, which are currently in the project database

    input:
        pid         project id
        columns_sel only return some selected columns

    output:
        tables      result as list

    """
    logger.info('Retrieving tables names, column selection: %s', columns_sel)

    # table array to be returned
    tables = {}

    # read the table names
    for tname, table in result_tables(db_pid=(db, pid)).items():

        included = True

        # if column selection is used, filter columns
        if columns_sel and columns_sel[0]:
            for column in columns_sel:
                if column not in [c.name for c in table.columns]:
                    included = False
                    break

        if included:
            tables[tname] = table

    return tables


def get_fields(db, pid, table_sel=[]):

    """
    get associative array of colum name -> tables using that column

    Input:
        pid        project id
        table_sel  table_sel to be included (empty array == all)

    output:
        tfields    dictionary

    """

    logger.info('Retrieving field names, table selection: %s', table_sel)

    # assoc array to be returned
    tfields = {}

    for tname, table in result_tables(db_pid=(db, pid)).items():

        # if table selection is user, filter tables
        if table_sel and table_sel[0] and tname not in table_sel:
            continue

        for column in table.columns:

            # skip meta fields
            if column.name in META_FIELDS:
                continue

            try:
                tfields[column.name].append(tname)
            except KeyError:
                tfields[column.name] = []
                tfields[column.name].append(tname)

    return tfields


def get_data(db, pid, column_sel=[], table_sel=[]):
    """
    get associative array of colum name -> tables using that column

    Input:
        pid         project id
        column_sel  column selection,
                    may include column names, e.g. [ip, fqdn, ...]
                    and/or condition for column values, e.g. [ip='127.0.0.1', fqdn, ...]
        table_sel   table_sel to be included (empty array == all)

    output:
        result

    """

    logger.info('Retrieving data. Columns: %s, Tables: %s',
                column_sel, table_sel)

    # get database connection
    conf = ccddb.get_projectdb_config(db, pid)
    if not conf:
        return {}
    addr = conf[0] + '://' + \
        conf[1] + ':' + conf[2] + '@' + \
        conf[3] + ':' + str(conf[4]) + '/' + \
        conf[5]
    _, meta, conn = __connect_to_projectdb(None, addr, 0)

    # TODO: maybe filter meta columns?
    column_sel = filter(lambda t: t and t not in META_FIELDS, column_sel)

    # filter options for colums, e.g. ip='127.0.0.7'
    # those are used as sql conditions
    # TODO: make sure this is safe
    filters = []
    for idx, cs in enumerate(column_sel):
        f = cs.split('=')
        if len(f) > 1:
            column_sel[idx] = f[0]
            filters.append(f[0] + '=' + f[1])

    logger.info('Filters: %s', filters)

    queries = []

    sth = False
    for tname, table in get_tables(db, pid, column_sel).items():
        logger.info('current table: %s', tname)

        sth = True
        if filters:
            q = sql.select(columns=column_sel).\
                select_from(table).\
                where(sql.and_(*filters)).distinct()
        else:
            q = sql.select(columns=column_sel).\
                select_from(table).\
                distinct()
        queries.append(q)

    if not sth:
        return None

    result = ''

    with conn.begin():
        # build query
        union_q = sql.union_all(*queries)
        try:
            # start query
            result = conn.execute(union_q)
        except Exception as e:
            logger.error('Error in sql \'%s\': %s', union_q, e)

    return result


def get_tables_dict(db,
                    pid,
                    skip_rows=META_FIELDS,
                    tbl_names=[],
                    group_by=None,
                    lang="de"):
    """
    return a database's tables as dictionary. first, get the projectdb's
    configuration (location, login creds) and connect to database. then
    iterate over tables

    input:
        db          database object
        pid         id of the project to get tables from
        skip_rows   rows that should be ignored
        tbl_names   tables to export
        grouped_by  a tuple that contains the table name and the column to
                    group by
        lang        languages to get get tables in

    output:
        tables      the dictionary containg the database's tables

    """
    tables = {}
    grouping = group_by
    logger.info('Group_by: %s', grouping)

    # get project config
    conf = ccddb.get_projectdb_config(db, pid)
    if not conf:
        raise Exception('Nothing to report yet')

    # connect
    addr = conf[0] + '://' + \
        conf[1] + ':' + conf[2] + '@' + \
        conf[3] + ':' + str(conf[4]) + '/' + \
        conf[5]

    db0 = db
    db = __connect_to_projectdb(None, addr, 0)[1:]
    meta = db[0]

    # read
    #for n, t in meta.tables.items():
    for n, t in get_tables(db0, pid, []).items():
        tbl_name = __get_real_table_name(n)

        # skipping unwanted tables
        if (tbl_names and tbl_names[0] and not tbl_name in tbl_names):
            logger.debug('skipping table %s', n)
            continue

        # if no group_by is passed, we check whether some default grouping is
        # set in database
        #if not group_by:
        #    db_grouping = projectdb.get_grouping_information_text(db, n)
        #    if db_grouping:
        #        grouping = [(tbl_name, db_grouping)]

        # check whether this table should be splitted in multiple output
        # tables
        if grouping:
            logger.debug("grouped tables requested:%s, n=%s", group_by,
                         tbl_name)
            for to_group, group_by_col in grouping:
                if to_group == tbl_name:
                    tables.update(__get_table_grouped_dict(db,
                                                           n,
                                                           t,
                                                           group_by_col,
                                                           skip_rows,
                                                           lang))
                    break
            else:
                tables.update(__get_table_dict(db, n, t, skip_rows, lang))

        else:
            logger.debug("no grouping for table %s", n)
            tables.update(__get_table_dict(db, n, t, skip_rows, lang))

    #logger.debug("table dict:%s", tables)
    return tables

def __get_table_dict(db, name, table, skip_rows, lang="de"):
    """
    Requests a table's data from sql and returns it as dict entry.
    In contrast to __get_table_grouped_dict() it does not group anything.

    example:
            database grouped by col3:

                    col1 | col2 | col3
                    -----+------+-----
                      1  | foo  | bar
                      2  | bar  | bar
                      3  | foo  | foo
                      4  | foo3 | foo
                      5  |foobar| bar

            result:

                database_bar = {
                    description: "This plugins scans for open ports.",
                    solution: "Disable unnecessary daemons and use a firewall"
                    data: [[col1, col2, col3],
                           [ 1  , foo , bar],
                           [ 2  , bar , bar],
                           [ 3  , foo , foo],
                           [ 4  , foo3, foo],
                           [ 5  , foobar, bar]
                          ]
                }


    input:
        db          tuple containg database meta object and connection
        name        name of the table to request.
        table       sqlalchemy table object of the table to request
        skip_rows   rows that should be ignored
        lang        languages to get get meta information in

    output:
        result_dict dictionary containg all virtual tables (see example above)


    """
    _, conn = db
    tbl_name = __get_real_table_name(name)
    table_dict = dict(description="", solution="", data=[])

    # description and solution
    desc, sol = projectdb.get_meta_information_text(db, name, lang)
    table_dict["description"] = desc
    table_dict["solution"] = sol

    # data
    # build data of list of columns to request from database
    cc = [c.name for c in table.columns if c.name not in skip_rows]
    logger.info("cc=%s", cc)

    # request actual data from database
    with conn.begin():
        s = sql.select(columns=cc, from_obj=table).distinct()
        rs = conn.execute(s)

    # add data to result dictionary
    data = [cc]
    for row in rs:
        data.append(map(str, row))
    table_dict["data"] = data

    #logger.debug("tables_dict=%s", table_dict)

    return {tbl_name: table_dict, }

def __get_table_grouped_dict(db, name, table, group_by, skip_rows, lang="de"):
    """
    Requests a table's data from sql, groups it and returns every group as
    separate table dict entry. In contrast, __get_table_dict() returns all
    table's (ungrouped) as ONE dict entry. The name of these virtual tables is
    the table name concat. with the value that is grouped by.

    example:
            database grouped by col3:

                    col1 | col2 | col3
                    -----+------+-----
                      1  | foo  | bar
                      2  | bar  | bar
                      3  | foo  | foo
                      4  | foo3 | foo
                      5  |foobar| bar

            result_dict:
                {
                    database_bar: {
                        solution: foobar,
                        description: foobar,
                        data: [[col1, col2],
                               [ 1  , foo ],
                               [ 2  , bar ],
                               [ 5  , foobar]
                               ]
                        },
                    database_foo: {
                        solution: foobar,
                        description: foobar,
                        data:[[col1, col2],
                              [ 3  , foo ],
                              [ 4  , foo3]
                             ]
                        }

                }


    input:
        db          tuple containg database meta object and connection
        base_name   name of the table to request. this acts as the base name of
                    the newly created virtual tables
        table       sqlalchemy table object of the table to request
        group_by    name of the column to group by/split by
        skip_rows   rows that should be ignored
        lang        languages to get get meta information in

    output:
        result_dict dictionary containg all virtual tables (see example above)

    """
    _, conn = db
    base_name = __get_real_table_name(name)
    group_by_idx = -1  # column index of column to group by
    tables = dict()

    # build list of columns to request from database
    cc = []
    i = 0
    for c in table.columns:
        if c.name in skip_rows:
            continue
        cc.append(c.name)
        if c.name == group_by:
            group_by_idx = i
        i += 1

    logger.debug("cc=%s", cc)
    logger.debug("group_by_idx=%s", group_by_idx)

    if group_by_idx < 0:
        raise Exception("Failed to group by column %s." % group_by)

    # request actual data from database
    with conn.begin():
        s = sql.select(columns=cc, from_obj=table)
        rs = conn.execute(s)

    # add data to result dictionary
    for row in rs:
        logger.debug("row=%s", row)
        tbl_name = "%s %s" % (base_name, row[group_by_idx])
        row = row[:group_by_idx] + row[group_by_idx + 1:]

        try:
            tables[tbl_name]["data"].append(map(str, row))
        except KeyError:
            tables[tbl_name] = dict(
                data=[cc[:group_by_idx] + cc[group_by_idx + 1:]],
                solution="",
                description=""
            )
            tables[tbl_name]["data"].append(map(str, row))

            desc, sol = projectdb.get_meta_information_text(db, name, lang)
            tables[tbl_name]["description"] = desc
            tables[tbl_name]["solution"] = sol

    return tables
