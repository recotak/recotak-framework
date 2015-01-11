"""
This module handels all ccd database interactions, that do not concern projects
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
specifics (e.g. storing data by plugin that is created during execution in
context of a project is stored in database.project.*). Though, this module
handles user, wgroup, proxychains and a lot more.

"""

from sqlalchemy.dialects import postgresql
from database.ccdErrors import *
from sqlalchemy import exc as sa_exc
import sqlalchemy as sql
import warnings
import logging
import types

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
warnings.simplefilter("ignore", category=sa_exc.SAWarning)

# database tables
__table_users = "users"
__table_passwd = "_passwd"
__table_sessions = "sessions"
__table_ptype = "ptypes"
__table_role = "roles"
__table_projects = "projects"
__table_workgroup = "workgroups"
__table_user2project = "_user2project"
__table_user2workgroup = "_user2workgroup"
__table_user2user = "_user2user"
__table_projectdb_config = "_projectdb_config"
__table_projectdb_passwd = "_projectdb_passwd"
__table_plugins = "plugins"
__table_project2plugin = "_project2plugin"
__table_workgroup2plugin = "_workgroup2plugin"
__table_fd = "_fd"
__table_scans = "scans"
__table_tasks = "tasks"
__table_proxies = "proxies"
__table_protocols = "_protocols"
__table_proxychains = "proxychains"
__table_conngroup = "conngroup"
__table_proxy2chain = "_proxy2chain"
__table_chain2group = "_chain2group"
__table_group2project2plugin = "_group2project2plugin"

# engine option
ENGINE_ARGS = dict(encoding="utf-8",
                   echo=False,
                   pool_size=0,
                   pool_reset_on_return='commit')
#                   poolclass=sql.pool.NullPool)
__meta = sql.MetaData()
__engine = None

# some db constraints
MAX_LEN_NAME = 255
MAX_LEN_MAIL = 255
MAX_LEN_PASSWORD = 255
MAX_LEN_DESC = 8096

# Role ids referenced by callers if they want to add relations
# like user2projects. The ids are created as soon as they are
# added to the database.
ROLE_SA = -1
ROLE_ADMIN = -1
ROLE_USER = -1
ROLE_VIEW = -1

# the rights that are defined in the role table
ACCESS_READ = 1
ACCESS_WRITE = 2
ACCESS_ADD = 4
ACCESS_DEL = 8
ACCESS_EXEC = 16

# The ptype state the type of a project
PTYPE_AUDIT = -1
PTYPE_ROUTINE = -1
PTYPE_ANALYSIS = -1


def initdatabase(url):
    """ Connect to database, create database session and create
        tables.
    """
    logger.info("Initialising database..")
    # database session
    db = getDatabaseMetadata(url)
    meta, conn = db

    # initialise tables
    createRoleTable(meta)
    createUserTable(meta)
    createPasswdTable(meta)
    createWorkgroupTable(meta)
    createUser2WorkgroupTable(meta)
    createpTypeTable(meta)
    create_projectdb_config_table(meta)
    create_projectdb_passwd_table(meta)
    createProjectTable(meta)
    createUser2ProjectTable(meta)
    createUser2UserTable(meta)
    createPluginTable(meta)
    createProject2PluginTable(meta)
    createWorkgroup2PluginTable(meta)
    createFdTable(meta)
    createSessionTable(meta)
    createTaskTable(meta)
    createScanTable(meta)
    createProtocolTable(meta)
    createProxyTable(meta)
    createProxyChainTable(meta)
    createProxy2ChainTable(meta)
    createConnectionGroupTable(meta)
    createChain2GroupTable(meta)
    createGroup2Project2PluginTable(meta)

    meta.create_all(conn, checkfirst=True)

    # create roles
    _init_roles(db)

    # create project types
    _init_ptypes(db)

    # create some basic protocols
    _init_protocols(db)

    # check plugins' states for illegal values. this might occur if the ccd is
    # SIGKILLed
    _sanitise_fd_state(db)

    return db

def _init_protocols(db):
    """ create some basic protocols """
    add_protocol(db, "s4", on_error_return_id=True)
    add_protocol(db, "direct", on_error_return_id=True)

def _init_roles(db):
    logger.debug("creating roles")
    global ROLE_SA, ROLE_ADMIN, ROLE_USER, ROLE_VIEW

    try:
        sa = "SA"
        ROLE_SA = create_role(db, sa, (True, True, True, True, True))
    except AlreadyExistingError:
        ROLE_SA = getrole_byname(db, sa)[0]

    try:
        admin = "Admin"
        ROLE_ADMIN = create_role(db, admin, (True, True, True, True, True))
    except AlreadyExistingError:
        ROLE_ADMIN = getrole_byname(db, admin)[0]

    try:
        user = "User"
        ROLE_USER = create_role(db, user, (True, True, False, False, True))
    except AlreadyExistingError:
        ROLE_USER = getrole_byname(db, user)[0]

    try:
        view = "View"
        ROLE_VIEW = create_role(db, view, (True, False, False, False, False))
    except AlreadyExistingError:
        ROLE_VIEW = getrole_byname(db, view)[0]


def _init_ptypes(db):
    """ create the initial roles """
    global PTYPE_AUDIT, PTYPE_ROUTINE, PTYPE_ANALYSIS

    try:
        ptype_audit = "Audit"
        PTYPE_AUDIT = create_ptype(db, ptype_audit)
    except AlreadyExistingError:
        PTYPE_AUDIT = getptype_byname(db, ptype_audit)[0]

    try:
        ptype_routine = "Routine"
        PTYPE_ROUTINE = create_ptype(db, ptype_routine)
    except AlreadyExistingError:
        PTYPE_ROUTINE = getptype_byname(db, ptype_routine)[0]

    try:
        ptype_analysis = "Analysis"
        PTYPE_ANALYSIS = create_ptype(db, ptype_analysis)
    except AlreadyExistingError:
        PTYPE_ANALYSIS = getptype_byname(db, ptype_analysis)[0]


def connect_to_database(url):
    """
    create new database engine and return bound metadata and
    connection

    """
    meta, conn = getDatabaseMetadata(url)
    meta.reflect()

    return meta, conn

def connect():
    """
    returns a new connection from sql connection pool. note, this does not
    recreate the database engine

    """
    connection = __engine.connect()

    return __meta, connection

def close(db):
    """
    closes a database connection

    input:
        db  tuple containing db meta and db connection

    """
    logger.debug("closing database connection..")
    conn = db[1]
    conn.close()

def getDatabaseMetadata(addr):
    """ Connect to database and create a database session. Return a database
        session object and the database session factory.
    """
    global __engine, __meta
    logger.debug("creating database metadata %s", addr)
    __engine = sql.create_engine(addr, **ENGINE_ARGS)
    __meta = sql.MetaData(__engine)
    connection = __engine.connect()

    return __meta, connection


###############################################
#             Plugin stuff
###############################################

def createPluginTable(meta):
    """ Create the table that contains plugin information. """
    logger.debug("creating table %s", __table_plugins)

    tbl = sql.Table(__table_plugins, meta,
        sql.Column("plg_id", sql.String, primary_key=True, index=True),
        sql.Column("name", sql.String, nullable=False, index=True),
        sql.Column("category", sql.String, nullable=True),
        sql.Column("dbtemplates", sql.String, nullable=True),
        sql.Column("interactive", sql.Boolean, default=False),
        sql.Column("runasroot", sql.Boolean, default=False),
        sql.Column("direct", sql.Boolean, default=False),
        sql.Column("created", sql.DateTime, default=sql.func.now()),
        sql.Column("deleted", sql.Boolean, default=False),
        sql.Column("description", sql.String, nullable=True),
        sql.Column("rank", sql.String, nullable=True),
        sql.Column("cli", sql.String, nullable=True),
        sql.Column("solution", sql.String, nullable=True)
    )

    sql.Index("unique_plugin", tbl.c.name,
                               postgresql_where=tbl.c.deleted==False,
                               unique=True)

    return tbl

def check_plgid(db, plg_id):
    """
    checks if __table_plugins contains a row with
    column plg_id == plg_id

    input:
        plg_id  plugin's id

    """
    meta, conn = db
    res = []
    with conn.begin():
        tbl = meta.tables[__table_plugins]
        sel = sql.select([tbl.c.plg_id]).where(tbl.c.plg_id==plg_id)
        res = conn.execute(sel).fetchall()
    return res

def check_nraise_plgid(db, plg_id):
    """
    checks if __table_plugins contains a row with
    column plg_id == plg_id.
    If not an NotFoundError is raised

    input:
        plg_id  plugin's id

    """
    if not check_plgid(db, plg_id):
        raise NotFoundError("No such plugin id: '%s'" % plg_id)

def get_plugin_name_by_id(db, plg_id):
    """
    return the plugins name

    input:
        plg_id  plugin's id

    """
    meta, conn = db
    with conn.begin():
        tbl = meta.tables[__table_plugins]
        sel = sql.select([tbl.c.name]).where(
                sql.and_(tbl.c.plg_id==plg_id,
                         tbl.c.deleted==False)
                )
        res = conn.execute(sel).fetchone()

    return res

def undelete_plugin_by_id(db, plg_id):
    """
    undelete a plugin by a given id

    input:
        plg_id plugin's id

    """
    meta, conn = db
    with conn.begin():
        tbl = meta.tables[__table_plugins]
        stmt = tbl.update().\
                    where(sql.and_(
                            tbl.c.plg_id==plg_id,
                            tbl.c.deleted==True)).\
                    values(deleted=False)
        conn.execute(stmt)
        conn.execute("commit")

def delete_plugin_by_name(db, plg_name):
    """
    delete a plugin by a given name

    input:
        plg_name  plugin's name

    """
    meta, conn = db
    with conn.begin():
        tbl = meta.tables[__table_plugins]
        stmt = tbl.update().\
                    where(sql.and_(
                            tbl.c.name==plg_name,
                            tbl.c.deleted==False)).\
                    values(deleted=True)
        conn.execute(stmt)
        conn.execute("commit")

def get_all_plugins(db):
    """ returns a list with all plugin ids """
    meta, conn = db
    with conn.begin():
        tbl = meta.tables[__table_plugins]
        sel = sql.select([tbl.c.plg_id]).where(
                         tbl.c.deleted==False
                    )
        res = conn.execute(sel)

    return res

def add_plugin(db, **kwargs):
    """ add plugin to plugin table """
    meta, conn = db
    tbl = meta.tables[__table_plugins]
    try:
        with conn.begin():
            ins = tbl.insert()
            conn.execute(ins,
                         plg_id=kwargs["id"],
                         name=kwargs["name"],
                         category=kwargs["categories"],
                         dbtemplates=kwargs["dbtemplate"],
                         interactive=kwargs["interactive"],)
            conn.execute("commit")

    except sql.exc.IntegrityError:
        raise AlreadyExistingError("Plugin already in database!")
    except KeyError as ke:
        raise InvalidQuery("Invalid kwargs passed:'%s'" % str(ke))

def createProject2PluginTable(meta):
    """ Create project2plugin table and return table object """
    logger.debug("creating table %s", __table_project2plugin)
    tbl = sql.Table(__table_project2plugin, meta,
        sql.Column("pid", sql.Integer, sql.ForeignKey("projects.pid"),
                                                            nullable=False),
        sql.Column("plg_id", sql.String, sql.ForeignKey("plugins.plg_id"),
                                                            nullable=False),
        sql.Column("deleted", sql.Boolean, default=False),
        #extend_existing=True

    )
#    tbl.create(checkfirst=True)
    sql.Index("p2p_unique", tbl.c.plg_id, tbl.c.pid,
                            postgresql_where=tbl.c.deleted==False,
                            unique=True)


    return tbl

def add_project2plugin(db, pid, plg_id):
    """ Add new project plugin relation."""

    # make sure the plugin id exists,
    # otherwise we might get a missing foreign key error
    check_nraise_plgid(db, plg_id)
    check_nraise_pid(db, pid)

    meta, conn = db
    try:
        with conn.begin():
            entry = meta.tables[__table_project2plugin].insert()
            conn.execute(entry, plg_id=plg_id, pid=pid)

    except sql.exc.IntegrityError as e:
        logger.error("Failed to store project2plugin relation:'%s'", str(e))
        if "p2p_unique" in str(e):
            raise AlreadyExistingError("Plugin already connected "
                                       "with project!")
        else:
            raise e

def delete_project2plugin(db, pid, plg_id):
    """ sets the delete flag """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_project2plugin]
        stmt = tbl.update().\
                    where(sql.and_(tbl.c.plg_id==plg_id, tbl.c.pid==pid)).\
                    values(deleted=True)
        conn.execute(stmt)
        conn.execute("commit")

def createWorkgroup2PluginTable(meta):
    """ Create project2plugin table and return table object """
    logger.debug("creating table %s", __table_workgroup2plugin)

    tbl = sql.Table(__table_workgroup2plugin, meta,
        sql.Column("wid", sql.Integer, sql.ForeignKey("workgroups.wid"),
                                                            nullable=False),
        sql.Column("plg_id", sql.String, sql.ForeignKey("plugins.plg_id"),
                                                            nullable=False),
        sql.Column("deleted", sql.Boolean, default=False),
        #extend_existing=True

    )

    sql.Index("w2p_unique", tbl.c.plg_id, tbl.c.wid,
              unique=True, postgresql_where=tbl.c.deleted==False)

    return tbl

def add_workgroup2plugin(db, wid, plg_id):
    """ Add new workgroup plugin relation."""
    logger.debug("add workgroup2plugin")

    # make sure the plugin id exists,
    # otherwise we might get a missing foreign key error
    check_nraise_plgid(db, plg_id)
    check_nraise_wid(db, wid)

    meta, conn = db

    try:
        with conn.begin():
            entry = meta.tables[__table_workgroup2plugin].insert()
            conn.execute(entry, plg_id=plg_id, wid=wid)
            conn.execute("commit")

    except sql.exc.IntegrityError as e:
        logger.error("Failed to store workgroup2plugin relation:'%s'", str(e))
        if "w2p_unique" in str(e):
            raise AlreadyExistingError("Plugin already connected "
                                       "with workgroup!")
        else:
            raise e

def delete_workgroup2plugin(db, wid, plg_id):
    """ sets the delete flag """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_workgroup2plugin]
        stmt = tbl.update().\
                where(sql.and_(tbl.c.plg_id==plg_id, tbl.c.wid==wid)).\
                values(deleted=True)
        conn.execute(stmt)

###############################################
#             Project stuff
###############################################

def createpTypeTable(meta):
    """ Create the table that contains project types. """
    logger.debug("creating table %s", __table_ptype)

    tbl = sql.Table(__table_ptype, meta,
                    sql.Column("tid", sql.Integer, primary_key=True, autoincrement=True),
                    sql.Column("name", sql.String, nullable=False, unique=True),
                    sql.Column("created", sql.DateTime, default=sql.func.now()),
                    extend_existing=True)
    return tbl


def create_ptype(db, name):
    """ create projects' type table """
    meta, conn = db

    tbl = meta.tables[__table_ptype]
    try:
        with conn.begin():
            entry = tbl.insert()
            res = conn.execute(entry, name=name)
            tid = res.inserted_primary_key[0]
            conn.execute("commit")

    except (sql.exc.IntegrityError, sql.exc.ProgrammingError) as e:
        if "ptypes_name_key" in str(e):
            raise AlreadyExistingError("Type '%s' already in database!" % name)
        else:
            logger.error("Failed to store ptype '%s':'%s'", name, str(e))
            raise e

    return tid

def delete_ptype_byname(db, name):
    """ remove project type by name """
    meta, conn = db

    with conn.begin():
        delete = meta.tables[__table_ptype].delete()
        conn.execute(delete, name=name)

def getptype_byname(db, name):
    """ return type with given name """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_ptype]
        select = tbl.select().where(tbl.c.name==name)
        res = conn.execute(select).fetchone()

    return res

def add_user2project(db, uid, pid, rid):
    """ Add new user project relation."""
    check_nraise_uid(db, uid)
    check_nraise_pid(db, pid)

    meta, conn = db

    try:
        with conn.begin():
            entry = meta.tables[__table_user2project].insert()
            conn.execute(entry, uid=uid, pid=pid, rid=rid)
            conn.execute("commit")

    except sql.exc.IntegrityError as e:
        logger.error("Failed to store user2project relation:'%s'", str(e))
        if "u2p_unique" in str(e):
            raise AlreadyExistingError("User already connected with project!")
        else:
            raise e

def delete_user2project(db, uid, pid):
    """ sets the delete flag """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_user2project]
        stmt = tbl.update().\
                where(sql.and_(tbl.c.uid==uid, tbl.c.pid==pid)).\
                values(deleted=True)
        conn.execute(stmt)
        conn.execute("commit")

def createUser2ProjectTable(meta):
    """ Create user2project table and return table object """
    logger.debug("creating table %s", __table_user2project)

    tbl = sql.Table(__table_user2project, meta,
        sql.Column("uid", sql.Integer, sql.ForeignKey("users.uid"),
                                                            nullable=False),
        sql.Column("pid", sql.Integer, sql.ForeignKey("projects.pid"),
                                                            nullable=False),
        sql.Column("rid", sql.Integer, sql.ForeignKey("roles.rid"),
                                                            nullable=False),
        sql.Column("deleted", sql.Boolean, default=False),
        extend_existing=True

    )
    sql.Index("u2p_unique", tbl.c.uid, tbl.c.pid,
                            postgresql_where=tbl.c.deleted==False,
                            unique=True)

    return tbl

def createProjectTable(meta):
    """ Create project table and return table object. """
    logger.debug("creating table %s", __table_projects)
    tbl = sql.Table(__table_projects, meta,
        sql.Column("pid", sql.Integer,
                          primary_key=True,
                          autoincrement=True),
        sql.Column("name", sql.String(MAX_LEN_NAME),
                           nullable=False),
        sql.Column("type", sql.Integer,
                           sql.ForeignKey("ptypes.tid"),
                           nullable=False),
        sql.Column("created", sql.DateTime,
                              default=sql.func.now()),
        sql.Column("creator", sql.Integer,
                              sql.ForeignKey("users.uid"),
                              nullable=False),
        sql.Column("owner", sql.Integer,
                            sql.ForeignKey("users.uid"),
                            nullable=False),
        sql.Column("deleted", sql.Boolean, default=False),
        sql.Column("projectdb", sql.Integer,
                                sql.ForeignKey("_projectdb_config.pdb_id")),
        sql.Column("description", sql.String(MAX_LEN_DESC),
                           nullable=True,
                           unique=False),
        #extend_existing=True
    )
    sql.Index("unique_project", tbl.c.name,
                                postgresql_where=tbl.c.deleted==False,
                                unique=True)


    return tbl

def check_pid(db, pid):
    """
    checks if __table_project contains a row with
    column pid == pid

    input:
        pid  project's id

    """
    meta, conn = db
    res = []
    with conn.begin():
        tbl = meta.tables[__table_projects]
        sel = sql.select([tbl.c.pid]).where(tbl.c.pid==pid)
        res = conn.execute(sel).fetchall()
    return res

def check_nraise_pid(db, pid):
    """
    checks if __table_plugins contains a row with
    column pid == pid.
    If not an NotFoundError is raised

    input:
        pid  plugin's id

    """
    if not check_pid(db, pid):
        raise NotFoundError("No such project id: '%s'" % pid)


def create_project(db, name, creator_uid, owner_uid, ptype, description=""):
    """ create a project entry. return project id """
    meta, conn = db
    logger.debug("creating project")

    with conn.begin():
        try:
            ins = meta.tables[__table_projects].insert()
            res = conn.execute(ins,
                            name=name,
                            creator=creator_uid,
                            owner=owner_uid,
                            description=description,
                            type=ptype)
            sel = meta.tables[__table_projects].select()
            p_res = conn.execute(sel, id=res.inserted_primary_key[0]).fetchone()
            conn.execute("commit")
        except sql.exc.IntegrityError as e:
            logger.error("Failed to store project:'%s'", str(e))
            if "unique_project" in str(e):
                raise AlreadyExistingError("Project already in db")
            else:
                raise e


    pid = res.inserted_primary_key[0]
    created = p_res[2]
    logger.debug("pid:%s, created:%s", pid, created)
    return pid, created

def get_all_projects(db):
    """ return all existing non-deleted workgroups """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_projects]
        sel = tbl.select().where(tbl.c.deleted==False)
        projs = conn.execute(sel).fetchall()

    return projs

def delete_project(db, pid):
    """ delete project given by its id """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_projects]
        stmt = tbl.update().\
                where(sql.and_(tbl.c.pid==pid)).\
                values(deleted=True)
        conn.execute(stmt)
        conn.execute("commit")


def update_project_description(db, pid, description):
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_projects]
        stmt = tbl.update().\
                    where(sql.and_(tbl.c.pid==pid)).\
                    values(description=description)
        conn.execute(stmt)
        conn.execute("commit")


def update_project(db, pid, name, ptype, creator, owner, description):
    """ updata a project's entry given by its id. """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_projects]
        stmt = tbl.update().\
                    where(sql.and_(tbl.c.pid==pid)).\
                    values(name=name,
                           type=ptype,
                           creator=creator,
                           owner=owner,
                           description=description)
        conn.execute(stmt)
        conn.execute("commit")

def getproject_byuid(db, uid):
    """ return projects' pid that is associated with a user given by uid """
    meta, conn = db
    tbl = meta.tables[__table_user2project]
    tbl_p = meta.tables[__table_projects]

    with conn.begin():
        select = sql.select([
                        tbl_p.c.pid,
                        tbl_p.c.name,
                        tbl_p.c.type,
                        tbl_p.c.created,
                        tbl_p.c.creator,
                        tbl_p.c.owner,
                        ]).where(
                  sql.or_(
                     sql.and_(
                        tbl.c.uid==uid,
                        tbl.c.deleted==False,
                        tbl_p.c.deleted==False),
                     sql.and_(
                        tbl_p.c.owner==uid,
                        tbl_p.c.deleted==False),
                     sql.and_(
                        tbl_p.c.creator==uid,
                        tbl_p.c.deleted==False)
                  )

             ).select_from(
                tbl_p.outerjoin(tbl)
             ).group_by(tbl_p.c.pid)
        entries = conn.execute(select).fetchall()
#    pids = [p[0] for p in entries]
    return entries


def getproject_byname(db, name):
    """ return entry for project with the given name that is not deleted """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_projects]
        select = tbl.select().where(
            sql.and_(tbl.c.name==name, tbl.c.deleted==False)
            )
        project = conn.execute(select).fetchone()

    return project

def getproject_bypid(db, pid):
    """
    return entry for project with the given id that is not deleted

    input:
        db  tuple containing db meta and db connection
        pid project id to look for

    output:
        project
    """
    meta, conn = db

    with conn.begin():
        tbl = meta.tables[__table_projects]
        select = tbl.select().where(
            sql.and_(tbl.c.pid==pid, tbl.c.deleted==False)
            )
        project = conn.execute(select).fetchone()

    return project

def get_project_access(db, pid, uid):
    """
    returns a user's access matrix

    input:
        db  tuple containing db meta and db connection
        pid project id to query permissions  of
        uid user id of the user who's permissions are checked

    output:
        permission  permission matrix

    """
    meta, conn = db
    tbl_p = meta.tables[__table_user2project]
    tbl_r = meta.tables[__table_role]

    with conn.begin():
        select = sql.select([
            "roles.read",
            "roles.write",
            "roles.add",
            "roles.write",
            "roles.execute"
            ],
            sql.and_(
                tbl_p.c.pid == pid,
                tbl_p.c.uid == uid,
                tbl_p.c.deleted == False
                )
           ).\
           select_from(
                tbl_p.join(tbl_r)
           )

        matrix = conn.execute(select).fetchone()

    if matrix:
        permissions = _get_permissions(*matrix)
    else:
        permissions = 0
    return permissions

def get_project_plugins(db, pid):
    """ returns a list of plg_ids that are part of project """
    meta, conn = db
    tbl = meta.tables[__table_project2plugin]

    with conn.begin():
        sel = sql.select([tbl.c.plg_id]).where(
            sql.and_(tbl.c.pid==pid, tbl.c.deleted==False)
        )
        entries = conn.execute(sel).fetchall()

    plg_ids = [p[0] for p in entries]
    return plg_ids

def get_project_members(db, pid):
    """ return a list of a project's members """
    meta, conn = db
    tbl = meta.tables[__table_user2project]
    tbl_u = meta.tables[__table_users]
    tbl_p = meta.tables[__table_projects]

    with conn.begin():
        sel = sql.select([
                    tbl_u.c.uid,
                    tbl_u.c.name,
                    tbl_u.c.mail,
                    tbl_u.c.created,
                    tbl.c.rid
                    ]).where(
                        sql.and_(
                            tbl.c.pid==pid,
                            tbl.c.deleted==False,
                            tbl_u.c.deleted==False,
                            tbl_p.c.deleted==False
                            )
                    ).select_from(
                        tbl.join(tbl_u).join(tbl_p, tbl.c.pid == tbl_p.c.pid)
                    )
        entries = conn.execute(sel).fetchall()

    return entries

def create_projectdb_config_table(meta):
    """ Create the table that contains project configuration. """
    sql.Table(__table_projectdb_config, meta,
              sql.Column("pdb_id", sql.Integer, primary_key=True,
                         autoincrement=True),
              sql.Column("user", sql.String, nullable=False),
              sql.Column("dialect", sql.String, nullable=False),
              sql.Column("dbname", sql.String, nullable=False),
              sql.Column("ip", sql.String, nullable=False),
              sql.Column("port", sql.Integer, nullable=False),
              sql.Column("created", sql.DateTime, default=sql.func.now())

    )
    return types

def create_projectdb_passwd_table(meta):
    """ Create Table that contains projectdb password """
    pwds = sql.Table(__table_projectdb_passwd, meta,
        sql.Column("pdb_id", sql.Integer,
                             sql.ForeignKey("_projectdb_config.pdb_id"),
                             nullable=False),
        sql.Column("password", sql.String, nullable=False),
        #extend_existing=True

    )
    return pwds

def get_projectdb_config(db, pid):
    """ return the projectdb configuration for a given project id """
    meta, conn = db
    logger.debug('Getting config for project %d', pid)

    tbl_proj = meta.tables[__table_projects]
    tbl_pdb = meta.tables[__table_projectdb_config]
    tbl_pwd = meta.tables[__table_projectdb_passwd]

    with conn.begin():
        sel = sql.select([tbl_pdb.c.dialect,
                      tbl_pdb.c.user,
                      tbl_pwd.c.password,
                      tbl_pdb.c.ip,
                      tbl_pdb.c.port,
                      tbl_pdb.c.dbname
                      ],
                      tbl_proj.c.pid==pid
              ).\
              select_from(
                tbl_proj.join(tbl_pdb.join(tbl_pwd))
              )
        config = conn.execute(sel).fetchone()

    return config

def store_projectdb_config(db, pid, dialect, user, pwd, ip, port, dbname):
    """ store project db configuration to ccddb database """
    meta, conn = db

    tbl = meta.tables[__table_projectdb_config]
    tbl_pwd = meta.tables[__table_projectdb_passwd]
    tbl_proj = meta.tables[__table_projects]

    with conn.begin():
        ins_cfg = tbl.insert().values(
                dialect=dialect,
                user=user,
                ip=ip,
                port=port,
                dbname=dbname)
        res = conn.execute(ins_cfg)

        ins_pwd = tbl_pwd.insert().values(
                pdb_id=res.inserted_primary_key[0],
                password=pwd
                )
        conn.execute(ins_pwd)

        upd_proj = tbl_proj.update().values(
                projectdb=res.inserted_primary_key[0]
               ).\
               where(
                tbl_proj.c.pid==pid
               )
        conn.execute(upd_proj)
        conn.execute("commit")

###############################################################################
#                           protocols
###############################################################################

def createProtocolTable(meta):
    """ Create protocol table and return table object """
    logger.debug("creating table %s", __table_protocols)

    tbl = sql.Table(__table_protocols, meta,
        sql.Column("protid", sql.Integer, primary_key=True, autoincrement=True),
        sql.Column("name", sql.String(MAX_LEN_DESC), nullable=False, unique=True)
        )

    return tbl

def add_protocol(db, name, on_error_return_id=False):
    """ add a new protocol """
    meta, conn = db

    with conn.begin():
        add = meta.tables[__table_protocols].insert()

        try:
            res = conn.execute(add, name=name)
            conn.execute("commit")
            protid = res.inserted_primary_key[0]
        except sql.exc.IntegrityError as ie:
            if not on_error_return_id:
                raise ie

    if on_error_return_id:
        protid = get_protid_by_name(db, name)
        logger.debug("protocol %s alread in db. protid:%s", name, protid)

    return protid

def get_protid_by_name(db, name):
    """ return the protocol id by a given name """
    meta, conn = db
    tbl = meta.tables[__table_protocols]

    with conn.begin():
        sel = sql.select([tbl.c.protid]).where(tbl.c.name==name)
        protid = conn.execute(sel).fetchone()

    return protid[0] if protid else None

###############################################################################
#                           proxies
###############################################################################

def createProxyTable(meta):
    """ Create proxies table and return table object """
    logger.debug("creating table %s", __table_proxies)
    protid = meta.tables[__table_protocols].c.protid

    tbl = sql.Table(__table_proxies, meta,
        sql.Column("pxid", sql.Integer, primary_key=True, autoincrement=True),
        sql.Column("ip", postgresql.INET, nullable=False),
        sql.Column("port", sql.Integer, nullable=False),
        sql.Column("protid", sql.Integer, sql.ForeignKey(protid),
                                          nullable=False),
        sql.Column("created", sql.DateTime, default=sql.func.now()),
        sql.Column("deleted", sql.Boolean, default=False),
        sql.Column("description", sql.String(MAX_LEN_DESC), nullable=True),
        #extend_existing=True
        )

    sql.Index("proxy_unique", tbl.c.ip, tbl.c.port,
               unique=True, postgresql_where=tbl.c.deleted==False)

    return tbl

def check_pxid(db, pxid):
    """
    checks if __table_workgroup contains a row with
    column pxid == pxid

    input:
        pxid  project's id

    """
    meta, conn = db
    res = []
    with conn.begin():
        tbl = meta.tables[__table_proxies]
        sel = sql.select([tbl.c.pxid]).where(tbl.c.pxid==pxid)
        res = conn.execute(sel).fetchall()
    return res

def check_nraise_pxid(db, pxid):
    """
    checks if __table_plugins contains a row with
    column pxid == pxid.
    If not an NotFoundError is raised

    input:
        pxid  plugin's id

    """
    if not check_pxid(db, pxid):
        raise NotFoundError("No such proxy id: '%s'" % pxid)



def add_proxy(db, ip, port, protocol, description):
    """ add a new proxy to proxy table """
    meta, conn = db

    with conn.begin():
        # first get the id of the procotol, used as foreign key in proxy table
        protid = get_protid_by_name(db, protocol)

        if not protid:
            raise Exception("No such protocol %s." % protocol)

        # add proxy
        add = meta.tables[__table_proxies].insert()

        try:
            res = conn.execute(add, ip=ip,
                          port=port,
                          protid=protid,
                          description=description)
        except sql.exc.IntegrityError as ie:
            if "violates unique constraint" in str(ie):
                raise AlreadyExistingError()
            else:
                raise ie

        conn.execute("commit")
        pxid = res.inserted_primary_key[0]

    return pxid

def delete_proxy(db, pxid):
    """ delete proxy from proxy table """
    meta, conn = db
    tbl = meta.tables[__table_proxies]

    with conn.begin():
        delete = tbl.update().where(tbl.c.pxid==pxid).values(deleted=True)
        conn.execute(delete)
        conn.execute("commit")

def get_proxy_by_id(db, pxid):
    """ get proxy configuration for a given proxy id """
    meta, conn = db
    tbl = meta.tables[__table_proxies]
    tbl_prot = meta.tables[__table_protocols]

    with conn.begin():
        sel = sql.select([tbl.c.pxid,
                          tbl.c.ip,
                          tbl.c.port,
                          tbl_prot.c.name,
                          tbl.c.description
                        ]).where(
                            sql.and_(
                                tbl.c.deleted==False,
                                tbl.c.pxid==pxid)
                        ).select_from(tbl.join(tbl_prot))
        res = conn.execute(sel).fetchone()

    return res

def get_proxy_by_addr(db, ip, port):
    """ get proxy configuration for a given proxy address """
    meta, conn = db
    tbl = meta.tables[__table_proxies]
    tbl_prot = meta.tables[__table_protocols]

    with conn.begin():
        sel = sql.select([tbl.c.pxid,
                          tbl.c.ip,
                          tbl.c.port,
                          tbl_prot.c.name,
                          tbl.c.description
                        ]).where(
                            sql.and_(
                                tbl.c.deleted==False,
                                tbl.c.ip==ip,
                                tbl.c.port==port)
                        ).select_from(tbl.join(tbl_prot))
        res = conn.execute(sel).fetchone()

    return res


def get_all_proxies(db):
    """ return a list of all proxies """
    meta, conn = db
    tbl = meta.tables[__table_proxies]
    tbl_prot = meta.tables[__table_protocols]

    with conn.begin():
        sel = sql.select([tbl.c.pxid,
                          tbl.c.ip,
                          tbl.c.port,
                          tbl_prot.c.name,
                          tbl.c.description
                        ]).where(tbl.c.deleted==False).\
                          select_from(tbl.join(tbl_prot))

        res = conn.execute(sel)

    return res

###############################################################################
#                        proxy chain
###############################################################################

def createProxyChainTable(meta):
    """ Create proxies table and return table object """
    logger.debug("creating table %s", __table_proxychains)

    tbl = sql.Table(__table_proxychains, meta,
        sql.Column("pcid", sql.String, primary_key=True),
        sql.Column("created", sql.DateTime, default=sql.func.now()),
        sql.Column("deleted", sql.Boolean, default=False),
        sql.Column("description", sql.String, nullable=True),
        #extend_existing=True
        )

    return tbl

def check_pcid(db, pcid):
    meta, conn = db
    res = []
    with conn.begin():
        tbl = meta.tables[__table_proxychains]
        sel = sql.select([tbl.c.pcid]).where(tbl.c.pcid==pcid)
        res = conn.execute(sel).fetchall()
    return res

def check_nraise_pcid(db, pcid):
    if not check_pcid(db, pcid):
        raise NotFoundError("No such proxy chain id: '%s'" % pcid)


def add_proxychain(db, pcid, description):
    """
    add a new proxy to proxy table

    input:
        db          database meta/connection tuple
        pcid        proxy chain id string
        description additional information

    """
    meta, conn = db

    with conn.begin():
        add = meta.tables[__table_proxychains].insert()
        conn.execute(add, pcid=pcid, description=description)
        conn.execute("commit")

def del_proxychain(db, pcid):
    """ delete proxy to proxy table """
    meta, conn = db
    tbl = meta.tables[__table_proxychains]

    with conn.begin():
        delete = tbl.update().where(tbl.c.pcid==pcid).values(deleted=True)
        conn.execute(delete)
        conn.execute("commit")

def get_chain_by_id(db, pcid):
    """ return a chain """
    meta, conn = db
    tbl_pc = meta.tables[__table_proxychains]

    with conn.begin():
        sel = sql.select([tbl_pc.c.pcid,
                          tbl_pc.c.description,
                        ]).\
                where(sql.and_(tbl_pc.c.deleted==False,
                               tbl_pc.c.pcid==pcid))
        entry = conn.execute(sel).fetchone()

    return entry

def get_all_chains(db):
    """ return a list of all chains, joined with the proxies """
    logger.debug("loading chains from database..")
    meta, conn = db
    tbl_px2pc = meta.tables[__table_proxy2chain]
    tbl_pc = meta.tables[__table_proxychains]
    res = {}

    with conn.begin():
        # first get all chains
        sel = sql.select([tbl_pc.c.pcid,
                          tbl_pc.c.description,
                          tbl_px2pc.c.pxid,
                          tbl_px2pc.c.deleted
                        ]).\
                where(tbl_pc.c.deleted==False).\
                select_from(
                    tbl_pc.outerjoin(tbl_px2pc)
                ).order_by(
                    tbl_px2pc.c.order
                )
        entries = conn.execute(sel).fetchall()

    # this is a concat_ws replacement. the entries that are returned
    # by the query look like <pcid>, <description>, <pxid>. the bad is,
    # that for every proxy assigned to the chain, the first to columns
    # become redundant. as a consequence, we build an easy dictionary
    # containing the pcid and description and a list of proxies
    for entry in entries:
        pcid = entry[0]

        try:
            # if chain already in dict, we just append the pxid to
            # the chain
            chain = res[pcid][1]
        except KeyError:
            # otherwise the add the proxy chain to dict and add the
            # proxy to the chain
            description = entry[1]
            chain = []
            res[pcid] = (description, chain)

        # add if pxid and association not deleted
        if entry[2] and not entry[3]:
            chain.append(entry[2])

    return res


def createProxy2ChainTable(meta):
    """ Create proxies table and return table object """
    logger.debug("creating table %s", __table_proxy2chain)
    tbl_px = meta.tables[__table_proxies]
    tbl_pc = meta.tables[__table_proxychains]

    tbl = sql.Table(__table_proxy2chain, meta,
        sql.Column("order", sql.Integer, primary_key=True, autoincrement=True),
        sql.Column("pcid", sql.String,
                           sql.ForeignKey(tbl_pc.c.pcid, ondelete="SET NULL"),
                           nullable=True),
        sql.Column("pxid", sql.Integer,
                           sql.ForeignKey(tbl_px.c.pxid, ondelete="SET NULL"),
                           nullable=True),
        sql.Column("deleted", sql.Boolean, default=False),
        #extend_existing=True
        )

    sql.Index("proxy2chain_unique", tbl.c.pxid, tbl.c.pcid,
               unique=True, postgresql_where=tbl.c.deleted==False)

    return tbl

def add_proxy_to_proxychain(db, pcid, pxid):
    """
    add a poxy to a proxy chain.

    input:
        db      database connection foo
        pcid    proxy chain id to add the proxy to
        pxid   proxy id of the proxy to add

    """

    check_nraise_pcid(db, pcid)
    check_nraise_pxid(db, pxid)

    meta, conn = db

    tbl = meta.tables[__table_proxy2chain]

    with conn.begin():
        ins = tbl.insert()
        try:
            conn.execute(ins, pcid=pcid, pxid=pxid)
        except sql.exc.IntegrityError as ie:
            if "violates foreign key constraint" in str(ie):
                raise InvalidQuery()
            elif "violates unique constraint" in str(ie):
                raise AlreadyExistingError()
            else:
                raise ie

        conn.execute("commit")

def del_proxy_from_proxychain(db, pcid, pxid):
    """
    remove poxy from proxy chain.

    input:
        db      database connection foo
        pcid    proxy chain id to add the proxy to
        pxid   proxy id of the proxy to add

    """
    meta, conn = db
    tbl = meta.tables[__table_proxy2chain]

    with conn.begin():
        delete = tbl.update().where(
                    sql.and_(tbl.c.pxid==pxid,
                             tbl.c.pcid==pcid,
                             tbl.c.deleted==False)).values(deleted=True)
        conn.execute(delete)
        conn.execute("commit")

def get_proxies_of_chain(db, pcid):
    """ return a list of all proxies associated with a chain """
    meta, conn = db
    tbl = meta.tables[__table_proxy2chain]

    with conn.begin():
        sel = sql.select([tbl.c.pxid]).\
                  where(
                    sql.and_(
                        tbl.c.pcid == pcid,
                        tbl.c.deleted == False
                    ))
        res = conn.execute(sel).fetchall()

    return res

###############################################################################
#                        connection groups
###############################################################################

def createConnectionGroupTable(meta):
    """ Create connection group table and return table object """
    logger.debug("creating table %s", __table_conngroup)

    tbl = sql.Table(__table_conngroup, meta,
        sql.Column("grpid", sql.String, primary_key=True, autoincrement=True),
        sql.Column("description", sql.String, nullable=True),
        sql.Column("created", sql.DateTime, default=sql.func.now()),
        sql.Column("deleted", sql.Boolean, default=False),
        sql.Column("default", sql.Boolean, default=False),
        #extend_existing=True
        )

    sql.Index("unique_default_group", tbl.c.default,
               unique=True,
               postgresql_where=sql.and_(tbl.c.deleted==False,
                                         tbl.c.default==True))

    return tbl

def check_grpid(db, grpid):
    meta, conn = db
    res = []
    with conn.begin():
        tbl = meta.tables[__table_conngroup]
        sel = sql.select([tbl.c.grpid]).where(tbl.c.grpid==grpid)
        res = conn.execute(sel).fetchall()
    return res

def check_nraise_grpid(db, grpid):
    if not check_grpid(db, grpid):
        raise NotFoundError("No such connection group id: '%s'" % grpid)


def add_connection_group(db, grpid,description):
    """ add a new connection group to table """
    meta, conn = db

    with conn.begin():
        add = meta.tables[__table_conngroup].insert()
        conn.execute(add, grpid=grpid, description=description)
        conn.execute("commit")

def del_connection_group(db, grpid):
    """ delete connection group """
    meta, conn = db
    tbl = meta.tables[__table_conngroup]

    with conn.begin():
        delete = tbl.update().where(tbl.c.grpid==grpid).values(deleted=True)
        conn.execute(delete)
        conn.execute("commit")

def get_group_by_id(db, grpid):
    """ return a group """
    meta, conn = db
    tbl = meta.tables[__table_conngroup]

    with conn.begin():
        sel = sql.select([tbl.c.grpid,
                          tbl.c.description,
                          tbl.c.default
                        ]).\
                where(sql.and_(tbl.c.deleted==False,
                               tbl.c.grpid==grpid))
        entry = conn.execute(sel).fetchone()

    return entry

def createChain2GroupTable(meta):
    """ Create proxies table and return table object """
    logger.debug("creating table %s", __table_chain2group)
    tbl_pc = meta.tables[__table_proxychains]
    tbl_grp = meta.tables[__table_conngroup]

    tbl = sql.Table(__table_chain2group, meta,
        sql.Column("pcid", sql.String,
                           sql.ForeignKey(tbl_pc.c.pcid, ondelete="SET NULL"),
                           nullable=True),
        sql.Column("grpid", sql.String,
                           sql.ForeignKey(tbl_grp.c.grpid, ondelete="SET NULL"),
                           nullable=True),
        sql.Column("priority", sql.Integer),
        sql.Column("deleted", sql.Boolean, default=False),
        #extend_existing=True
        )

    sql.Index("chain2proxy_unique", tbl.c.pcid, tbl.c.grpid,
               unique=True, postgresql_where=tbl.c.deleted==False)

    return tbl

def add_chain_to_group(db, grpid, pcid, prio):
    """
    add a proxy chain to a connection group.

    input:
        db      database connection foo
        pcid    proxy chain id to add
        grpid   id of the connection group to add to
        prio    priority that is assigned to the chain

    """

    check_nraise_grpid(db, grpid)
    check_nraise_pcid(db, pcid)

    meta, conn = db
    tbl = meta.tables[__table_chain2group]

    with conn.begin():
        ins = tbl.insert()
        try:
            conn.execute(ins, pcid=pcid, grpid=grpid, priority=prio)
        except sql.exc.IntegrityError as ie:
            if "violates foreign key constraint" in str(ie):
                raise InvalidQuery()
            elif "violates unique constraint" in str(ie):
                raise AlreadyExistingError()
            else:
                raise ie

        conn.execute("commit")

def del_chain_from_group(db, grpid, pcid):
    """
    remove chain from connection group.

    input:
        db      database connection foo
        pcid    proxy chain id to add
        grpid   id of the connection group to add to

    """
    meta, conn = db
    tbl = meta.tables[__table_chain2group]

    with conn.begin():
        delete = tbl.update().where(
                    sql.and_(tbl.c.grpid==grpid,
                             tbl.c.pcid==pcid,
                             tbl.c.deleted==False)).values(deleted=True)
        conn.execute(delete)
        conn.execute("commit")

def get_chains_of_group(db, grpid):
    """ return a list of all chains associated with a group """
    meta, conn = db
    tbl = meta.tables[__table_chain2group]

    with conn.begin():
        sel = sql.select([tbl.c.pcid]).\
                  where(
                    sql.and_(
                        tbl.c.grpid == grpid,
                        tbl.c.deleted == False,
                    ))
        res = conn.execute(sel).fetchall()

    return res


def set_default_conngroup(db, grpid):
    """
    set default flag of connection group.

    input:
        db      database connection foo
        pcid    proxy chain id to add
        grpid   id of the connection group

    """
    meta, conn = db
    tbl = meta.tables[__table_conngroup]

    with conn.begin():
        # unset old default group
        old = tbl.update().where(
                    sql.and_(tbl.c.default==True,
                             tbl.c.deleted==False)).values(default=False)
        conn.execute(old)

        # set new default group
        new = tbl.update().where(
                    sql.and_(tbl.c.grpid==grpid,
                             tbl.c.deleted==False)).values(default=True)
        conn.execute(new)
        conn.execute("commit")

def get_default_conngroup(db):
    """
    get connection group with default flag set

    input:
        db      database connection foo

    """
    meta, conn = db
    tbl = meta.tables[__table_conngroup]

    with conn.begin():
        sel = sql.select([tbl.c.grpid]).where(
                    sql.and_(tbl.c.default==True,
                             tbl.c.deleted==False))
        res = conn.execute(sel).fetchone()
        if res:
            res = res[0]

    return res


def get_all_conngroups(db):
    """ return a list of all groups, joined with the chains """
    meta, conn = db
    tbl_pc2grp = meta.tables[__table_chain2group]
    tbl_grp = meta.tables[__table_conngroup]
    res = {}

    with conn.begin():
        # first get all congroups
        sel = sql.select([tbl_grp.c.grpid,
                          tbl_grp.c.description,
                          tbl_grp.c.default,
                          tbl_pc2grp.c.pcid,
                          tbl_pc2grp.c.deleted,
                          tbl_pc2grp.c.priority
                        ]).\
                where(tbl_grp.c.deleted==False).\
                select_from(
                    tbl_grp.outerjoin(tbl_pc2grp)
                ).order_by(
                    tbl_pc2grp.c.priority
                )
        entries = conn.execute(sel).fetchall()

        res = __concat_ws(entries)

    return res

def __concat_ws(entries):
    """
    this is a concat_ws replacement. the entries that are returned
    by the query look like <grpid>, <description>, <pcid>. the bad is,
    that for every chain assigned to the group, the first to columns
    become redundant. as a consequence, we build an easy dictionary
    containing the grpid and description and a list of chains

    """
    res = {}

    for entry in entries:
        grpid = entry[0]

        try:
            # if group already in dict, we just append the pcid to
            # the group
            group = res[grpid][1]
        except KeyError:
            # otherwise the add the conn group to dict and add the
            # chain to the group
            description = entry[1]
#            default = entry[2]
            group = []
            prio = entry[5]
            res[grpid] = (description, group, prio)

        # add if pxid and association not deleted
        logger.debug("entry:%s", entry)
        if entry[3] and not entry[4]:
            group.append(entry[3])

    return res


def createGroup2Project2PluginTable(meta):
    """ Create table and return table object """
    logger.debug("creating table %s", __table_group2project2plugin)
    tbl_grp = meta.tables[__table_conngroup]
    tbl_pro = meta.tables[__table_projects]
    tbl_plg = meta.tables[__table_plugins]

    tbl = sql.Table(__table_group2project2plugin, meta,
        sql.Column("plg_id", sql.String,
                            sql.ForeignKey(tbl_plg.c.plg_id,
                                           ondelete="SET NULL"),
                            nullable=True),

        sql.Column("pid", sql.Integer,
                           sql.ForeignKey(tbl_pro.c.pid,
                                          ondelete="SET NULL"),
                           nullable=True),

        sql.Column("grpid", sql.String,
                           sql.ForeignKey(tbl_grp.c.grpid,
                                          ondelete="SET NULL"),
                           nullable=True),

        sql.Column("deleted", sql.Boolean, default=False),
        #extend_existing=True
        )

    sql.Index("group2project2plugin_unique",
                tbl.c.plg_id, tbl.c.pid,
                unique=True, postgresql_where=tbl.c.deleted==False)

    return tbl

def get_group_by_projectplugin(db, plg_id, pid):
    """ returns the group id associated with the plugin-proj combination """
    meta, conn = db
    tbl = meta.tables[__table_group2project2plugin]
    res = None

    with conn.begin():
        sel = sql.select([tbl.c.grpid]).where(
                                    sql.and_(tbl.c.deleted==False,
                                            tbl.c.plg_id==plg_id,
                                            tbl.c.pid==pid)
                                    )
        entry = conn.execute(sel).fetchone()
        if entry:
            res = entry[0]

    return res

def add_group_to_projectplugin(db, grpid, plg_id, pid):
    """
    add a connection group to a project/plugin

    input:
        db      database connection foo
        grpid   group to add
        plg_id  id of the plugin
        pid   id of the project

    """

    check_nraise_grpid(db, grpid)
    check_nraise_plg_id(db, plg_id)
    check_nraise_pid(db, pid)

    meta, conn = db
    tbl = meta.tables[__table_group2project2plugin]

    with conn.begin():
        ins = tbl.insert()
        try:
            conn.execute(ins, plg_id=plg_id, grpid=grpid, pid=pid)
        except sql.exc.IntegrityError as ie:
            if "violates foreign key constraint" in str(ie):
                raise InvalidQuery("Invalid Group-Project-Plugin insert query!")
            elif "violates unique constraint" in str(ie):
                raise AlreadyExistingError("Group-Project-Plugin combination "
                                           "already in database")
            else:
                raise ie

        conn.execute("commit")

def del_group_from_projectplugin(db, plg_id, pid):
    """
    delete a connection group from a project/plugin

    input:
        db      database connection foo
        plg_id  id of the plugin
        pid   id of the project

    """
    meta, conn = db
    tbl = meta.tables[__table_group2project2plugin]

    with conn.begin():
        delete = tbl.update().where(
                    sql.and_(tbl.c.pid==pid,
                             tbl.c.plg_id==plg_id,
                             tbl.c.deleted==False)).values(deleted=True)
        conn.execute(delete)
        conn.execute("commit")

def get_group_by_plugin_project(db, plg_id, pid):
    """
    get connection group given a plugin and a project id

    input:
        db      database connection foo
        plg_id  plugin id
        pid     project id

    """
    meta, conn = db
    tbl = meta.tables[__table_group2project2plugin]
    res = None

    with conn.begin():
        # first get all congroups
        sel = sql.select([tbl.c.grpid]).where(
                        sql.and_(tbl.c.deleted==False,
                                 tbl.c.plg_id==plg_id,
                                 tbl.c.pid==pid))
        entry = conn.execute(sel).fetchone()
        if entry:
            res = entry[0]
    return res


###############################################################################
#                           workgroups
###############################################################################

def add_user2workgroup(db, uid, wid, rid):
    """ Add new user workgroup relation."""

    check_nraise_uid(db, uid)
    check_nraise_wid(db, wid)

    meta, conn = db

    try:
        with conn.begin():
            entry = meta.tables[__table_user2workgroup].insert()
            conn.execute(entry, uid=uid, wid=wid, rid=rid)
            conn.execute("commit")

    except sql.exc.IntegrityError as e:
        logger.error("Failed to store user2workgroup:'%s'", str(e))
        if "u2w_unique" in str(e):
            raise AlreadyExistingError("Relation already in database!")
        else:
            raise e

def delete_user2workgroup(db, uid, wid):
    """ sets the delete flag """
    logger.debug("removing user '%s' from '%s'.", uid, wid)
    meta, conn = db

    tbl = meta.tables[__table_user2workgroup]

    with conn.begin():
        stmt = tbl.update().\
                where(sql.and_(tbl.c.uid==uid,
                               tbl.c.wid==wid,
                               tbl.c.deleted==False)).\
                values(deleted=True)
        conn.execute(stmt)
        conn.execute("commit")

def createUser2WorkgroupTable(meta):
    """ Create user2workgroup table and return table object """
    logger.debug("creating table %s", __table_user2workgroup)

    tbl = sql.Table(__table_user2workgroup, meta,
        sql.Column("uid", sql.Integer, sql.ForeignKey("users.uid"),
                   nullable=False),
        sql.Column("wid", sql.Integer, sql.ForeignKey("workgroups.wid"),
                   nullable=False),
        sql.Column("rid", sql.Integer, sql.ForeignKey("roles.rid"),
                   nullable=False),
        sql.Column("deleted", sql.Boolean, default=False),
        #extend_existing=True

    )

    sql.Index("u2w_unique", tbl.c.uid, tbl.c.wid,
              postgresql_where=tbl.c.deleted==False, unique=True)

    return tbl

def createWorkgroupTable(meta):
    """ Create workgroup table and return table object """
    logger.debug("creating table %s", __table_workgroup)

    tbl = sql.Table(__table_workgroup, meta,
        sql.Column("wid", sql.Integer, primary_key=True, autoincrement=True),
        sql.Column("name", sql.String(MAX_LEN_NAME), nullable=False),
        sql.Column("created", sql.DateTime, default=sql.func.now()),
        sql.Column("deleted", sql.Boolean, default=False),
        sql.Column("pseudo", sql.Boolean, default=False),
        sql.Column("description", sql.String(MAX_LEN_DESC), nullable=False),
        )

    sql.Index("unique_workgroup", tbl.c.name,
              postgresql_where=tbl.c.deleted==False, unique=True)

    return tbl

def check_wid(db, wid):
    meta, conn = db
    res = []
    with conn.begin():
        tbl = meta.tables[__table_workgroup]
        sel = sql.select([tbl.c.wid]).where(tbl.c.wid==wid)
        res = conn.execute(sel).fetchall()
    return res

def check_nraise_wid(db, wid):
    if not check_wid(db, wid):
        raise NotFoundError("No such workgroup id: '%s'" % wid)


def create_workgroup(db, name, pseudo=False, description=''):
    """
    create a workgroup entry. return project id

    input:
        pseudo  set a wgroup as pseudo group

    """
    meta, conn = db
    tbl = meta.tables[__table_workgroup]

    try:
        ins = tbl.insert()
        args = dict(name=name, description=description)

        if pseudo:
            args["pseudo"] = True

        with conn.begin():
            res = conn.execute(ins, **args)
            sel = tbl.select()
            wid = res.inserted_primary_key[0]
            res = conn.execute(sel,
                               id=res.inserted_primary_key[0]).fetchone()
            conn.execute("commit")

    except sql.exc.IntegrityError as e:
        if "unique_workgroup" in str(e):
            raise AlreadyExistingError("Workgroup '%s' already in database!" %
                                        name)
        else:
            raise e

    created = res[2]

    return wid, created

def delete_workgroup(db, wid):
    meta, conn = db
    tbl = meta.tables[__table_workgroup]

    with conn.begin():
        stmt = tbl.update().\
                where(tbl.c.wid==wid).\
                values(deleted=True)
        conn.execute(stmt)
        conn.execute("commit")

def get_all_workgroups(db):
    """ return all existing non-deleted workgroups """
    meta, conn = db
    tbl = meta.tables[__table_workgroup]

    with conn.begin():
        sel = tbl.select().where(tbl.c.deleted==False)
        wgroups = conn.execute(sel).fetchall()

    return wgroups

def get_workgroup_plugins(db, wid):
    """ returns a list of plg_ids that are part of workgroup """
    meta, conn = db
    tbl = meta.tables[__table_workgroup2plugin]

    with conn.begin():
        sel = sql.select([tbl.c.plg_id]).where(
            sql.and_(tbl.c.wid==wid, tbl.c.deleted==False)
        )
        entries = conn.execute(sel).fetchall()

    plg_ids = [p[0] for p in entries]
    return plg_ids


def getworkgroup_byname(db, name):
    """ return entry for workgroup with the given name that is not deleted """
    meta, conn = db
    tbl = meta.tables[__table_workgroup]

    with conn.begin():
        select = tbl.select().where(
            sql.and_(tbl.c.name==name, tbl.c.deleted==False)
            )
        workgroup = conn.execute(select).fetchone()

    return workgroup

def getworkgroup_bywid(db, wid):
    """ return entry for workgroup for the given wid that is not deleted """
    meta, conn = db
    tbl = meta.tables[__table_workgroup]

    with conn.begin():
        select = tbl.select().where(
            sql.and_(tbl.c.wid==wid, tbl.c.deleted==False)
            )
        workgroup = conn.execute(select).fetchone()

    return workgroup


def _get_permissions(*args):
    """ gets the permission matrix from database and builds
        the byte representation to return
    """
    permissions = 0

    if args[0]:
        permissions |= ACCESS_READ

    if args[1]:
        permissions |= ACCESS_WRITE

    if args[2]:
        permissions |= ACCESS_ADD

    if args[3]:
        permissions |= ACCESS_DEL

    if args[4]:
        permissions |= ACCESS_EXEC


    return permissions

def get_workgroup_access(db, wid, uid):
    """ returns a user's access matrix """
    meta, conn = db
    tbl_w = meta.tables[__table_user2workgroup]
    tbl_r = meta.tables[__table_role]

    with conn.begin():
        select = sql.select([
            "roles.read",
            "roles.write",
            "roles.add",
            "roles.write",
            "roles.execute"
            ],
            sql.and_(
                tbl_w.c.wid == wid,
                tbl_w.c.uid == uid,
                tbl_w.c.deleted == False
                )
           ).\
           select_from(
                tbl_w.join(tbl_r)
           )

        matrix = conn.execute(select).fetchone()

    if matrix:
        permissions = _get_permissions(*matrix)
    else:
        permissions = 0
    return permissions

def get_workgroup_members(db, wid):
    """ return a list of a project's members """
    meta, conn = db
    tbl = meta.tables[__table_user2workgroup]
    tbl_u = meta.tables[__table_users]

    with conn.begin():
        sel = sql.select([tbl_u.c.uid,
                      tbl_u.c.name,
                      tbl_u.c.mail,
                      tbl_u.c.created,
                      tbl.c.rid
                     ]).where(
                        sql.and_(
                            tbl.c.wid==wid,
                            tbl.c.deleted==False,
                            tbl_u.c.deleted==False
                            )
                    ).select_from(
                        tbl_u.join(tbl)
                    )

        entries = conn.execute(sel).fetchall()

    return entries

def getworkgroup_byuid(db, uid):
    """ return workgroup that is associated with a user given by uid """
    meta, conn = db
    tbl_u2w = meta.tables[__table_user2workgroup]
    tbl_w = meta.tables[__table_workgroup]

    with conn.begin():
        try:
            select = sql.select([tbl_w.c.wid]).where(
                      sql.and_(tbl_u2w.c.uid==uid,
                               tbl_u2w.c.deleted==False)
                       ).select_from(
                                tbl_u2w.join(tbl_w)
                        )
            wg = conn.execute(select).fetchone()

        except Exception as e:
            logger.error("Error while getting workgroup:%s", e)
            raise

    logger.debug("wg:%s",wg)
    return wg

def update_workgroup_description(db, wid, description):
    meta, conn = db
    tbl = meta.tables[__table_workgroup]
    try:

        with conn.begin():
            stmt = tbl.update().\
                where(sql.and_(tbl.c.wid == wid)).\
                values(description=description)
            conn.execute(stmt)
            conn.execute("commit")

    except sql.exc.IntegrityError as e:
        logger.error("Failed to update workgroup %d:'%s'.", wid, str(e))
        raise Exception("Failed to update workgroup %d. ", wid)


def update_workgroup(db, wid, name, description):
    meta, conn = db
    tbl = meta.tables[__table_workgroup]
    try:
        with conn.begin():
            stmt = tbl.update().\
                where(sql.and_(tbl.c.wid==wid)).\
                values(name=name, description=description)
            conn.execute(stmt)
            conn.execute("commit")

    except sql.exc.IntegrityError as e:
        logger.error("Failed to update workgroup %s:'%s'.", name, str(e))
        raise AlreadyExistingError("Failed to update workgroup. "
                                   " A workgroup '%s' already exists.",
                                   name)


###############################################
#             role stuff
###############################################
def createRoleTable(meta):
    """ Create role table and return table object """
    logger.debug("creating table %s", __table_role)

    role = sql.Table(__table_role, meta,
        sql.Column("rid", sql.Integer, primary_key=True, autoincrement=True),
        sql.Column("name", sql.String, nullable=False, unique=True),
        sql.Column("read", sql.Boolean, nullable=False, default=False),
        sql.Column("write", sql.Boolean, nullable=False, default=False),
        sql.Column("add", sql.Boolean, nullable=False, default=False),
        sql.Column("execute", sql.Boolean, nullable=False, default=False),
        sql.Column("delete", sql.Boolean, nullable=False, default=False),
        sql.Column("created", sql.DateTime, default=sql.func.now()),
        #extend_existing=True
    )
    return role

def create_role(db, name, acl):
    """ create a new role in database """
    rid = -1
    read = acl[0]
    write = acl[1]
    add = acl[2]
    delete = acl[3]
    execute = acl[4]

    meta, conn = db

    tbl = meta.tables[__table_role]

    try:
        with conn.begin():
            entry = tbl.insert()
            res = conn.execute(entry, name=name,
                           read=read,
                           write=write,
                           add=add,
                           delete=delete,
                           execute=execute
                   )
            rid = res.inserted_primary_key[0]
            conn.execute("commit")

    except (sql.exc.IntegrityError, sql.exc.ProgrammingError) as e:
        if "roles_name_key" in str(e):
            raise AlreadyExistingError("Role '%s' already in database!" % name)
        else:
            logger.error("Failed to store role '%s':'%s'", name, str(e))
            raise e

    return rid

def getrole_byname(db, name):
    """ select role by name """
    meta, conn = db

    tbl = meta.tables[__table_role]
    with conn.begin():
        select = tbl.select().where(tbl.c.name==name)
        role = conn.execute(select).fetchone()

    return role

###############################################
#             user stuff
###############################################

def add_user2user(db, uid, rid):
    """ Add new user user relation."""
    check_nraise_uid(db, uid)

    meta, conn = db

    with conn.begin():
        entry = meta.tables[__table_user2user].insert()
        conn.execute(entry, uid=uid, rid=rid)
        conn.execute("commit")

def del_user2user(db, uid):
    """ Delete user user relation."""
    meta, conn = db
    tbl = meta.tables[__table_user2user]
    with conn.begin():
        stmt = tbl.update().\
                where(sql.and_(
                    tbl.c.uid==uid,
                    tbl.c.deleted==False
                    )).\
                values(deleted=True)
        conn.execute(stmt)
        conn.execute("commit")

def createUser2UserTable(meta):
    """ Create user2user table and return table object """
    logger.debug("creating table %s", __table_user2user)

    tbl = sql.Table(__table_user2user, meta,
                    sql.Column("uid",
                               sql.Integer,
                               sql.ForeignKey("users.uid"),
                               nullable=False),
                    sql.Column("rid",
                               sql.Integer,
                               sql.ForeignKey("roles.rid"),
                               nullable=False),
                    sql.Column("deleted",
                               sql.Boolean,
                               default=False),
                    )

    sql.Index("unique_user2users", tbl.c.uid,
                                   postgresql_where=tbl.c.deleted==False,
                                   unique=True)

    return tbl

def createUserTable(meta):
    """ Create user table. Return table object."""
    logger.debug("creating table %s", __table_users)
    tbl = sql.Table(__table_users, meta,
        sql.Column("uid", sql.Integer, primary_key=True, autoincrement=True),
        sql.Column("name", sql.String(MAX_LEN_NAME), nullable=False,
                           index=True),
        sql.Column("mail", sql.String(MAX_LEN_MAIL)),
        sql.Column("created", sql.DateTime, default=sql.func.now()),
        sql.Column("deleted", sql.Boolean, default=False),
        sql.Column("description", sql.String(MAX_LEN_DESC), nullable=True),
        #extend_existing=True
    )

    sql.Index("unique_users", tbl.c.name,
                              postgresql_where=tbl.c.deleted==False,
                              unique=True)

    return tbl

def check_uid(db, uid):
    meta, conn = db
    res = []
    with conn.begin():
        tbl = meta.tables[__table_users]
        sel = sql.select([tbl.c.uid]).where(tbl.c.uid==uid)
        res = conn.execute(sel).fetchall()
    return res

def check_nraise_uid(db, uid):
    if not check_uid(db, uid):
        raise NotFoundError("No such user id: '%s'" % uid)


def createPasswdTable(meta):
    """ Create Table that contains users' password """
    pwds = sql.Table(__table_passwd, meta,
        sql.Column("uid", sql.Integer, sql.ForeignKey("users.uid"),
                                                       nullable=False),
        sql.Column("password", sql.String(MAX_LEN_PASSWORD), nullable=False),
        #extend_existing=True
    )
    return pwds

def getusers(db, username, pwd):
    """
    Return a list of users given by 'username' and
    corresponding password.

    input:
        db          tuple containing db meta and db connection
        username    username to look for
        pwd         password of the user

    output:
        users       users that have this username/password. this should be
                    a list of length one

    """
    meta, conn = db

    tbl_u = meta.tables[__table_users]
    tbl_p = meta.tables[__table_passwd]

    with conn.begin():
        statement = sql.select([tbl_u],
           sql.and_(
                tbl_u.c.name == username,
                tbl_p.c.password == pwd,
                tbl_u.c.deleted == False
                )
           ).\
           select_from(
                tbl_u.join(tbl_p)
           )
        try:
            users = conn.execute(statement).fetchall()
        except Exception as e:
            logger.error("Failed to get user in db:'%s'", e)
            raise e

    return users

def get_all_users(db):
    """
    return all existing non-deleted users

    input:
        db  tuple containing db meta and db connection

    output:
        users   a list of all users

    """
    meta, conn = db
    tbl = meta.tables[__table_users]
    with conn.begin():
        sel = tbl.select().where(tbl.c.deleted==False)
        users = conn.execute(sel).fetchall()

    return users

def getuser_byname(db, name):
    """ returns user entry for a given user name """
    meta, conn = db
    tbl = meta.tables[__table_users]

    with conn.begin():
        select = tbl.select().where(tbl.c.name==name)
        res = conn.execute(select).fetchone()

    return res

def getuser_byuid(db, uid):
    """
    returns user entry for a given user id

    input:
        db  tuple containing db meta and db connection
        uid user id of the user to look for

    output:
        res the database entry of the found user

    """
    meta, conn = db
    tbl = meta.tables[__table_users]

    with conn.begin():
        select = tbl.select().where(
            sql.and_(tbl.c.uid==uid, tbl.c.deleted==False)
        )
        res = conn.execute(select).fetchone()

    return res

def create_user(db, user, pwd, mail="", description=""):
    """ creates a user if not already existing"""
    meta, conn = db
    uid = ""

    try:
        with conn.begin():
            user_ins = meta.tables[__table_users].insert()
            user_res = conn.execute(user_ins,
                                       name=user,
                                       mail=mail,
                                       description=description)
            uid = user_res.inserted_primary_key[0]

            user_sel = meta.tables[__table_users].select()
            user_res = conn.execute(user_sel,
                                   uid=uid).fetchone()
            created = user_res[2]

            # create passwd entry
            passwd_ins = meta.tables[__table_passwd].insert()
            conn.execute(passwd_ins, uid=uid, password=pwd)
            conn.execute("commit")

    except sql.exc.IntegrityError as e:
        if "unique_users" in str(e):
            raise AlreadyExistingError("User '%s' already in database!" %
                                           user)
        else:
            logger.error("Failed to create user '%s':'%s'", user, e)
            raise e

    return uid, created

def update_user_password(db, uid, old_pwd, new_pwd):
    """
    update a user's password. verifies that user and password combination
    matches. if no user is found with the given uid-old_pwd combination, throws
    a InputError.

    input:
        db      tuple containing db meta and db connection
        uid     user id of user to change password
        old_pwd old password
        new_pwd password to set

    """
    meta, conn = db

    tbl_p = meta.tables[__table_passwd]
    tbl_u = meta.tables[__table_users]

    # check for the user not to be deleted
    with conn.begin():
        sel_user = tbl_u.select().where(
                        sql.and_(
                            tbl_u.c.uid==uid,
                            tbl_u.c.deleted==False,
                            tbl_p.c.password==old_pwd
                            )
                    ).select_from(
                       tbl_p.join(tbl_u)
                    )
        users = conn.execute(sel_user).fetchone()

        logger.debug("found:%s", users)
        if not users:
            raise InputError("User or password wrong!")

        # update password
        passwd_upd = tbl_p.update().where(
                            sql.and_(
                                tbl_p.c.uid==uid,
                                tbl_p.c.password==old_pwd
                            )
                      ).values(password=new_pwd)
        conn.execute(passwd_upd)
        conn.execute("commit")


def delete_user(db, uid):
    """
    delete a user

    input:
        db      tuple containing db meta and db connection
        uid     user id of the user to delete

    """
    meta, conn = db
    tbl = meta.tables[__table_users]

    with conn.begin():
        stmt = tbl.update().\
                where(sql.and_(
                    tbl.c.uid==uid,
                    tbl.c.deleted==False
                    )).\
                values(deleted=True)
        conn.execute(stmt)
        conn.execute("commit")


def update_user_description(db, uid, description):
    meta, conn = db
    tbl = meta.tables[__table_users]

    with conn.begin():
        stmt = tbl.update().\
            where(
                sql.and_(
                    tbl.c.uid == uid,
                    tbl.c.deleted == False
                )
            ).\
            values(description=description)
        conn.execute(stmt)
        conn.execute("commit")


def update_user(db, uid, name, mail, description):
    """
    updates a user's name and mail information

    input:
        db      tuple containing db meta and db connection
        uid     user to change information of
        name    new name to set
        mail    new mail to set
        description description to set

    """
    meta, conn = db

    tbl = meta.tables[__table_users]

    try:
        with conn.begin():
            stmt = tbl.update().\
                    where(
                         sql.and_(
                            tbl.c.uid==uid,
                            tbl.c.deleted==False
                            )
                    ).\
                    values(name=name, mail=mail, description=description)
            conn.execute(stmt)
            conn.execute("commit")

    except sql.exc.IntegrityError as e:
        logger.error("Failed to update user")
        if "unique_users" in str(e):
            raise AlreadyExistingError("User already in db!")
        else:
            raise e


def getuser_bywid(db, wid):
    """ return user that is associated with a workgroup given by wid"""
    meta, conn = db
    tbl_u2w = meta.tables[__table_user2workgroup]
    tbl_u = meta.tables[__table_users]

    with conn.begin():
        select = sql.select([tbl_u.c.name, tbl_u2w.c.rid]).where(
                  sql.and_(tbl_u2w.c.wid==wid, tbl_u2w.c.deleted==False)
             ).select_from(
                tbl_u2w.join(tbl_u)
             )
        users = conn.execute(select).fetchall()

    return users

def get_user_access(db, uid):
    """ returns a user's access matrix """
    meta, conn = db
    tbl = meta.tables[__table_user2user]
    tbl_r = meta.tables[__table_role]

    with conn.begin():
        select = sql.select([
            "roles.read",
            "roles.write",
            "roles.add",
            "roles.write",
            "roles.execute"
            ],
            sql.and_(
                tbl.c.uid == uid,
                tbl.c.deleted == False
                )
           ).\
           select_from(
                tbl.join(tbl_r)
           )

        matrix = conn.execute(select).fetchone()
    if matrix:
        permissions = _get_permissions(*matrix)
    else:
        permissions = 0
    return permissions

###############################################
#          task management
###############################################

def createTaskTable(meta):
    """ Create the table that contains project types. """
    logger.debug("creating table %s", __table_tasks)
    tbl = sql.Table(__table_tasks, meta,
        sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
        sql.Column("start", sql.DateTime),
        sql.Column("uid", sql.Integer, sql.ForeignKey("users.uid"),
                                                    nullable=False),
        sql.Column("pid", sql.Integer, sql.ForeignKey("projects.pid"),
                                                    nullable=False),
        #extend_existing=True

    )
    return tbl

def insert_task(db, start, uid, pid):
    """
    create a new task entry and return task id

    input:
        start   datetime the task should be executed at
        uid     user id that created the task
        pid     id of the project

    output :
        tid     task id

    """
    meta, conn = db
    tbl = meta.tables[__table_tasks]

    with conn.begin():
        ins = tbl.insert().values(
                start=start,
                uid=uid,
                pid=pid
            )
        res = conn.execute(ins)
        tid = res.inserted_primary_key[0]
        conn.execute("commit")

    return tid

###############################################
#          scan management
###############################################

def createScanTable(meta):
    """ Create the table that contains project types. """
    logger.debug("creating table %s", __table_scans)

    tbl_t = meta.tables[__table_tasks]
    tbl_plg = meta.tables[__table_plugins]

    tbl = sql.Table(__table_scans, meta,
        sql.Column("id", sql.Integer, primary_key=True, autoincrement=True),
        sql.Column("start", sql.DateTime),
        sql.Column("stop", sql.DateTime),
        sql.Column("tid",
                   sql.Integer,
                   sql.ForeignKey(tbl_t.c.id,
                                  ondelete="SET NULL"),
                   nullable=False),
        sql.Column("plg_id",
                   sql.String,
                   sql.ForeignKey(tbl_plg.c.plg_id,
                                  ondelete="SET NULL"),
                   nullable=True)
    )
    return tbl

def insert_scan(db, start, stop, tid, plg_id):
    """
    create a new scan entry and return scan id

    input:
        stop    datetime scan ended
        tid     task id that triggered the scan
        start   datetime the scan startet
        plg_id  plugin id

    """
    meta, conn = db
    tbl = meta.tables[__table_scans]

    with conn.begin():
        ins = tbl.insert().values(
                start=start,
                stop=stop,
                tid=tid,
                plg_id=plg_id
            )
        res = conn.execute(ins)
        conn.execute("commit")

    return res.inserted_primary_key[0]

###############################################
#          session management
###############################################

def createSessionTable(meta):
    """ Create session table. Return table object. """
    logger.debug("creating table %s", __table_sessions)
    sessions = sql.Table(__table_sessions, meta,
        sql.Column("sid", sql.String, nullable=False),
        sql.Column("uid",
                   sql.Integer,
                   sql.ForeignKey("users.uid"),
                   nullable=False),
        sql.Column("pid",
                   sql.Integer,
                   sql.ForeignKey("projects.pid",
                                  ondelete="SET NULL"),
                   nullable=True),
        sql.Column("created", sql.DateTime, default=sql.func.now()),

    )
#    sessions.create(checkfirst=True)
    return sessions

def store_session(db, sid, uid, pid=None):
    """
    Stores a session associated with a user.

    input:
        db  tuple containing db meta and db connection
        sid session id to store
        uid user that is associated with that session
        pid project id, that is associated with the session

    """
    meta, conn = db
    with conn.begin():
        statement = meta.tables[__table_sessions].insert().\
                                values(
                                       sid=sid,
                                       uid=uid,
                                       pid=pid
                                       )
        conn.execute(statement)
        conn.execute("commit")

def update_session(db, sid, pid):
    meta, conn = db
    tbl = meta.tables[__table_sessions]

    with conn.begin():
        upd = tbl.update().where(tbl.c.sid==sid).values(
                                pid=pid if pid else sql.sql.null()
                             )
        conn.execute(upd)
        conn.execute("commit")

def get_sessions(db):
    """
    returns a dictionary containing all sessions

    input:
        db  tuple containing db meta and db connection

    output:
        res return a list of all sessions

    """
    meta, conn = db

    with conn.begin():
        select = meta.tables[__table_sessions].select()
        res = conn.execute(select).fetchall()

    return res

def delete_session_by_uid(db, uid):
    """ get a user id and deletes the corresponding session """
    meta, conn = db

    with conn.begin():
        delete = meta.tables[__table_sessions].delete()
        conn.execute(delete, uid=uid)


###############################################
#              fd management
###############################################

def createFdTable(meta):
    """ create fd table to contain file descriptors to which a running
        plugin writes its stdout/reads its stdin
    """
    logger.debug("creating table %s", __table_fd)
    fd = sql.Table(__table_fd, meta,
        sql.Column("fid", sql.Integer, primary_key=True, autoincrement=True),
        sql.Column("command", sql.String),
        sql.Column("uid", sql.Integer, sql.ForeignKey("users.uid")),
        sql.Column("fd_in", sql.String),
        sql.Column("fd_out", sql.String),
        sql.Column("plg_id", sql.String, sql.ForeignKey("plugins.plg_id")),
        sql.Column("request_id", sql.String, unique=True),
        sql.Column("created", sql.DateTime, default=sql.func.now()),
        sql.Column("state", sql.Integer, nullable=True),
        sql.Column("process_id", sql.Integer, nullable=True),
        sql.Column("deleted", sql.Boolean, default=False),
        #extend_existing=True

    )
    return fd

def is_fd_interactive(db, plg_id):
    """ check whether plugin is interactive """
    meta, conn = db
    tbl = meta.tables[__table_plugins]

    with conn.begin():
        sel = sql.select([tbl.c.interactive]).where(
            sql.and_(tbl.c.plg_id==plg_id,
                     tbl.c.deleted==False)
            )
        res = conn.execute(sel).fetchone()

    logger.debug("interactive plugin:%s", res)
    try:
        if res[0] == True:
            return True
    except (KeyError, TypeError):
        pass

    return False

def getFdByUid(db, uid):
    """ Returns a list of fd entries for a given user id. """
    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        select = tbl.select().where(
                sql.and_(tbl.c.uid==uid,
                         tbl.c.deleted==False)
                )
        entries = conn.execute(select).fetchall()

    return entries

def getFdByRid(db, rid, uid):
    """ Returns a list of fd entries for a given user id. """
    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        select = tbl.select().where(
                        sql.and_(tbl.c.request_id==rid,
                                 tbl.c.uid==uid,
                                 tbl.c.deleted==False)
                        )
        entries = conn.execute(select).fetchone()

    return entries


def getFdByFid(db, fid, uid):
    """ Returns a list of fd entries for a given user id. """

    logger.info('Getting fd from database with fid: %s, uid: %s',
                fid, uid)

    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        select = tbl.select().where(
                        sql.and_(tbl.c.fid==fid,
                                 tbl.c.uid==uid,
                                 tbl.c.deleted==False)
                        )
        logger.info('%s', select)
        entries = conn.execute(select).fetchall()
        logger.info('%s --> %s', select, entries)

    return entries

def getFdByCommand(db, command, uid):
    """ Returns a list of fd entries for a given user id. """
    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        select = tbl.select().where(
                  sql.and_(
                    tbl.c.command==command,
                    tbl.c.uid==uid,
                    tbl.c.deleted==False)
                 )
        res = conn.execute(select)
        res = res.fetchone()

    logger.debug("res:%s", res)
    return res

def _sanitise_fd_state(db):
    """
    sets all states with value -1 to 9.

    this is usefull if the ccd is killed via SIGKILL and all plugins are killed
    too. if so, the ccd is not able to their state, which leads to
    inconsistencies since the states remain -1 although the plugin is not
    running anymore.

    """
    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        update = tbl.update().where(tbl.c.state=='-1').values(state='9')
        conn.execute(update)
        conn.execute("commit")
        update = tbl.update().where(tbl.c.state==None).values(state='9')
        conn.execute(update)
        conn.execute("commit")

def set_fd_state(db, fid, new_state):
    """
    set file descriptor/plugin state

    input:
        fid     id of the file descriptor table entry
        state   integer indicating the state

    """
    logger.debug("setting fd(%d) state:%s", fid, new_state)
    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        insert = tbl.update().where(
                    sql.and_(
                        tbl.c.deleted==False,
                        tbl.c.fid==fid
                    )
                ).values(state=new_state)
        conn.execute(insert)
        conn.execute("commit")

def get_fd_state(db, fid):
    """
    get file descriptor/plugin state

    input:
        fid     id of the file descriptor table entry

    """
    logger.debug('Getting fd status %d', fid)
    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        select = sql.select([tbl.c.state]).where(
                        tbl.c.fid==fid
                )
        conn.execute(select)
        res = conn.execute(select).fetchone()

    return res

def set_fd_state_by_rid(db, rid, new_state):
    """
    set file descriptor/plugin state given the request id

    input:
        rid         id of the request, that started the plugin
        state       integer indicating the state

    """
    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        insert = tbl.update().where(
                    sql.and_(
                        tbl.c.deleted==False,
                        tbl.c.request_id==rid
                    )
                ).values(state=new_state)
        conn.execute(insert)
        conn.execute("commit")


def get_fd_by_rid(db, request_id):
    """
    return the fd entry for a given request id

    input:
        request_id  id of the request, that started the plugin

    """
    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        select = tbl.select().where(
                    sql.and_(
                        tbl.c.deleted==False,
                        tbl.c.request_id==request_id
                    )
                )
        res = conn.execute(select).fetchall()

    return res

def set_fd_process_id(db, fid, pid):
    """
    set the file decriptor/plugin process id

    input:
        fid  id of the file descriptor table entry
        pid  process id associated with the running plugin

    """
    logger.debug("setting fd(%d) process id:%d", fid, pid)
    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        insert = tbl.update().where(
                    sql.and_(
                        tbl.c.deleted==False,
                        tbl.c.fid==fid
                    )
                ).values(process_id=pid)
        conn.execute(insert)
        conn.execute("commit")


def storeFd(db, fd_out, fd_in, uid, command, plg_id, request_id,
            state=-1, process_id=None):
    """ Stores a plugin's new file descriptor (aka stdin/stdout), the user that
        issued the plugin execution and the command that was triggered.

        insert:
            fd_out      file path to stdout descriptor to store
            fd_int      file path to stdin descriptor to store

            uid         user id of the owner
            command     command that executes the plugin which makes use of the
                        fd
            plg_id      plugin id of the plugin executed
            request_id  id of the request that issued the plugin
            status      an integer to indicate status (<0: running,
                        0: finished, >0: error, empty: not running)
            process_id  process id of the plugin process

    """
    logger.debug("storing fd for plugin %s", plg_id)
    meta, conn = db

    with conn.begin():
        statement = meta.tables[__table_fd].insert().values(
            fd_out=fd_out,
            fd_in=fd_in,
            uid=uid,
            command=command,
            plg_id=plg_id,
            request_id=request_id,
            process_id=process_id,
            state=state
        )
        res = conn.execute(statement)
        conn.execute("commit")

    return res.inserted_primary_key[0]

def removeFd(db, fid):
    """ removes a file descriptor from _fd table """
    logger.debug("deleting %s from database", fid)

    meta, conn = db
    tbl = meta.tables[__table_fd]

    with conn.begin():
        stmt = tbl.update().\
                where(sql.and_(
                    tbl.c.fid == fid,
                    tbl.c.deleted == False
                )).\
                values(deleted=True)
        conn.execute(stmt)
        conn.execute("commit")

class AlreadyExistingError(Exception):
    pass

class DatabaseError(Exception):
    pass

class InvalidQuery(Exception):
    pass


