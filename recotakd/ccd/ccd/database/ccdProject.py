""" project creation, deletion and manipulation """

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
from database.ccdErrors import PermissionDenied
from database.project import db as projectdb
from database.ccdErrors import NotFoundError
from files.upload import get_write_location
from database.ccdErrors import InputError
from database.ccddb import MAX_LEN_NAME
from database.ccddb import MAX_LEN_DESC
from files import CSV
from files import PDF
#from files import ODT
from genreport import pdf
#from genreport import cOdf
from connection import ccdlib
from plugins import plugin
from database import ccddb
import logging
import os

logger = logging.getLogger("ccd.%s" % __name__)
logger.setLevel(logging.DEBUG)

class Project(object):
    """
    A project can be seen as workspace for the user or a plugin. A user must join
    a project to actually execute plugins. The plugin's execution is associated
    with the project (e.g. each project has its own database). In order to be
    member of a project, the user needs to be either added to an existing
    project or he must create a new project. Before triggering plugin
    execution, the user must set the project, which means that he choses the
    corresponding plugin for working.

    Every project object has the following attributes:

        pid         project id, an integer, usually assigned by the database
        created     datetime object that represents the time the project is
                    created
        name        name of the project
        ptype       type of the project. at the moment, the types do not have
                    any effects
        creator     the user instance of the creator of the project
        owner       the user instance of the owner of the project
        description a descriptive string

    """

    def __init__(self, name, creator, owner, ptype, pid, created,
                 description=""):
        self.pid = pid
        self.created = created
        self.name = name
        self.ptype = ptype
        self.creator = creator
        self.owner = owner
        self.description = description

    @classmethod
    def create_fromname(cls, db,
                        name, creator, owner, ptype, description="",
                        return_project=False):
        """
        create new database entry and return new project

        input:
            db          database connection
            name        name of the project
            createtor   creator instance of the project
            owner       owner instance of the project
            ptype       type id of the project
            description description string of the project
            return_project  in case of an AlreadyExistingError return the
                            existing project

        output:
            the project instance

        """
        logger.debug("creating project from name:%s", db)
        try:
            pid, created = ccddb.create_project(db, name, creator.uid, owner.uid,
                                                ptype)
            project = cls(name=name,
                          creator=creator.uid,
                          owner=owner.uid,
                          ptype=ptype,
                          pid=pid,
                          created=created,
                          description=description)
        except ccddb.AlreadyExistingError:
            if return_project:
                project = cls.by_name(db, name)
            else:
                raise

        return project

    @classmethod
    def by_pid(cls, db, pid):
        """"
        get project from database and return project

        input:
            cls     project constructor
            db      database connection used for db requests
            pid     project id of the new project

        output:
            project new created project instance

        """
        db_entry = ccddb.getproject_bypid(db, pid)
        if not db_entry:
            raise NotFoundError("No project with pid %d." % pid)

        project = cls(name=db_entry[1],
                      creator=db_entry[4],
                      owner=db_entry[5],
                      ptype=db_entry[2],
                      pid=db_entry[0],
                      created=db_entry[3],
                      description=db_entry[6])
        return project

    @classmethod
    def by_name(cls, db, name):
        """" get project from database and return project """
        db_entry = ccddb.getproject_byname(db, name)
        if not db_entry:
            raise NotFoundError("No such project: '%s'.", name)

        project = cls(name=db_entry[1],
                      creator=db_entry[4],
                      owner=db_entry[5],
                      ptype=db_entry[2],
                      pid=db_entry[0],
                      created=db_entry[3],
                      description=db_entry[6])
        return project

    def data_save_csv(self, db, columns, tables, filename):
        """ save project results to disk """

        result = self.data_view(db, columns, tables)
        with open(filename, 'w') as fd:
            fd.write(result)
            fd.flush()
        return filename

    def data_show(self, db, columns, tables):
        """ show meta information about project results """

        result = ''

        if not columns[0]:
            # show all fields contained in tables xyz
            data = projectdb.get_fields(db, self.pid, tables)
            fmt = '{:30}{:}'
            result = fmt.format('Field', 'Tables')
            result += '\n'
            result += '-' * 80
            result += '\n'
            for clm, tabs in sorted(data.items()):
                result += fmt.format(clm, ', '.join(sorted(tabs)))
                result += '\n'

        if not tables[0]:
            # show all tables containing fields xyz
            tabs = projectdb.get_tables(db, self.pid, columns)
            result += 'Tables'
            if columns:
                result += ' containing: '
                result += ', '.join(columns) or '*'
            result += '\n'
            result += '-' * 80
            result += '\n'
            result += '\n'.join(sorted(tabs))
            result += '\n'

        return result

    def data_view(self, db, columns, tables):
        """ view project results """

        logger.info('View %s, %s', columns, tables)

        result = ''

        if columns and columns[0]:
            result = '#'
            data = projectdb.get_data(db, self.pid, columns, tables)

            if data is None:
                return 'Column not found'

            for i, col in enumerate(columns):
                if '=' in col:
                    idx = col.find('=')
                    result += col[:idx]
                else:
                    result += col
                if i != len(columns) - 1:
                    result += ','

            result += '\n'
            for line in data:
                result += ','.join(map(str, line))
                result += '\n'

        elif tables and tables[0]:
            for tab in tables:
                table = projectdb.get_table(db, self.pid, tab)

                result += '\n#'
                result += tab
                result += '\n'

                if table is None:
                    return 'Table not found'
                fields, data = table
                result += '#'
                result += ', '.join(fields) + '\n'
                for row in data:
                    result += ', '.join(map(str, row)) + '\n'
        else:
            tables = projectdb.get_tables(db, self.pid, columns)
            for tab in tables:
                result += '\n#'
                result += tab
                result += '\n'
                table = projectdb.get_table(db, self.pid, tab)
                if table is None:
                    return 'Table not found'
                fields, data = table
                result += '#'
                result += ', '.join(fields) + '\n'
                result += ', '.join(fields) + '\n'
                for row in data:
                    result += ', '.join(map(str, row)) + '\n'

        return result

    def has_plugin(self, db, plg_id):
        """ returns True if plugin is linked to project """
        plugins = ccddb.get_project_plugins(db, self.pid)
        found = plg_id in plugins
        logger.debug("project %s has plugin %s: %s",
                     self.pid, str(plg_id), found)
        return found

    def delete(self, db):
        """ delete the project from database """
        ccddb.delete_project(db, self.pid)

    def flush(self, db):
        """ write user to database """
        ccddb.update_project(db,
                             self.pid,
                             self.name,
                             self.ptype,
                             self.creator,
                             self.owner,
                             self.description)

    def add_member(self, db, uid, role_id):
        """ add a member to project """
        try:
            ccddb.add_user2project(db, uid, self.pid, role_id)
        except ccddb.AlreadyExistingError:
            logger.warning("User(%d) already in project(%d)", uid, self.pid)

    def remove_member(self, db, uid):
        """ remove a member from project """
        ccddb.delete_user2project(db, uid, self.pid)

    def get_members(self, db):
        """ return list of project's members """
        members = [dict(uid=m[0],
                        name=m[1],
                        mail=m[2],
                        created=m[3].isoformat(),
                        rid=m[4])
                   for m in ccddb.get_project_members(db, self.pid)]
        return members

    def add_plugin(self, db, plg_id):
        """ add a new plugin to project """
        ccddb.add_project2plugin(db, self.pid, plg_id)

    def remove_plugin(self, db, plg_id):
        """ remove a plugin from project """
        ccddb.delete_project2plugin(db, self.pid, plg_id)

    def is_allowed(self, db, user, access):
        """
        verify that user has required access rights

        input:
            db      database connection to user for requests
            user    database.ccdUser object to query permissions of
            access  permissions to request

        output:
            granted boolean

        """
        granted = False
        permissions = 0

        if access < 0:
            return False

        # check whether role has access
        permissions = ccddb.get_project_access(db, self.pid, user.uid)

        mask = access & permissions
        if mask == access:
            granted = True

        return granted

def data(ccd, sid, pld, mth):

    """
    View information from project database

    Input:
        sid     Session ID
        pld     Payload

    output:
        result  path where file is written to
    """

    logger.info('op report: %s', pld)

    result = None

    # get user and workgroup
    user, _ = ccd.get_user_and_workgroup(sid)

    # mandatory payload
    try:
        # project ID
        pid = int(pld["pid"])

        # which columns we want to view OR special keywords [columns, fields]
        columns = pld["columns"]

        # which tables we want to view
        tables = pld["tables"]

    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # optional payload. this only mandatory if report is generated to file
    # (indicated via MTH_SAVE)
    #print 'pld ' + repr(pld)
    try:
        filename = pld["filename"]
        fmt = pld["fmt"]

    except KeyError:
        if mth == ccdlib.MTH_SAVE:
            raise InputError("Invalid payload format. Missing filename or "
                             "file format!")

    # language is optional
    try:
        language = pld["lang"]
    except KeyError:
        language = "de"

    # group is optional
    try:
        group_by_list = pld["group_by"].split(',')
        logger.info('group_by_list: %s', group_by_list)
        group_by = []

        if group_by_list:
            for gp_item in group_by_list:
                if not gp_item:
                    continue
                logger.info("gp_item:%s", gp_item)
                item = tuple(gp_item.split(':'))
                if not len(item) == 2:
                    raise InputError("Invalid payload format!")
                group_by.append(item)

    except KeyError:
        group_by = []

    columns = columns.split(',')
    tables = tables.split(',')
    logger.info('view columns: \'%s\', tables: \'%s\'', columns, tables)

    # project we want to dump
    proj = Project.by_pid(ccd._db.conn, pid)

    # authorise
    if not (user.uid == ccd.superadmin.uid or
            proj.creator == user.uid or
            proj.owner == user.uid or
            proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_READ)):
        raise PermissionDenied(user.name)

    # store report
    if mth == ccdlib.MTH_SAVE:

        # get absolute file name
        path_dest = get_write_location(ccd, sid, filename)

        # check if we have anything to write
        tables_dict = projectdb.get_tables_dict(ccd._db.conn,
                                                proj.pid,
                                                tbl_names=tables,
                                                group_by=group_by,
                                                lang=language)

        if not tables_dict:
            return

        if fmt == CSV:
            proj.data_save_csv(ccd._db.conn,
                               columns,
                               tables,
                               path_dest)

        elif fmt == PDF:
            pdf.gen_pdf(ccd._db.conn,
                        proj.pid,
                        path_dest,
                        os.path.join(
                            ccd.config.shared_directory,
                            'stdtmpl.tar.gz'),
                        tables_dict,
                        language
                        )

        #elif fmt == ODT:
        #    cOdf.gen_odf(ccd._db.conn, proj.pid, tables_dict, path_dest,
        #                 language)

        else:
            raise InputError("Invalid file format:%s!", fmt)

        os.chown(path_dest, ccd.config.runAsUid, ccd.config.runAsGid)
        result = filename

    # just return report
    elif mth == ccdlib.MTH_VIEW:
        result = proj.data_view(ccd._db.conn, columns, tables)

    elif mth == ccdlib.MTH_INFO:
        result = proj.data_show(ccd._db.conn, columns, tables)

    return result

def new_project(ccd, sid, pld):
    """
    create new project

    input:
        ccd     ccd instance
        sid     session id of running session
        pld     payload of the OP_NEWPROJ packet
                might contain the following data:

                    name        name of the plugin
                    tid         type id
                    descrption  plugin description

    output:
        returns project id

    """
    logger.debug("creating new project..")

    # get user and workgroup
    user, wg = ccd.get_user_and_workgroup(sid)

    # is user superadmin
    if (not user.uid == ccd.superadmin.uid and
            not wg.is_allowed(ccd._db.conn, user, ccddb.ACCESS_ADD)):
        raise PermissionDenied(user.name)
    elif not wg:
        raise Exception("Failed to create project since user is not "
                        "assigned to any workgroup")

    # parse request
    try:
        name = pld["name"]
        if len(name) > MAX_LEN_NAME:
            raise InputError("Name exceeds limit of %d characters" %
                             MAX_LEN_NAME)

        tid = int(pld["tid"])

        try:
            description = pld["description"]
        except KeyError:
            description = ""
        if len(description) > MAX_LEN_DESC:
            raise InputError("Desc exceeds limit of %d characters" %
                             MAX_LEN_DESC)

    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # set creator
    creator = user

    # set owner
    # at the moment it's just some admin user
    admins = wg.getmember_byrole(ccd._db.conn, ccddb.ROLE_ADMIN)
    if not admins:
        raise NotFoundError("No admin user in wgroup find!")
    owner = admins[0]

    # create project
    proj = Project.create_fromname(ccd._db.conn, name, creator,
                                   owner, tid, description)

    return proj.pid

def delete_project(ccd, sid, pld):
    """
    delete existing project

    input:
        ccd     ccd instance
        sid     session id of running session
        pld     payload of the OP_DELPROJ packet
                must contain the following data:

                    pid     id of the project to delete

    """

    # get user and workgroup
    user, wg = ccd.get_user_and_workgroup(sid)

    # authorise
    if (not user.uid == ccd.superadmin.uid) and \
            (not wg.is_allowed(ccd._db.conn, user, ccddb.ACCESS_DEL)):
        raise PermissionDenied(user.name)

    # parse packet
    try:
        pid = int(pld["pid"])
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # delete project
    proj = Project.by_pid(ccd._db.conn, pid)
    ses = ccd.get_session(sid)
    ses.unsetproject(ccd._db.conn, proj)
    proj.delete(ccd._db.conn)

def update_project(ccd, sid, pld):
    """
    update existing project

    input:
        ccd     ccd instance
        sid     session id of running session
        pld     payload of the OP_UPDATEPROJ packet
                must contain the following data:

                    pid     id of the project to update
                    name    new name to set
                    descrption  new description text to set

    """

    user, _ = ccd.get_user_and_workgroup(sid)

    # parse request
    try:
        pid = int(pld["pid"])
        name = pld["name"]
        if len(name) > MAX_LEN_NAME:
            raise InputError("Name exceeds limit of %d characters" %
                             MAX_LEN_NAME)

        try:
            description = pld["description"]
        except KeyError:
            description = ""
        if len(description) > MAX_LEN_DESC:
            raise InputError("Desc exceeds limit of %d characters" %
                             MAX_LEN_DESC)

    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # get project
    proj = Project.by_pid(ccd._db.conn, pid)

    # authorise
    if (not user.uid == ccd.superadmin.uid) and \
            (not proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_WRITE)):
        raise PermissionDenied(user.name)

    # update
    proj.name = name
    if description:
        proj.description = description

    proj.flush(ccd._db.conn)

def add_member(ccd, sid, pld):
    """
    add a user to a project

    input:
        ccd     ccd instance
        sid     session id of running session
        pld     payload of the OP_ADDPROJMEMBER packet
                must contain the following data:

                    pid     id of the project to add user to
                    uid     id of the user to add
                    role_id id of the role the new user has

    """

    # get user and workgroup
    user, _ = ccd.get_user_and_workgroup(sid)

    # parse payload
    try:
        pid = int(pld["pid"])
        uid = int(pld["uid"])
        role_id = int(pld["role_id"])
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # project we want to add to
    proj = Project.by_pid(ccd._db.conn, pid)

    # authorise
    if not (user.uid == ccd.superadmin.uid or
            proj.creator == user.uid or
            proj.owner == user.uid or
            proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_ADD)):
        raise PermissionDenied(user.name)

    # add member
    proj.add_member(ccd._db.conn, uid, role_id)

def remove_member(ccd, sid, pld):
    """
    remove a user to a project

    input:
        ccd     ccd instance
        sid     session id of running session
        pld     payload of the OP_DELPROJMEMBER packet
                must contain the following data:

                    pid     id of the project to del user from
                    uid     id of the user to delete

    """

    # get user and workgroup
    user, _ = ccd.get_user_and_workgroup(sid)

    # parse payload
    try:
        pid = int(pld["pid"])
        uid = int(pld["uid"])
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # project we want to add to
    proj = Project.by_pid(ccd._db.conn, pid)

    if not proj:
        raise NotFoundError("No such project")

    # authorise
    if not (user.uid == ccd.superadmin.uid or
            proj.creator == user.uid or
            proj.owner == user.uid or
            proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_DEL)):
        raise PermissionDenied(user.name)

    # remove member
    proj.remove_member(ccd._db.conn, uid)

def select(ccd, sid, pld):
    """
    Associate a project with a session. Without doing this, a user is not able
    to execute any plugins.

    input:
        ccd     ccd instance
        sid     session id of running session
        pld     payload of the OP_SETPROJ packet
                must contain the following data:

                    pid     id of the project to select


    """
    # get user and workgroup
    user, _ = ccd.get_user_and_workgroup(sid)

    # parse payload
    try:
        pid = int(pld["pid"])
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # project we want to add to
    proj = Project.by_pid(ccd._db.conn, pid)

    if not proj:
        raise NotFoundError("No such project")

    # authorise
    if not (user.uid == ccd.superadmin.uid or
            proj.creator == user.uid or
            proj.owner == user.uid or
            proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_READ)):
        raise PermissionDenied(user.name)

    # select
    ses = ccd.get_session(sid)
    ses.setproject(ccd._db.conn, proj)

def add_plugin(ccd, sid, pld):
    """
    add a plugin to a project

    input:
        ccd     ccd instance
        sid     session id of running session
        pld     payload of the OP_ADDPROJPLG packet
                must contain the following data:

                    pid     id of the project to add a plugin to
                    plg_id  id of the plugin to add to project


    """
    # get user and workgroup
    user, wg = ccd.get_user_and_workgroup(sid)

    # parse payload
    try:
        pid = int(pld["pid"])
        plg_id = pld["plg_id"]
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # project we want to add to
    proj = Project.by_pid(ccd._db.conn, pid)

    if not proj:
        raise NotFoundError("No such project")

    # authorise
    if not (user.uid == ccd.superadmin.uid or
            proj.creator == user.uid or
            proj.owner == user.uid or
            proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_ADD)):
        raise PermissionDenied(user.name)

    # check whether plugin is in user's workgroup
    if not wg or not wg.has_plugin(ccd._db.conn, plg_id):
        raise NotFoundError("Plugin is not part of workgroup!")

    # add plugin
    proj.add_plugin(ccd._db.conn, plg_id)

def remove_plugin(ccd, sid, pld):
    """
    remove a user to a project

    input:
        ccd     ccd instance
        sid     session id of running session
        pld     payload of the OP_DELPROJPLG packet
                must contain the following data:

                    pid     id of the project to del a plugin from
                    plg_id  id of the plugin to del from project


    """
    # get user and workgroup
    user, wg = ccd.get_user_and_workgroup(sid)

    # parse payload
    try:
        pid = int(pld["pid"])
        plg_id = int(pld["plg_id"])
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # project we work with
    proj = Project.by_pid(ccd._db.conn, pid)

    if not proj:
        raise NotFoundError("No such project")

    # authorise
    if not (user.uid == ccd.superadmin.uid or
            proj.creator == user.uid or
            proj.owner == user.uid or
            proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_DEL)):
        raise PermissionDenied(user.name)

    # check whether plugin is in user's workgroup
    if not wg.has_plugin(ccd._db.conn, plg_id):
        raise NotFoundError("Plugin is not part of workgroup!")

    # remove member
    proj.remove_plugin(ccd._db.conn, plg_id)

def execute_plugin(ccd, sock, req_t):
    """
    execute a plugin. To do so, check whether plugin is associated with
    project.

    input:
        ccd     ccd instance to operate on
        sock    socket the request came from
        req_t   request tuple

    output:
        returns result of the execution

    """
    op, sid, rid, cat, plg_id, gid, mth, args = req_t

    # get user and workgroup
    user, wg = ccd.get_user_and_workgroup(sid)

    # get project we work with
    proj = ccd._get_project(sid)

    if not proj:
        raise NotFoundError("No such project")

    # validate plugin id
    if not proj.has_plugin(ccd._db.conn, plg_id):
        raise NotFoundError("Plugin to execute is not in project!")

    # authorise
    if not (proj.creator == user.uid or
            proj.owner == user.uid or
            proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_EXEC)):
        raise PermissionDenied(user.name)

    # execute
    logger.debug("request is valid, so executing..")
    result = plugin.execute(ccd, proj.pid, sock, req_t)

    return result

def kill_plugin(ccd, sock, req_t):
    """
    kill a plugin. To do so, check whether plugin is associated with
    project.

    input:
        ccd     ccd instance to operate on
        sock    socket the request came from
        req_t   request tuple

    """
    logger.debug("user wants to kill plugin..")
    op, sid, rid, cat, plg_id, gid, mth, args = req_t

    # get user and workgroup
    user, wg = ccd.get_user_and_workgroup(sid)

    # get project we work with
    proj = ccd._get_project(sid)

    if not proj:
        raise NotFoundError("No such project")

    # validate plugin id
    if not proj.has_plugin(ccd._db.conn, plg_id):
        raise NotFoundError("Plugin to kill is not in project!")

    # authorise
    if not (proj.creator == user.uid or
            proj.owner == user.uid or
            proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_EXEC)):
        raise PermissionDenied(user.name)

    # execute
    plugin.kill(ccd, sid, plg_id, mth, args)

def show_project_members(ccd, sid, pld):
    """
    return a project's member

    input:
        ccd     ccd instance
        sid     session id
        pld     payload of the packet
                must contain the following data:

                    pid     id of the project to get users from

    output:
        returns a project's members

    """
    # get user we work with
    user, _ = ccd.get_user_and_workgroup(sid)

    # parse payload
    try:
        pid = int(pld["pid"])
    except (KeyError, ValueError, TypeError):
        raise InputError("Invalid payload format!")

    if pid < 0:
        raise InputError("Invalid pid requested:%s", pid)

    # project we want to add to
    proj = Project.by_pid(ccd._db.conn, pid)

    if not proj:
        raise NotFoundError("No such project")

    # authorise
    if not (user.uid == ccd.superadmin.uid or
            proj.creator == user.uid or
            proj.owner == user.uid or
            proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_READ)):
        raise PermissionDenied(user.name)

    return proj.get_members(ccd._db.conn)


def show_projects(ccd, sid, pld):
    """
    return projects the user is in

    input:
        ccd     ccd instance
        sid     session id
        pld     payload of the OP_SHOWPROJ packet. if no payload provided, all
                projects the user is member of are shown.

                might contain the following data:

                    pid     id of the project to show. this field might have
                            different states:


                                pid=<int>   show project with corresponding id
                                pid=        show all projects. only allowed for
                                            superadmin

    output:
        returns selected projects

    """
    response = []

    # get user we work with
    user, _ = ccd.get_user_and_workgroup(sid)

    # get users projects
    if not pld:
        projs = user.get_projects(ccd._db.conn)

        logger.debug("projs:%s", projs)
        for proj in projs:
            response.append(dict(pid=proj[0],
                                 name=proj[1],
                                 ptype=proj[2],
                                 created=proj[3].isoformat(),
                                 creator=proj[4],
                                 owner=proj[5]))

    # get specific project
    else:
        try:
            pid = pld["pid"]
        except KeyError:
            raise InputError("Invalid payload format!")

        logger.debug("pid=:%s", pid)

        # return project the user is interested in
        if pid:
            try:
                pid = int(pid)
            except ValueError:
                raise InputError("Invalid pid!")

            # project we want to add to
            proj = Project.by_pid(ccd._db.conn, pid)

            if not proj:
                raise NotFoundError("No such project")

            # authorise
            if not (user.uid == ccd.superadmin.uid or
                    proj.creator == user.uid or
                    proj.owner == user.uid or
                    proj.is_allowed(ccd._db.conn, user, ccddb.ACCESS_READ)):
                raise PermissionDenied(user.name)

            response = [dict(pid=proj.pid,
                             name=proj.name,
                             ptype=proj.ptype,
                             created=proj.created.isoformat(),
                             creator=proj.creator,
                             owner=proj.owner)]

        # if pid field empty, return all existing projects
        else:
            # authorise
            if not (user.uid == ccd.superadmin.uid):
                raise PermissionDenied(user.name)

            all_projects = ccddb.get_all_projects(ccd._db.conn)
            response = [dict(pid=p[0],
                             name=p[1],
                             ptype=p[2],
                             created=p[3].isoformat(),
                             creator=p[4],
                             owner=p[5]) for p in all_projects]

    return response
