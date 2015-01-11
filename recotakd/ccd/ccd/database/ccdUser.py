"""
user management
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

There basically two types of users
    a) the superadmin
       The hero of the world, the guy who is allowed to do everything.
       The superadmin user is stored as ccd instance variable. You will find a
       lot of statements, that check whether the user sending the request is
       the superadmin:

        if (not user.uid == ccd.superadmin.uid) and ..

    b) the rest
       users need to have specific permissions to perform operations. This
       operations are checked before processing a request. For instance:

        if (not user.uid == ccd.superadmin.uid) and
            (not is_allowed(ccd._db.conn, user, ccddb.ACCESS_ADD)):
            raise PermissionDenied(user.name)

The user's permissions are managed in table 'role'. This is basically an ACL,
where every set of permissions have an ID. This role ID indicates which
operations are allowed for a user and which not.

User information are stored in a table called 'user'. The relation, that a user
is member of a workgroup or project is represented by a table '_user2workgroup'
or '_user2project'. These tables contain the id of the user, uid, the id of the
workgroup, wid, and the id of role, rid.

This module abstracts access to database tables by providing basic
functionalities and a User class to work with. So do not bypass anything provided
here, since it provides authorisation checks.

"""
from database.ccddb import MAX_LEN_PASSWORD
from database.ccddb import MAX_LEN_NAME
from database.ccddb import MAX_LEN_MAIL
from database.ccddb import MAX_LEN_DESC
from database.ccdErrors import *
from database import ccddb
import logging
import os
import re

logger = logging.getLogger("ccd.%s" % __name__)

class User(object):
    """ implements a user """

    #: path to globally configured user dir
    BASE_DIR = ""

    #: path to globally configured shared dir
    SHARED_DIR = ""

    FD_DIR = ".fd"

    def __init__(self, name, mail, uid, created, description=''):
        self.uid = uid
        self.name = name
        self.mail = mail
        self.description = description
        self.created = created

        if User.BASE_DIR:
            home_dir = os.path.join(User.BASE_DIR, name)
        else:
            logger.warning("User base dir isn't set!")
            home_dir = ""

        self.home_dir = home_dir

    @classmethod
    def by_name(cls, db, name):
        """ select user from database and return instance of class user"""
        res = ccddb.getuser_byname(db, name)
        user = cls(uid=res[0],
                   name=res[1],
                   mail=res[2],
                   created=res[3],
                   description=res[5])
        return user

    @classmethod
    def by_uid(cls, db, uid):
        """
        select user from database and return instance of class user

        input:
            cls User constructor
            db  database connection to use for db interaction
            uid user id of the new user to create

        output:
            return new user

        """
        res = ccddb.getuser_byuid(db, uid)
        if not res:
            raise NotFoundError("No user with uid '%s'." % uid)

        user = cls(uid=res[0],
                   name=res[1],
                   mail=res[2],
                   created=res[3],
                   description=res[5]
                  )
        return user

    @classmethod
    def create_fromname(cls, db,
                        name, password, mail, description='',
                        return_user=False):
        """
        create database entry for the new user

        input:
            db      database connection
            name    name string of the connection
            password    password string of the user (do not store any cleartext
                        passwords!)
            mail        mail address of user
            description description of the user
            return_user in case of AlreadyExistingError return the existing
                        user

        output:
            the user instance

        """
        try:
            uid, created = ccddb.create_user(db,
                                             name,
                                             password,
                                             mail,
                                             description)

            user = cls(uid=uid,
                       name=name,
                       mail=mail,
                       created=created,
                       description=description)
        except ccddb.AlreadyExistingError:
            if return_user:
                user = cls.by_name(db, name)
            else:
                raise

        return user

    def delete(self, db):
        """ delete the workgroup from database """
        ccddb.delete_session_by_uid(db, self.uid)
        ccddb.delete_user(db, self.uid)

    def flush(self, db):
        """ write user to database """
        ccddb.update_user(db, self.uid, self.name, self.mail, self.description)

    def get_workgroup(self, db):
        """ return workgroup the user is in """
        from database import ccdWorkgroup
        wids = ccddb.getworkgroup_byuid(db, self.uid)
        if not wids:
            raise NotFoundError("Failed to get workgroup the user is in")

        logger.debug("user is member of wgroups %s", wids)
        wid = wids[0]
        wg = ccdWorkgroup.Workgroup.by_wid(db, wid)
        return wg

    def get_projects(self, db):
        """ return project pids of the projects the user is in """
        logger.debug("getting users' projects")
        projects = ccddb.getproject_byuid(db, self.uid)
        return projects

    def get_home_directory(self, db, recursive=False, no_names=False):
        """
        returns a list of the user's home directory

        input:
            db          database connection
            recursive   boolean, to indicate whether to return the content of
                        the subdirectories to
            no_names    boolean, to indicate whether to not resolve the
                        directory hashes to names

        output:
            home        a dict containing the user's home directory content

        """
        home = dict()
        home[self.name] = dict(d=True, content=dict())
        parent = home[self.name]["content"]


        if not self.home_dir:
            logger.warning("invalid home_dir %s", self.home_dir)
            return

        l = len(self.home_dir)
        for root, dirs, files in os.walk(self.home_dir, followlinks=True):
            dirs[:] = [d for d in dirs if d != User.FD_DIR]
            logger.debug("=================================================")
            logger.debug("root:%s", root)
            logger.debug("dirs:%s", dirs)
            logger.debug("files:%s", files)
            breadcrumps = root[l+1:].split("/")
            logger.debug("breadcrumps:%s", breadcrumps)
            old_parent = parent
            for bc in breadcrumps:

                if (not bc):
                    break

                logger.debug("walking '%s'", bc)
                try:
                    parent = parent[bc]["content"]
                except KeyError:
                    pass

            logger.debug("parent:%s", parent)

            # iterate over directories in user home
            for plg_id in dirs:

                subdir_fn = os.path.join(root, plg_id)
                logger.debug("processing directory:%s", subdir_fn)

                # ignore if owner is not ccd user
                if not _valid_owner(subdir_fn):
                    continue

                # resolve plg ids to plg names
                name = ccddb.get_plugin_name_by_id(db, plg_id)
                is_shared = os.path.realpath(subdir_fn)==User.SHARED_DIR
                logger.debug("is_shared:%s", is_shared)
#                if not name and not is_shared:
#                    logger.debug("skipping %s", plg_id)
#                    continue


                # add new directory
                parent[plg_id] = dict()

                # indicate that entry represents a directory
                parent[plg_id]["d"] = True

                # since it is a directory, it might have content
                parent[plg_id]["content"] = dict()

                # name of the plugin
                if not no_names and name:
                    parent[plg_id]["name"] = name[0]

            # iterate over files in user home
            for f in files:
                # ignore if owner is not ccd user
                subdir_f = os.path.join(root, f)
                if not _valid_owner(subdir_f):
                    continue

#                parent[key]["content"][f] = dict(name=f, d=False)
                logger.debug("adding %s", f)
                parent[f] = dict(d=False)

            parent = old_parent
            logger.debug("home:%s", home)

        return home

def _valid_owner(subdir_fn):
    statinfo = os.stat(subdir_fn)
    valid_owner_uid = getattr(_valid_owner, "CCD_UID", 0)
    if not statinfo.st_uid == valid_owner_uid:
        return False

    return True


def is_allowed(db, user, access):
    """
    returns True if user has the access bits set

    input:
        db      database connection
        user    user object to request allowance for
        access  requested permissions
                e.g:
                    ccddb.ACCESS_READ
                    ccddb.ACCESS_WRITE
                    ccddb.ACCESS_ADD
                    ccddb.ACCESS_DEL
                    ccddb.ACCESS_EXEC

                request for multiple permission via OR (e.g.
                ccddb.ACCESS_READ|ccddb.ACCESS_WRITE)

    output:
        True if allowed else False

    """
    logger.debug("requested access:%d", access)
    granted = False
    permissions = 0

    if access < 0:
        return False

    # check whether role has access
    permissions = ccddb.get_user_access(db, user.uid)
    logger.debug("permission:%d", permissions)

    mask = access & permissions
    if mask == access:
        granted = True

    return granted

def new_user(ccd, sid, pld):
    """
    create new user. The user must be the superadmin or must have ACCESS_ADD in
    the _user2users table.

    input:
        ccd     ccd instance
        sid     session id of the user that wants to create a new user
        pld     payload. the payload consists of. If mandatory fields are
                missing, raises a database.ccddb.InputError.

                    name    name of the user to create. the length of the name
                            must not exceed database.ccddb.MAX_LEN_NAME. the
                            user name must only consist of letters a-zA-z and
                            numbers 0-9 and underscore _
                    mail    mail address of the user to create. the length of
                            the mail address must not exceed
                            database.ccddb.MAX_LEN_MAIL
                    password    password of the user to create. note, the
                                password should be hashed. the length of the
                                password must not exceed the length of
                                database.ccddb.MAX_LEN_PASSWORD
                    description a descriptional text for the user. the length
                    (optional)  of the description must not exceed
                                database.ccddb.MAX_LEN_DESC


    output:
        returns the user id

    """
    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise
    if (not user.uid == ccd.superadmin.uid) and \
        (not is_allowed(ccd._db.conn, user, ccddb.ACCESS_ADD)):
        raise PermissionDenied(user.name)

    # verify that a payload is given
    if not pld or not isinstance(pld, dict):
        raise InputError("Invalid payload format!")

    # parse request
    try:
        name = pld["name"]
        if len(name) > MAX_LEN_NAME:
            raise InputError("Name exceeds limit of %d characters" %
                             MAX_LEN_NAME)

        mail = pld["mail"]
        if len(mail) > MAX_LEN_MAIL:
            raise InputError("Mail exceeds limit of %d characters" %
                             MAX_LEN_MAIL)

        password = pld["password"]
        if len(password) > MAX_LEN_PASSWORD:
            raise InputError("Password exceeds limit of %d characters" %
                             MAX_LEN_PASSWORD)

        try:
            description = pld["description"]
        except KeyError:
            description = ''
        if len(description) > MAX_LEN_DESC:
            raise InputError("Desc exceeds limit of %d characters" %
                             MAX_LEN_DESC)


    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # verify user name
    valid = re.compile("^[a-zA-Z0-9_]")
    if not valid.match(name):
        raise InputError("Invalid username:'%s'!", name)

    # create user
    user = User.create_fromname(ccd._db.conn,
                                name,
                                password,
                                mail,
                                description)
    return user.uid


def show_user(ccd, sid, pld):
    """
    get user information

    input:
        ccd     ccd instance
        sid     session id
        pld     payload as dict to update user information. either one of the
                following keys must occur in payload:

                    uid     return informations for a specific user. A user is
                            only allowed to receive information about himself
                            as loong as he is not explicitly authorised by
                            having the ACCESS_READ flag set in
                            user2user-table.
                            the superadmin is allowed to request arbitrary
                            users' information.

                            a user is able to request information about
                            himself by requesting his own uid or an empty uid
                            (uid=)..

                    pid     returns members of a given project.
                    wid     returns members of a given workgroup

    output:
        requested user information

    """
    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # verify that a payload is given
    if not pld or not isinstance(pld, dict):
        raise InputError("Invalid payload format!")

    # show single user
    if "uid" in pld:
        try:
            uid = int(pld["uid"]) if pld["uid"] else None
        except ValueError:
            raise InputError("Invalid payload format!")

        # requesting information of user himself, everything is fine
        if uid and user.uid == uid:
            response = [dict(
                uid=user.uid,
                name=user.name,
                mail=user.mail,
                description=user.description
            )]

        # requesting information about others and not authenticated
        elif (not user.uid == ccd.superadmin.uid) and \
             (not is_allowed(ccd._db.conn, user, ccddb.ACCESS_READ)):
            raise PermissionDenied(user.name)

        # if no uid is provided and authorised, return all existing users.
        # this is only allowed for superadmin. though, the authrisation
        # happends in the previous if-clause above, so no redundant code here.
        elif not uid:
            all_users = ccddb.get_all_users(ccd._db.conn)
            response = [dict(uid=u[0],
                             name=u[1],
                             mail=u[2]) for u in all_users]

        # requesting information and being authenticated
        # get user from database
        else:
            user = User.by_uid(ccd._db.conn, uid)
            response = [dict(uid=user.uid,
                             name=user.name,
                             mail=user.mail,
                             description=user.description)
                       ]

    # show user in project
    elif "pid" in pld:
        from database import ccdProject
        response = ccdProject.show_project_members(ccd,
                                                   sid,
                                                   dict(pid=pld["pid"]))

    # show user in wgroup
    elif "wid" in pld:
        from database import ccdWorkgroup
        response = ccdWorkgroup.show_workgroup_members(ccd,
                                                       sid,
                                                       dict(wid=pld["wid"]))

    else:
        raise InputError("Invalid json!")

    return response


def delete_user(ccd, sid, pld):
    """
    delete existing user. the user must either be superadmin or has ACCESS_DEL.

    input:
        ccd     ccd instance
        sid     session id
        pld     payload as dict to update user information. the following key
                must be submitted:

                    uid     the user's id to remove


    """

    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise
    if (not user.uid == ccd.superadmin.uid) and \
       (not is_allowed(ccd._db.conn, user, ccddb.ACCESS_DEL)):
        raise PermissionDenied(user.name)

    # verify that a payload is given
    if not pld or not isinstance(pld, dict):
        raise InputError("Invalid payload format!")

    # parse request
    try:
        uid = int(pld["uid"])
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # verify that the SA is not deleted
    if uid == ccd.superadmin.uid:
        raise InputError("Superadmin cannot be deleted!")

    user = User.by_uid(ccd._db.conn, uid)
    user.delete(ccd._db.conn)

def update_user(ccd, sid, pld):
    """
    update existing user. The user must either be superadmin or has
    ACCESS_WRITE.

    input:
        ccd     ccd instance
        sid     session id
        pld     payload as dict to update user information.

                    uid         id of the user to update
                    name        new name of the user
                    mail        new mail of the user
                    description the new description text of the user. this
                    (optional)  argument is optional


    """
    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise
    if (not user.uid == ccd.superadmin.uid) and \
       (not is_allowed(ccd._db.conn, user, ccddb.ACCESS_WRITE)):
        raise PermissionDenied(user.name)

    # verify that a payload is given
    if not pld or not isinstance(pld, dict):
        raise InputError("Invalid payload format!")

    # parse request
    #TODO instead of setting every dict value we should work with
    # more general *args or **kwargs
    try:
        uid = int(pld["uid"])
        name = pld["name"]
        if len(name) > MAX_LEN_NAME:
            raise InputError("Name exceeds limit of %d characters" %
                             MAX_LEN_NAME)

        # verify user name
        valid = re.compile("^[a-zA-Z0-9_]")
        if not valid.match(name):
            raise InputError("Invalid username:'%s'!", name)

        mail = pld["mail"]
        if len(mail) > MAX_LEN_MAIL:
            raise InputError("Mail exceeds limit of %d characters" %
                             MAX_LEN_MAIL)

        try:
            description = pld["description"]
        except KeyError:
            description = ''
        if len(description) > MAX_LEN_DESC:
            raise InputError("Desc exceeds limit of %d characters" %
                             MAX_LEN_DESC)

    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # create user
    if uid == ccd.superadmin.uid:
        logger.warning("Superadmin is modified to name=%s(old:%s), "
                       "mail=%s(old:%s)", name, mail)

    user = User.by_uid(ccd._db.conn, uid)
    user.name = name
    user.mail = mail
    if description:
        user.description = description
    user.flush(ccd._db.conn)


def update_user_passwd(ccd, sid, pld):
    """
    update existing user's password

    input:
        ccd     ccd instance
        sid     session id
        pld     payload as dict to contain old and new password

                    uid     user id of the user
                    old     old password
                    new     new password

    """
    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise
    if (not user.uid == ccd.superadmin.uid) and \
       (not is_allowed(ccd._db.conn, user, ccddb.ACCESS_ADD)):
        raise PermissionDenied(user.name)

    # verify that a payload is given
    if not pld or not isinstance(pld, dict):
        raise InputError("Invalid payload format!")

    # parse request
    try:
        uid = int(pld["uid"])
        old_pwd = pld["old"]
        if len(old_pwd) > MAX_LEN_PASSWORD:
            raise InputError("Old password exceeds limit of %d characters" %
                             MAX_LEN_PASSWORD)

        new_pwd = pld["new"]
        if len(new_pwd) > MAX_LEN_PASSWORD:
            raise InputError("New password exceeds limit of %d characters" %
                             MAX_LEN_PASSWORD)

    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # verify that the SA's password is not changed
    if uid == ccd.superadmin.uid:
        raise InputError("Superadmin's password cannot be changed this way!")

    # update password
    ccddb.update_user_password(ccd._db.conn, uid, old_pwd, new_pwd)

