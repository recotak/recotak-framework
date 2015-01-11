"""
adding, deleting or modifying workgroups
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

If user is not allowed to perform operation a
database.ccdErrors.PermissionDenied Exception is raised.
In case of illegal input an InputError is thrown.


"""

from database.ccddb import MAX_LEN_NAME
from database.ccddb import MAX_LEN_DESC
from database.ccdErrors import *
from database import ccdUser
from database import ccddb
import logging

logger = logging.getLogger("ccd.%s" % __name__)

class Workgroup(object):
    """
    A workgroup is similiar to a company's department. Every User needs to be
    assigned to at least one workgroup.

    A workgroup has the following attributes:

        wid         id of the workgroup
        created     datetime-object the workgroup is created at
        name        name of the workgroup
        description a descriptive string of the workgroup


    """

    def __init__(self, name, wid, created, description=''):
        self.wid = wid
        self.created = created
        self.name = name
        self.description = description

    @classmethod
    def create_fromname(cls, db, name, pseudo=False, description='',
                        return_workgroup=False):
        """
        create new database entry and return new workgroup. raises an
        AlreadyExistingError if workgroup already in database. If
        return_workgroup is set, returns the already existing workgroup
        instead.

        input:
            db      database connection
            name    name string of project
            pseudo  create a pseudo group (default is False). You should not
                    change this unless you know what you're doing
            description         a short description string
            return_workgroup    in case of an AlreadyExistingError return the
                                existing workgroup

        output:
            the workgroup instance

        """
        try:
            wid, created = ccddb.create_workgroup(db, name, pseudo=pseudo)

            wg = cls(name=name,
                     wid=wid,
                     created=created,
                     description=description)

        except ccddb.AlreadyExistingError:
            if return_workgroup:
                wg = cls.by_name(db, name)
            else:
                raise

        return wg

    @classmethod
    def by_wid(cls, db, wid):
        """ get workgroup from database and return new workgroup """
        db_entry = ccddb.getworkgroup_bywid(db, wid)
        if not db_entry:
            raise NotFoundError("No such workgroup id: '%s'" % wid)

        wg = cls(name=db_entry[1],
                 wid=db_entry[0],
                 created=db_entry[2],
                 description=db_entry[3])
        return wg


    @classmethod
    def by_name(cls, db, name):
        """ get workgroup from database and return new workgroup """
        db_entry = ccddb.getworkgroup_byname(db, name)
        if not db_entry:
            raise NotFoundError("No such workgroup name: '%s'" % name)

        wg = cls(name=db_entry[1],
                 wid=db_entry[0],
                 created=db_entry[2],
                 description=db_entry[3])
        return wg

    def delete(self, db):
        """ delete the workgroup from database """
        ccddb.delete_workgroup(db, self.wid)

    def add_member(self, db, uid, role_id):
        """
        add a member to workgroup. raised an AlreadyExistingError if user
        alread in database.

        input:
            db      database connection
            uid     id of the user to add
            role_id id of the role the user has


        """
        try:
            ccddb.add_user2workgroup(db, uid, self.wid, role_id)
        except ccddb.AlreadyExistingError:
            pass

    def remove_member(self, db, uid):
        """ remove a user from workgroup """
        ccddb.delete_user2workgroup(db, uid, self.wid)

    def add_plugin(self, db, plg_id):
        """ add plugin to workgroup """
        ccddb.add_workgroup2plugin(db, self.wid, plg_id)

    def remove_plugin(self, db, plg_id):
        """ remove plugin from workgroup """
        ccddb.delete_workgroup2plugin(db, self.wid, plg_id)

    def get_members(self, db):
        """ return list of wgroups's members """
        members = [dict(uid=m[0],
                        name=m[1],
                        mail=m[2],
                        created=m[3].isoformat(),
                        rid=m[4])
                   for m in ccddb.get_workgroup_members(db, self.wid)]
        return members

    def flush(self, db):
        """ write user to database """
        ccddb.update_workgroup(db, self.wid, self.name, self.description)

    def is_allowed(self, db, user, access):
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
        logger.debug("user (%s) requested access:%d", user.name, access)
        granted = False
        permissions = 0

        if access < 0:
            return False

        # check whether role has access
        permissions = ccddb.get_workgroup_access(db, self.wid, user.uid)

        mask = access & permissions
        if mask == access:
            granted = True

        logger.debug("granted:%s", granted)
        return granted

    def has_user(self, db, user):
        """ returns True if a user is part of the workgroup """
        users = ccddb.get_workgroup_members(db, self.wid)
        for u in users:
            if u[0] == user.uid:
                return True

        return False

    def has_plugin(self, db, plg_id):
        """ returns True if plugin is linked to workgroup """
        plugins = ccddb.get_workgroup_plugins(db, self.wid)
        res = plg_id in plugins
        logger.debug("has plugin %s:%s", str(plg_id), res)
        return res

    def getmember_byrole(self, db, role_id):
        """ return a list of members that are associated with
            to given role_id
        """
        logger.debug("Get users of wgroup %s with role_id %d",
                     self.wid, role_id)
        users = []
        found = ccddb.getuser_bywid(db, self.wid)
        logger.debug("users in wgroup:%s", found)
        for entry  in found:
            name = entry[0]
            rid = entry[1]
            if rid == role_id:
                user = ccdUser.User.by_name(db, name)
                users.append(user)
        logger.debug("found users:%s", users)
        return users

def new_workgroup(ccd, sid, pld):
    """
    create new workgroup. only the superadmin is allowed to create new
    workgroups

    input:
        ccd     ccd instance
        sid     session id
        pld     payload. requires the following keys:

                    name    name of the new workgroup

                optional keys:
                    description     description of the workgroup

    output:
        id of new workgroup


    """
    logger.debug("creating new workgroup..")

    # get user we work with
    user, _ = ccd.get_user_and_workgroup(sid)

    # is user superadmin
    if not user.uid == ccd.superadmin.uid:
        raise PermissionDenied(user.name)

    # create workgroup
    try:
        # name
        name = pld["name"]
        if len(name) > MAX_LEN_NAME:
            raise InputError("Name exceeds limit of %d characters" %
                             MAX_LEN_NAME)

        # description
        try:
            description = pld["description"]
        except KeyError:
            description = ""
        if len(description) > MAX_LEN_DESC:
            raise InputError("Desc exceeds limit of %d characters" %
                             MAX_LEN_DESC)

    except KeyError:
        raise InputError("Invalid payload format!")

    wg = Workgroup.create_fromname(ccd._db.conn, name, description)

    # add plugins to workgroup
    for plg_id in ccddb.get_all_plugins(ccd._db.conn):
        wg.add_plugin(ccd._db.conn, plg_id[0])

    return wg.wid

def delete_workgroup(ccd, sid, pld):
    """
    delete existing workgroup. only superadmin is allowed to.

    input:
        ccd     ccd instance
        sid     session id
        pld     payload. requires the following keys:

                    wid    id of workgroup to remove

    """

    # get user we work with
    user, _ = ccd.get_user_and_workgroup(sid)

    # is user superadmin
    if not user.uid == ccd.superadmin.uid:
        raise PermissionDenied(user.name)

    # delete workgroup
    try:
        wid = int(pld["wid"])
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    wg = Workgroup.by_wid(ccd._db.conn, wid)
    wg.delete(ccd._db.conn)


def update_workgroup(ccd, sid, pld):
    """
    update existing workgroup. only superadmin is allowed to.

    input:
        ccd     ccd instance
        sid     session id
        pld     payload. requires the following keys:

                    wid     id of workgroup to remove
                    name    new name of the workgroup

                optional keys:
                    description     new description of workgroup

    """

    # get user we work with
    user, _ = ccd.get_user_and_workgroup(sid)

    # is user superadmin
    if not user.uid == ccd.superadmin.uid:
        raise PermissionDenied(user.name)

    # create workgroup
    try:
        wid = int(pld["wid"])
        newname = pld["name"]
        try:
            description = pld["description"]
        except KeyError:
            description = ""

    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    wg = Workgroup.by_wid(ccd._db.conn, wid)
    wg.name = newname
    if description:
        wg.description = description

    wg.flush(ccd._db.conn)

def add_member(ccd, sid, pld):
    """
    add a user to a workgroup. only superadmin is allowed to add members to
    workgroup

    input:
        ccd     ccd instance
        sid     session id
        pld     payload. requires the following keys:

                    wid     id of workgroup to add to
                    uid     id of the user to add
                    rid     role id of the user

    """

    # get user we work with
    user, _ = ccd.get_user_and_workgroup(sid)

    # check rights
    if not user.uid == ccd.superadmin.uid:
        raise PermissionDenied(user.name)

    # parse payload
    try:
        wid = int(pld["wid"])
        uid = int(pld["uid"])
        role_id = int(pld["role_id"])
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # we group we want to add to
    wg = Workgroup.by_wid(ccd._db.conn, wid)

    wg.add_member(ccd._db.conn, uid, role_id)

def remove_member(ccd, sid, pld):
    """
    remove a user to a workgroup. only superadmin is allowed to.

    input:
        ccd     ccd instance
        sid     session id
        pld     payload. requires the following keys:

                    wid     id of workgroup to add to
                    uid     id of the user to add
                    rid     role id of the user

    """

    # get user we work with
    user, _ = ccd.get_user_and_workgroup(sid)

    # check rights
    if not user.uid == ccd.superadmin.uid:
        raise PermissionDenied(user.name)

    # parse payload
    try:
        wid = int(pld["wid"])
        uid = int(pld["uid"])
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # we group we want to add to
    wg = Workgroup.by_wid(ccd._db.conn, wid)

    wg.remove_member(ccd._db.conn, uid)

def show_workgroup_members(ccd, sid, pld):
    """
    return workgroups the user is in. The superadmin is able to get workgroup
    members of every workgroup.

    input:
        ccd     ccd instance
        sid     session id
        pld     payload. requires the following keys:

                    wid     id of workgroup to add to

    """
    # get user we work with
    user, wg = ccd.get_user_and_workgroup(sid)

    # get users wgroup
    if pld:
        try:
            wid = int(pld["wid"])
        except (KeyError, ValueError, TypeError):
            raise InputError("Invalid payload format!")

        # check rights
        if not user.uid == ccd.superadmin.uid and not wid == wg.wid:
            raise PermissionDenied(user.name)

        if wid < 0:
            raise InputError("Invalid wid requested:%s" % wid)

            # we group we want to add to
        wg = Workgroup.by_wid(ccd._db.conn, wid)

    return wg.get_members(ccd._db.conn)

def show_workgroups(ccd, sid, pld):
    """
    return information of workgroups

    input:
        ccd     ccd instance
        sid     session id
        pld     payload

                a) no payload provided
                   if user is superadmin, return information about all
                   workgorups. if user is nonsuperadmin, only return
                   inforamtion about workgroup, the user is member of.

                b) payload.
                   return infrmation about specified workgroup. only allowed
                   to superadmin

                   mandatory keys:

                        wid     workgroup id to get information from


    output:
        list of dictionaries that represent workgroup information

    """
    # get user we work with
    user, wg = ccd.get_user_and_workgroup(sid)

    # no payload is sent
    if not pld:

        # if user is superadmin and no payload defined return information
        # about all wgroups
        if user.uid == ccd.superadmin.uid:
            all_wgroups = ccddb.get_all_workgroups(ccd._db.conn)
            return [dict(wid=w[0],
                         name=w[1].encode("utf8"),
                         created=w[2].isoformat()) for w in all_wgroups]

        # if user not superadmin and no paylouad defined, return information
        # about wgroup the user is in
        elif wg:
            return [dict(wid = wg.wid,
                         name = wg.name.encode("utf8"),
                         created = wg.created.isoformat())]

        # the user does not been added to a workgroup yet
        else:
            logger.warning("user %s is not assigned to a workgroup" %
                           user.name)
            return []

    # some payload is given
    else:

        # if user is not assigned to any wgroup, he must be SA to processed.
        # other words: the superadmin is able to request for all wgroups,
        # although he is not assigned to one (wg == None)
        if not wg and not user.uid == ccd.superadmin.uid:
            raise PermissionDenied(user.name)

        try:
            wid = pld["wid"]
            wid = int(wid)
        except (KeyError, ValueError):
            raise InputError("Invalid payload format!")

        # if not superadmin and requests a specific domain, it must be the
        # wgroup of the user himself. other words: the user has only access to
        # the workgroups of himself
        if not user.uid == ccd.superadmin.uid and not wg.wid == wid:
            raise PermissionDenied(user.name)

        wg = Workgroup.by_wid(ccd._db.conn, wid)

        return [dict(wid = wg.wid,
                     name = wg.name.encode("utf8"),
                     created = wg.created.isoformat())]

def add_plugin(ccd, sid, pld):
    """
    add a plugin to a workgroup

    input:
        ccd     ccd instance
        sid     session id
        pld     payload. mandatory keywords are:

                    wid     id of workgroup to add plugin to
                    plg_id  id of plugin to add


    """
    # get user we work with
    user, _ = ccd.get_user_and_workgroup(sid)

    if not user.uid == ccd.superadmin.uid:
        raise PermissionDenied(user.name)

    # parse payload
    try:
        wid = int(pld["wid"])
        plg_id = pld["plg_id"]
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # we group we want to add to
    wg = Workgroup.by_wid(ccd._db.conn, wid)

    # check whether plugin id is valid
    if not ccd.validate_pluginid(plg_id):
        raise NotFoundError("No such plugin id: '%s'" % plg_id)

    wg.add_plugin(ccd._db.conn, plg_id)

def remove_plugin(ccd, sid, pld):
    """
    remove a plugin from workgroup

    input:
        ccd     ccd instance
        sid     session id
        pld     payload. mandatory keywords are:

                    wid     id of workgroup to remove plugin from
                    plg_id  id of plugin to from

    """
    # get user we work with
    user, _ = ccd.get_user_and_workgroup(sid)

    if not user.uid == ccd.superadmin.uid:
        raise PermissionDenied(user.name)

    # parse payload
    try:
        wid = int(pld["wid"])
        plg_id = pld["plg_id"]
    except (KeyError, ValueError):
        raise InputError("Invalid payload format!")

    # we group we want to add to
    wg = Workgroup.by_wid(ccd._db.conn, wid)

    # check whether plugin id is valid
    if not ccd.validate_pluginid(plg_id):
        raise NotFoundError("No such plugin id: '%s'" % plg_id)


    wg.remove_plugin(ccd._db.conn, plg_id)


