""" provides ways to create, delete or manipulate connection groups """

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
from connection.ccdProxyChain import return_chain_by_id
from connection.ccdProxyChain import ProxyChainSocket
from database.ccdProject import Project
from connection.ccdCrypto import genGID
from ctools.cUtil import validString
from database.ccdErrors import *
from database import ccddb
from copy import copy
import logging

logger = logging.getLogger("ccd.%s" % __name__)

class ConnectionGroup(object):
    """
    A connection group is basically a list of proxy chains with a certain
    priority. As soon as a plugin establishes a connection, its traffic is
    routed via the proxy chain with hightest priority in the chain. If the
    chains is defect, a chain with the next lower priority is chosen for
    connection routing.

        +--------------------------------+
        |        connection group        |
        +--------------------------------+
                        |
                        | consists of (ordered by priority)
                        |
                        v
        +--------------------------------+
        |          proxy chains          |
        +--------------------------------+
                        |
                        | consists of
                        |
                        v
        +--------------------------------+
        |            proxies             |
        +--------------------------------+



    A connection group object has the following attributes:

        grpid       the id of the connection group. an 8 byte hash
        description a string to contain some descriptive wordings
        chains      a list of chains ordered by priority. the priority is
                    encoded in the list index. a chain with top priority has
                    index 0. the higher the index, the lower the priority.
                    since everything is stored in database, too, this can be
                    seen as cache.
        default     a flag, to indicate whether the group is a system group


    """

    def __init__(self, grpid, description, default=False):
        self.grpid = grpid
        self.description = description
        self.chains = []
        self.default = default # sys default group

    @classmethod
    def create(cls, db, description):
        """
        create a group by passing the description. the id is set
        automatically

        """
        grpid = genGID()
        ccddb.add_connection_group(db, grpid, description)
        return cls(grpid, description)

    def add_chain(self, db, chain, prio):
        """
        add a chain with a given priority to the group. the priority states
        the position of the chain in our list. this results in a list that
        is sorted by priority. add chain to database, too.

        input:
            db      database connection
            chain   chain object to add
            prio    priority assigned to the chain

        """
        if chain.pcid in self.chains:
            return

        # add chain to db
        try:
            ccddb.add_chain_to_group(db, self.grpid, chain.pcid, prio)
        except ccddb.AlreadyExistingError:
            pass
        except ccddb.InvalidQuery:
            raise Exception("tried to add invalid chain id(%s) to "
                            "conngroup(%s)!" % (chain.pcid, self.grpid))

        # add chain to local chain cache, the priority states the position
        # of the chain in our list. this results in a list that is sorted
        # by priority
        self.chains.insert(prio, chain)

    def del_chain(self, db, chain):
        """
        delete a chain. also deletes chain from database.

        input:
            db      database connection
            chain   chain object to delete

        """
        if not chain in self.chains:
            return

        # add proxy to db
        ccddb.del_chain_from_group(db, self.grpid, chain.pcid)

        # add proxy to local chain cache
        self.chains.remove(chain.pcid)

    def set_default(self, db):
        """
        set as connection group as default group. only one default group is
        allowed. raises an exception if another group is default group.

        """
        ccddb.set_default_conngroup(db, self.grpid)
        self.default = True

    def set_chains(self, chains):
        """ set a group's chains cache by passing a list of proxy chains """
        self.chains = chains

    def get_chains(self):
        """ return the list of the group's proxy chains in cache """
        return self.chains

    def has_chain(self, chain):
        """ return True if the passed chain is already added to group """
        for c in self.chains:
            if c.pcid == chain.pcid:
                break
        else:
            return False

        return True

    def reset(self):
        """ deletes chain cache """
        self.chains = []

    def as_dict(self):
        """ returns a dictionary of the group """
        return dict(grpid=self.grpid,
                    description=self.description,
                    default=self.default,
                    chains=[chain.pcid for chain in self.chains])

def return_group_by_id(ccd, grpid):
    """
    requests information of group from database, creates group object and
    returns it..

    """
    # get from cache
    try:
        return ccd.connection_groups[grpid]

    # on error continue and get group from db.
    except KeyError:
        pass

    db = ccd._db.conn

    res = ccddb.get_group_by_id(db, grpid)
    if not res:
        raise Exception("Failed to get group with id %s" % grpid)

    group = ConnectionGroup(grpid=grpid,
                            description=res[1],
                            default=res[2])

    # get the chains that are assigned to the group
    for prio, pcid in enumerate(ccddb.get_chains_of_group(db, grpid)):
        if not pcid:
            continue

        logger.debug("group %s has chain %s", grpid, pcid)
        chain = return_chain_by_id(ccd, pcid[0])
        group.add_chain(db, chain, prio)

    ccd.connection_groups[grpid] = group
    return group

def create_group(ccd, sid, pld):
    """ create a connection group """

    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise user
    if (not user.uid == ccd.superadmin.uid):
        raise PermissionDenied(user.name)

    # parse payload
    try:
        # validate description
        description = pld["description"]
        if not validString(description):
            raise InputError("Invalid characters is description!")

    except KeyError:
        raise InputError("Invalid json format!")

    # create new conn group
    group = ConnectionGroup.create(ccd._db.conn, description)

    # cache
    ccd.connection_groups[group.grpid] = group

    # return group id
    return dict(grpid=group.grpid)

def show_group(ccd, sid):
    """
    show connection groups in database

    input:
        ccd     ccd instance
        oundid     session id

    """

    # get user
    user, wg = ccd.get_user_and_workgroup(sid)

    # authorise user.
    if (not user.uid == ccd.superadmin.uid  and
        not wg.is_allowed(ccd._db.conn, user, ccddb.ACCESS_READ)):
        raise PermissionDenied(user.name)

    # get all proxy chains
    pld = _update_connection_groups(ccd)

    return pld

def del_group(ccd, sid, pld):
    """
    delete connection group from database

    input:
        ccd     ccd instance
        sid     session id
        pld     payload of request


    """

    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise user
    if (not user.uid == ccd.superadmin.uid):
        raise PermissionDenied(user.name)

    # parse payload
    try:
        grpid = pld["grpid"]
    except (KeyError, ValueError):
        raise InputError("Invalid json format!")

    # delete chain
    try:
        ccddb.del_connection_group(ccd._db.conn, grpid)
    except Exception as e:
        raise InputError("Failed to delete chain:'%s'!" % e)

    # remove from cache
    del ccd.connection_groups[grpid]

def use_group(ccd, sid, pld):
    """
    trigger connection group to use for plugins' traffic forwarding

    input:
        ccd     ccd instance
        sid     session id
        pld     payload of request


    """
    db = ccd._db.conn

    # get user
    user, wg = ccd.get_user_and_workgroup(sid)

    # parse payload
    try:
        grpid = pld["grpid"]
        plg_id = pld["plg_id"] if "plg_id" in pld else None
        pid = pld["pid"] if "pid" in pld else None

    except (KeyError, ValueError):
        raise InputError("Invalid json format!")

    # authorise user. if user is SA, user is able to do everything.
    # if wgroup admin, user is allowed to set group usage for a
    # plugin/project combination. the wgroup admin is not allowed to set the
    # default group! A more previse check happens below, just before executing
    # the database voodoo.
    is_sa = user.uid == ccd.superadmin.uid
    if not is_sa:
        # the SA has now workgroup, so this branch is only taken, if the user
        # is not a SA
        is_wgroup_admin = wg.is_allowed(db, user=user, access=ccddb.ACCESS_ADD)
    else:
        is_wgroup_admin = False

    if not (is_sa or is_wgroup_admin):
        raise PermissionDenied(user.name)

    # check group
    if not grpid in ccd.connection_groups:
        raise InputError("Invalid group id to use (%s)!" % grpid)

    # set default group to redirect plugins' traffic through. the default
    # group is only set if the user is SA and no plg_id and no
    # project id is given.
    if (is_sa and not plg_id and not pid):
        group = ccd.connection_groups[grpid]
        group.set_default(db)
        old_default_group = ProxyChainSocket._current_connection_group
        ProxyChainSocket._current_connection_group = group
        old_default_group.default = False


    # if the user is wgroup admin, and the payload is ok, set group to use for
    # plugin-project combination
    elif (is_wgroup_admin or is_sa) and plg_id and pid:

        # check whether project id is valid
        try:
            proj = Project.by_pid(db, pid)
        except Exception as e:
            logger.error("Failed to get project with pid %s:'%s'", pid, e)

        # user must have corresponding permissions for the project
        if not (is_sa or
                proj.creator == user.uid or
                proj.owner == user.uid or
                proj.is_allowed(db, user, ccddb.ACCESS_ADD) or
                proj.is_allowed(db, user, ccddb.ACCESS_EXEC)):
            raise PermissionDenied(user.name)

        # check whether plugin id is valid
        if not proj.has_plugin(db, plg_id):
            raise NotFoundError("Plugin %s is not in project %s!" %
                                (plg_id, pid))

        # add connection group-plugin-project-relation. If already plugin
        # project combination set, remove it and set new one
        try:
            ccddb.add_group_to_projectplugin(db, grpid, plg_id, pid)
        except ccddb.AlreadyExistingError:
            ccddb.del_group_from_projectplugin(db, plg_id, pid)
            ccddb.add_group_to_projectplugin(db, grpid, plg_id, pid)

    # invalid request
    else:
        raise PermissionDenied(user.name)

def _update_connection_groups(ccd):
    # get conn groups from database
    all_groups = ccddb.get_all_conngroups(ccd._db.conn)

    # update cache and serialise proxy
    pld = []
    for grpid, _ in all_groups.items():
        group = return_group_by_id(ccd, grpid)
        pld.append(group.as_dict())

    return pld

def flush(ccd, sid, pld):
    """
    stores a connection group's chains

    input:
        pld     payload of the ccd protocol message

    """

    # get user
    user, _ = ccd.get_user_and_workgroup(sid)

    # authorise user.
    if (not user.uid == ccd.superadmin.uid):
        raise PermissionDenied(user.name)

    # parse payload
    try:
        grpid = pld["grpid"]
        chains = pld["chains"]
    except KeyError:
        raise InputError("Invalid json format!")

    # resetting
    try:
        group = ccd.connection_groups[grpid]
        old_chains = copy(group.get_chains())
        group.reset()
    except KeyError:
        raise InputError("No proxy chain with id %s" % grpid)

    # add new
    try:
        for new in chains:
            chain = return_chain_by_id(ccd, new["pcid"])

            logger.debug("chain pcid %s, given %s", chain.pcid, new["pcid"])
            group.add_chain(ccd._db.conn, chain, new["prio"])
    except KeyError:
        raise InputError("Invalid json format of chains!")
    except Exception as e:
        raise InputError("Error while adding proxy to chain:'%s'" % e)

    logger.debug("new chain :%s", [c.pcid for c in group.get_chains()])

    # for every old proxy that is not in new chain, delete it
    for chain in old_chains:
        if not group.has_chain(chain):
            ccddb.del_chain_from_group(ccd._db.conn, group.grpid, chain.pcid)

