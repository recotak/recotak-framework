"""
This unit test verifies proper showing of users.
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

"""
from database.ccddb import __table_projects as tbl_projects
from database.ccddb import __table_users as tbl_users
from database.ccdErrors import PermissionDenied
from database.ccdErrors import InvalidSessionID
from connection.ccdCrypto import getRandomBytes
from unittests.ccdBase import create_workgroup
from database.ccdErrors import NotFoundError
from unittests.ccdBase import create_project
from unittests.ccdBase import create_user
from database.ccdErrors import InputError
from database.ccddb import add_user2user
from database.ccdProject import Project
from database.ccdUser import show_user
from unittests.ccdBase import CcdTest
import sqlalchemy as sql
import unittest

class ShowUser(CcdTest):
    """
    Test verifies OP_SHOWUSER functionality by testing
    database.ccdUser.show_user().

    """

    def assertUsersInProject(self, res, users):
        """
        checkes whether all users are returned via res

        input:
            res     resolution of show_user
            users   users that must be returned

        """
        self.assertEqual(len(users), len(res))

        for user in users:
            for entry in res:
                if user.uid == entry["uid"]:
                    res.remove(entry)
                    break
            else:
                # user not found in show_user result
                raise AssertionError("User(uid:%d) not found in show_user "
                                     "result!" % user.uid)


    def assertEqualResolution(self, dictionary, res):
        """
        compares the dictonary (that is returned by show_user) with the database
        records (res)

        input:
            dictionary  result of show_user:

                            {'mail': u'mail@mynewuser',
                             'name': u'a9957914d1487fa3a98cdc0955f69c69',
                             'uid': 769}

            res         result of db request:

                            (254, # uid
                            u'mynewuser2471', # name
                            u'mail@mynewuser', # mail
                            datetime.datetime(2014, 7, 30, 10, 9, 34, 859595),  # created
                            False, # deleted
                            u'' # description)

        """
        self.assertEqual(len(dictionary), len(res))

        for entry in res:
            uid = entry[0]
            name = entry[1]
            mail = entry[2]
            for d in dictionary:
                if (d["uid"] == uid and
                    d["name"] == name and
                    d["mail"] == mail):
                    dictionary.remove(d)
                    break
            else:
                # db uid not found it show_user result
                raise AssertionError("Uid(%d) not found in show_user result!" % uid)

    def test_non_dict_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid
        payload = "foobar"
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                show_user,
                                self.ccd,
                                valid_sid,
                                payload)

    def test_missing_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid
        payload = None
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                show_user,
                                self.ccd,
                                valid_sid,
                                payload)


    def test_invalid_sid(self):
        """ withough valid session id an error must be raised """
        invalid_sid = "foobar"
        payload = {"uid":None}
        self.assertRaises(InvalidSessionID,
                          show_user,
                          self.ccd,
                          invalid_sid,
                          payload)

    def test_single_user_itself(self):
        """
        showing information of the user itself should work. the user is no
        superadmin.

        """
        db = self.ccd._db.conn
        user = create_user(db, str(getRandomBytes()))
        wg = create_workgroup(db, "newworkgroup", user.uid, 3)
        valid_sid = self.ccd._assign_user_a_session(user).sid
        payload = {"uid": user.uid}

        res = show_user(self.ccd, valid_sid, payload)[0]
        try:
            self.assertEqual(res["uid"], user.uid)
            self.assertEqual(res["name"], user.name)
            self.assertEqual(res["mail"], user.mail)
            self.assertEqual(res["description"], user.description)
        finally:
            user.delete(db)
            wg.delete(db)

    def test_single_user_nonint(self):
        """
        requesting a user with a uid that is not an int must raise an
        InputError

        """
        db = self.ccd._db.conn
        valid_sid = self.session.sid
        payload = {"uid": "foobar"}

        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                show_user,
                                self.ccd,
                                valid_sid,
                                payload)

    def test_single_user_nonsuperadmin(self):
        """
        a user is allowed to receive information of an arbitrary user, if he
        has ACCESS_READ in the user2user table.

        """
        db = self.ccd._db.conn

        # user that requests the information. needs ACCESS_READ
        user = create_user(db, str(getRandomBytes()))
        wg = create_workgroup(db, "newworkgroup", user.uid, 3)
        add_user2user(db, user.uid, 3) # ACCESS_READ
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # user to request for information
        user_to_request = create_user(db, str(getRandomBytes()))
        create_workgroup(db, "newworkgroup", user_to_request.uid, 3)

        payload = {"uid": user_to_request.uid}

        res = show_user(self.ccd, valid_sid, payload)[0]
        try:
            self.assertEqual(res["uid"], user_to_request.uid)
            self.assertEqual(res["name"], user_to_request.name)
            self.assertEqual(res["mail"], user_to_request.mail)
            self.assertEqual(res["description"], user_to_request.description)
        finally:
            user.delete(db)
            user_to_request.delete(db)
            wg.delete(db)

    def test_single_user_superadmin(self):
        """
        the superadmin is allowed to receive information of an existing user.

        """
        db = self.ccd._db.conn

        # user that requests the information. needs ACCESS_READ
        valid_sid = self.session.sid

        # user to request for information
        user_to_request = create_user(db, str(getRandomBytes()))
        wg = create_workgroup(db, "newworkgroup", user_to_request.uid, 3)

        payload = {"uid": user_to_request.uid}

        res = show_user(self.ccd, valid_sid, payload)[0]

        try:
            self.assertEqual(res["uid"], user_to_request.uid)
            self.assertEqual(res["name"], user_to_request.name)
            self.assertEqual(res["mail"], user_to_request.mail)
            self.assertEqual(res["description"], user_to_request.description)
        finally:
            user_to_request.delete(db)
            wg.delete(db)

    def test_single_user_nonexisting(self):
        """
        requesting a non-existing user should fail

        """
        db = self.ccd._db.conn

        # user that requests the information. needs ACCESS_READ
        valid_sid = self.session.sid

        # user to request for information
        user_to_request = create_user(db, str(getRandomBytes()))
        wg = create_workgroup(db, "newworkgroup", user_to_request.uid, 3)

        payload = {"uid": -1}

        try:
            self.assertRaises(NotFoundError,
                              show_user,
                              self.ccd,
                              valid_sid,
                              payload)
        finally:
            user_to_request.delete(db)
            wg.delete(db)

    def test_single_user_permission_denied(self):
        """
        a user that is not superadmin and has no ACCESS_READ must fail reading
        user information (of user that are not the user ifself). it must be
        raised a permission denied exceperion. Note. every role includes
        ACCESS_READ by default, hence the user that requests the information
        must no be in user2user table.

        """
        db = self.ccd._db.conn

        # user that requests the information. needs ACCESS_READ
        user = create_user(db, str(getRandomBytes()))
        wg = create_workgroup(db, "newworkgroup", user.uid, 3)
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # user to request for information
        user_to_request = create_user(db, str(getRandomBytes()))
        create_workgroup(db, "newworkgroup", user_to_request.uid, 3)

        payload = {"uid": user_to_request.uid}

        try:
            self.assertRaises(PermissionDenied,
                              show_user,
                              self.ccd,
                              valid_sid,
                              payload)
        finally:
            user.delete(db)
            user_to_request.delete(db)
            wg.delete(db)

    def test_all_user_nonsuperadmin(self):
        """
        a user is allowed to receive information of a user, if he has
        ACCESS_READ in the user2user table.

        """
        db = self.ccd._db.conn

        # user that requests the information. needs ACCESS_READ
        user = create_user(db, str(getRandomBytes()))
        wg = create_workgroup(db, "newworkgroup", user.uid, 3)
        add_user2user(db, user.uid, 3) # ACCESS_READ
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # set None to request all users
        payload = {"uid": None}

        res = show_user(self.ccd, valid_sid, payload)

        meta, conn = db
        tbl = meta.tables[tbl_users]
        with conn.begin():
            sel = tbl.select().where(tbl.c.deleted==False)
            users = conn.execute(sel).fetchall()

        try:
            self.assertEqualResolution(res, users)
        finally:
            user.delete(db)
            wg.delete(db)

    def test_all_user_superadmin(self):
        """
        the superadmin is allowed to receive information of all existing user.

        """
        db = self.ccd._db.conn

        # user that requests the information. needs ACCESS_READ
        valid_sid = self.session.sid

        # set None to request all users
        payload = {"uid": None}

        res = show_user(self.ccd, valid_sid, payload)

        meta, conn = db
        tbl = meta.tables[tbl_users]
        with conn.begin():
            sel = tbl.select().where(tbl.c.deleted==False)
            users = conn.execute(sel).fetchall()

        self.assertEqualResolution(res, users)

    def test_all_user_permission_denied(self):
        """
        a user that is not superadmin and has no ACCESS_READ must fail reading
        user information (of user that are not the user ifself). it must be
        raised a permission denied exception

        """
        db = self.ccd._db.conn

        # user that requests the information. needs ACCESS_READ
        user = create_user(db, str(getRandomBytes()))
        wg = create_workgroup(db, "newworkgroup", user.uid, 3)
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # user to request for information
        user_to_request = create_user(db, str(getRandomBytes()))
        create_workgroup(db, "newworkgroup", user_to_request.uid, 3)

        # set None to request all users
        payload = {"uid": None}

        try:
            self.assertRaises(PermissionDenied,
                              show_user,
                              self.ccd,
                              valid_sid,
                              payload)
        finally:
            user.delete(db)
            user_to_request.delete(db)
            wg.delete(db)

    def test_project_user_superadmin(self):
        """
        using pid instead of uid in payload should return user in
        corresponding project

        """
        db = self.ccd._db.conn

        # user that requests the information. needs ACCESS_READ
        valid_sid = self.session.sid

        # create users
        users = []
        for i in range(10):
            user = create_user(db, str(getRandomBytes()))
            create_workgroup(db, "newworkgroup", user.uid, 3)
            users.append(user)

        # add users to projects
        for u in users:
            proj = create_project(db, "test_project_user_superadmin", u, 3)

        # set None to request all users
        payload = {"pid": proj.pid}

        res = show_user(self.ccd, valid_sid, payload)
        try:
            self.assertUsersInProject(res, users)
        finally:
            proj.delete(db)
            for u in users:
                u.delete(db)


    def test_project_user_creator(self):
        """
        the project creator is able to request the users within its project

        """
        db = self.ccd._db.conn
        users = []

        # user that requests the information is creator of the new project
        owner = create_user(db, "owner_%s" % str(getRandomBytes()))
        create_workgroup(db, "newworkgroup", owner.uid, 3)

        creator = create_user(db, "creator_%s" % str(getRandomBytes()))
        create_workgroup(db, "newworkgroup", creator.uid, 3)
        proj = Project.create_fromname(
                        db,
                        "test_project_user_creator",
                        creator, # creator
                        owner, # owner
                        1, # type id
                        "my project" #description
                        )

        valid_sid = self.ccd._assign_user_a_session(creator).sid

        # create users
        for i in range(10):
            u = create_user(db, str(getRandomBytes()))
            create_workgroup(db, "newworkgroup", u.uid, 3)
            users.append(u)

        # add users to project
        for u in users:
            create_project(db, "test_project_user_creator", u, 3)

        # set None to request all users
        payload = {"pid": proj.pid}

        res = show_user(self.ccd, valid_sid, payload)
        try:
            self.assertUsersInProject(res, users)
        finally:
            proj.delete(db)
            for u in users:
               u.delete(db)
            creator.delete(db)
            owner.delete(db)

    def test_project_user_owner(self):
        """
        the project owner is able to request the users within its project

        """
        db = self.ccd._db.conn
        users = []

        # user that requests the information is creator of the new project
        owner = create_user(db, "owner_%s" % str(getRandomBytes()))
        create_workgroup(db, "newworkgroup", owner.uid, 3)

        creator = create_user(db, "creator_%s" % str(getRandomBytes()))
        create_workgroup(db, "newworkgroup", creator.uid, 3)
        proj = Project.create_fromname(
                        db,
                        "test_project_user_creator",
                        creator, # creator
                        owner, # owner
                        1, # type id
                        "my project" #description
                        )

        valid_sid = self.ccd._assign_user_a_session(owner).sid

        # create users
        for i in range(10):
            u = create_user(db, str(getRandomBytes()))
            create_workgroup(db, "newworkgroup", u.uid, 3)
            users.append(u)

        # add users to project
        for u in users:
            create_project(db, "test_project_user_creator", u, 3)

        # set None to request all users
        payload = {"pid": proj.pid}

        res = show_user(self.ccd, valid_sid, payload)
        try:
            self.assertUsersInProject(res, users)
        finally:
            proj.delete(db)
            for u in users:
               u.delete(db)
            creator.delete(db)
            owner.delete(db)

    def test_project_user_readaccess(self):
        """
        a user that has read access within the project, is able to get the
        users joining the project

        """

    def test_project_user_permission_denied(self):
        """
        a user that is neither superadmin, project creator, owner nor has
        ACCESS_READ is not allowed to get the users of the project. a
        permission denied must be raised

        """

    def test_project_user_nonint(self):
        """
        if the project id is a non int a InputError must be raised

        """

    def test_project_user_nonexisting(self):
        """
        requesting users of a non-existing project must fail

        """

if __name__ == '__main__':
    unittest.main()
