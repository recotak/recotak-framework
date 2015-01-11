"""
Test whether the ccd session stage verification is working properly. Stage
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
one requires a valid session id. Stage two requires a valid request id.
Stage three requires a valid project.

"""
from database.ccdErrors import SessionError
from connection.ccdSession import verify_stages
from unittests.ccdBase import create_workgroup
from connection.ccdSession import stage_three
from unittests.ccdBase import create_project
from connection.ccdSession import stage_one
from connection.ccdSession import stage_two
from connection.ccdSession import Session
from unittests.ccdBase import create_user
from unittests.ccdBase import CcdTest
from connection import ccdlib
import unittest

class SessionStageOne(CcdTest):
    """
    Session one requires a valid session id in order to be passed. If there is
    no valid session id, the user is only allowed to login (in order to get
    one).

    """

    def test_valid_sid(self):
        """ verify that stage one is passed with a valid session id. """
        valid_sid = self.session.sid
        self.assertTrue(stage_one(self.ccd, valid_sid))

    def test_invalid_sid(self):
        """ verify that stage one is not passed with invalid session id  """
        invalid_sid = "z"
        self.assertFalse(stage_one(self.ccd, invalid_sid))

    def test_invalid_sid_nonlogin(self):
        """
        it is allowed to have no valid sid, if the packet operation
        is OP_LOGIN. So having a non-OP_LOGIN packet must raise an exception

        """
        invalid_sid = "z"
        operations = [op for op in dir(ccdlib)
                     if op.startswith("OP_") and not op == "OP_PLUGIN"]

        # also test some values that are not part of the protocol
        # specification
        operations.extend([-1, 999999])

        for op in operations:
            print("testing %s" % op)
            self.assertRaisesRegexp(SessionError,
                                    "Invalid Operation in stage 1!",
                                    verify_stages,
                                    self.ccd,
                                    invalid_sid,
                                    None, # request id does not matter
                                    op
                                   )

    def test_invalid_sid_login(self):
        """
        it is allowed to have no valid sid, if the packet operation
        is OP_LOGIN. So providing OP_LOGIN packet must must work properly

        """
        invalid_sid = "z"

        res = verify_stages(self.ccd,
                            invalid_sid,
                            None, # request id does not matter
                            ccdlib.OP_LOGIN
                            )

        self.assertTrue(res)

class SessionStageTwo(CcdTest):
    """
    Session two requires stage one to be passed and a valid request id in
    order to be passed. If no valid requist id is present, the user is only
    allowed to request a request id or to pass plugin input.

    """

    def test_valid_rid(self):
        """ verify the stage is passed with a valid request id """
        valid_sid = self.session.sid
        valid_session = self.session
        valid_rid = valid_session.assign_rid()

        self.assertTrue(stage_two(self.ccd, valid_sid, valid_rid))

    def test_invalid_rid_getrid(self):
        """
        if no valid request id is passed, the user is allowed to use
        OP_GETRID. this operation is used to get a request id..

        """
        invalid_rid = "z"
        valid_sid = self.session.sid

        res = verify_stages(self.ccd,
                            valid_sid,
                            invalid_rid,
                            ccdlib.OP_GETRID)

        self.assertTrue(res)

    def test_invalid_rid_plugin(self):
        """
        if no valid request id is passed, the user is allowed to use
        OP_PLUGIN. this operation is used to pass data to the plugin.

        """
        invalid_rid = "z"
        valid_sid = self.session.sid

        res = verify_stages(self.ccd,
                            valid_sid,
                            invalid_rid,
                            ccdlib.OP_PLUGIN)

        self.assertTrue(res)

    def test_invalid_rid(self):
        """
        if no valid request id is provided and the command neither is OP_GETRID
        nor OP_PLUGIN, stage two must fail. In other words: if an invalid rid
        is provided and test_invalid_rid_getrid AND test_invalid_rid_plugin
        both fail, this stage must fail.

        """
        invalid_rid = "z"
        valid_sid = self.session.sid
        operations = [op for op in dir(ccdlib)
                     if op.startswith("OP_") and not op in ("OP_PLUGIN",
                                                            "OP_GETRID")]

        # also test some values that are not part of the protocol
        # specification
        operations.extend([-1, 999999])

        for op in operations:
            print("testing %s" % op)
            self.assertRaisesRegexp(SessionError,
                                    "Invalid Operation in stage 2!",
                                    verify_stages,
                                    self.ccd,
                                    valid_sid,
                                    invalid_rid,
                                    op
                                   )

class SessionStageThree(CcdTest):
    """
    Session three requires stage one and stage two to be passed and
    a valid project needs to be set in order to be passed. The superadmin is
    passes stage three even w/o a project set.
    However, if the user has no project selected and is not allowed to create
    one (due to missing permission, user can be seen as "workgroup admin"),
    stage three fails.

    """

    def test_project_set(self):
        """
        verify the stage is passed with a valid project set and the user is not
        a superadmin

        """
        db = self.ccd._db.conn

        user = create_user(db, "my non admin user")
        wg = create_workgroup(db, "wgroup", user.uid, 3) # role id 3 = normal
                                                          # user, no wgroup admin
        proj = create_project(db, "my project", user, 2) # project admin, role
                                                          # does not matter in
                                                          # this test

        try:
           # get a session for the non-admin
            valid_session = self.ccd._assign_user_a_session(user)
            valid_sid = valid_session.sid
            valid_session.setproject(db, proj)

            self.assertTrue(stage_three(self.ccd, valid_sid))
        finally:
            if valid_session:
                valid_session.unsetproject(db, proj)

            user.delete(db)
            wg.delete(db)
            proj.delete(db)

    def test_superadmin(self):
        """
        verify the stage is passed as superadmin even w/o having a project
        set

        """
        valid_session = self.session
        valid_sid = valid_session.sid

        self.assertTrue(stage_three(self.ccd, valid_sid))

    def test_no_project_but_write_access(self):
        """
        if no project is set, the user passes the stage if he is allowed to
        create one

        """
        db = self.ccd._db.conn
        user = create_user(db, "my non admin user")
        wg = create_workgroup(db, "wgroup", user.uid, 2) # role id 2 = wgroup
                                                          # admin with write
                                                          # access
        try:
            valid_session = self.ccd._assign_user_a_session(user)
            valid_sid = valid_session.sid

            self.assertTrue(stage_three(self.ccd, valid_sid))
        finally:
            user.delete(db)
            wg.delete(db)

    def _test_non_admin_operation(self, op):
        """
        gets an operation an test for proper executing for a workgroup user
        (non-workgroup admin). asserts True as result.

        """
        db = self.ccd._db.conn
        user = create_user(db, "my non admin user")
        wg = create_workgroup(db, "wgroup", user.uid, 3) # role id 3 = normal
                                                          # user, no wgroup admin
        try:
            valid_session = self.ccd._assign_user_a_session(user)
            valid_sid = valid_session.sid
            valid_rid = valid_session.assign_rid()

            res = verify_stages(self.ccd,
                                valid_sid,
                                valid_rid,
                                op)
            self.assertTrue(res)

        finally:
            user.delete(db)
            wg.delete(db)


    def test_no_project_logout(self):
        """"
        if no project set and no write access is set, the stage is passed if
        the OP is OP_LOGOUT

        """
        self._test_non_admin_operation(ccdlib.OP_LOGOUT)

    def test_no_project_setproj(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_SETPROJ

        """
        self._test_non_admin_operation(ccdlib.OP_SETPROJ)

    def test_no_project_showproj(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_SHOWPROJ

        """
        self._test_non_admin_operation(ccdlib.OP_SHOWPROJ)

    def test_no_project_newproj(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_NEWPROJ

        """
        self._test_non_admin_operation(ccdlib.OP_NEWPROJ)

    def test_no_project_delproj(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_DELPROJ

        """
        self._test_non_admin_operation(ccdlib.OP_DELPROJ)

    def test_no_project_updateproj(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_UPDATEROJ

        """
        self._test_non_admin_operation(ccdlib.OP_UPDATEPROJ)

    def test_no_project_addprojmember(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_ADDPROJMEMBER

        """
        self._test_non_admin_operation(ccdlib.OP_ADDPROJMEMBER)

    def test_no_project_delprojmember(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_DELPROJMEMBER

        """
        self._test_non_admin_operation(ccdlib.OP_DELPROJMEMBER)

    def test_no_project_addprojplg(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_ADDPROJPLG

        """
        self._test_non_admin_operation(ccdlib.OP_ADDPROJPLG)

    def test_no_project_delprojplg(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_DELPROJPLG

        """
        self._test_non_admin_operation(ccdlib.OP_DELPROJPLG)

    def test_no_project_showwgroup(self):
        """
        if no project set and no write access is set, the stage is passed if
        the OP is OP_SHOWWGROUP

        """
        self._test_non_admin_operation(ccdlib.OP_DELPROJPLG)

    def test_no_project(self):
        """
        if no project is set, the user has no write access to create one and
        the operations is non of the allowed ones, stage three must fail

        """
        db = self.ccd._db.conn
        user = create_user(db, "my non admin user")
        wg = create_workgroup(db, "wgroup", user.uid, 3) # role id 3 = normal
                                                          # user, no wgroup admin
        try:
            valid_session = self.ccd._assign_user_a_session(user)
            valid_sid = valid_session.sid

            operations = [
                     op for op in dir(ccdlib)
                     if op.startswith("OP_") and not op in ("OP_LOGOUT",
                                                            "OP_SETPROJ",
                                                            "OP_SHOWPROJ",
                                                            "OP_NEWPROJ",
                                                            "OP_DELPROJ",
                                                            "OP_UPDATEPROJ",
                                                            "OP_ADDPROJMEMBER",
                                                            "OP_DELPROJMEMBER",
                                                            "OP_ADDPROJPLG",
                                                            "OP_DELPROJPLG",
                                                            "OP_SHOWWGROUP")]

            # also test some values that are not part of the protocol
            # specification
            operations.extend([-1, 999999])

            for op in operations:
                print("testing %s" % op)
                valid_rid = valid_session.assign_rid()

                self.assertRaisesRegexp(SessionError,
                                        "Invalid Operation in stage 3!",
                                        verify_stages,
                                        self.ccd,
                                        valid_sid,
                                        valid_rid,
                                        op
                                       )

        finally:
            user.delete(db)
            wg.delete(db)

if __name__ == '__main__':
    unittest.main()
