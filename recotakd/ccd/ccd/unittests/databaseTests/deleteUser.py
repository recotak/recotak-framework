"""
This unit test verifies proper handling of user deletion.
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
from database.ccdErrors import PermissionDenied
from database.ccdErrors import InvalidSessionID
from connection.ccdCrypto import getRandomBytes
from unittests.ccdBase import create_workgroup
from database.ccdErrors import NotFoundError
from unittests.ccdBase import create_user
from database.ccdErrors import InputError
from database.ccddb import add_user2user
from database.ccdUser import delete_user
from unittests.ccdBase import CcdTest
from database.ccdUser import new_user
import unittest
import random


class DeleteUser(CcdTest):
    """
    Test checks for user deletion functionality that is provided by the
    database.ccdUser module. A special focus is on input validation, hence
    this test neither explicitly tests the database.ccddb.delete_user(..).
    Instead it calls database.ccdUser.delete_user(..) which is called in
    case of an OP_DELUSER operation.

    """

    def test_superadmin(self):
        """ verify that the superadmin is able to delete users"""
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        add_pld = {"name": name,
                     "mail": "mail@mynewuser",
                     "password": "mynewuser"}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        # second, we delete the user
        del_pld = {"uid": uid}
        self.assertIsNone(delete_user(self.ccd, valid_sid, del_pld))

    def test_delpermission(self):
        """
        verify that a user with ACCESS_DEL in user2user table is able to
        delete users. note: this user must not be the superadmin.

        """
        db = self.ccd._db.conn

        # create a user and a workgroup. give the user ACCESS_ADD in
        # user2users table
        user = create_user(db, str(random.randrange(1000,9999)))
        wg = create_workgroup(db, "newworkgroup", user.uid, 2)
        add_user2user(db, user.uid, 2) # ACCESS_DEL
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # create user
        name = str(getRandomBytes())
        valid_pld = {"name": name,
                     "mail": "mail@mynewuser",
                     "password": "mynewuser"}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, valid_pld)
        self.assertIsInstance(uid, int)

        # second, we delete that user
        del_pld = {"uid": uid}
        self.assertIsNone(delete_user(self.ccd, valid_sid, del_pld))

        user.delete(db)
        wg.delete(db)

    def test_uid_noint(self):
        """ verify that a non-int uid raises an InputError """
        valid_sid = self.session.sid
        invalid_pld = {"uid": "foobar"}
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                delete_user,
                                self.ccd,
                                valid_sid,
                                invalid_pld)

    def test_permission_denied(self):
        """
        if user is no superadmin and has no ACCESS_DEL, a permissionDenied
        exception is raised

        """
        db = self.ccd._db.conn

        # create a user and a workgroup. give the user ACCESS_ADD in
        # user2users table
        user = create_user(db, str(random.randrange(1000,9999)))
        wg = create_workgroup(db, "newworkgroup", user.uid, 3)
        add_user2user(db, user.uid, 4) # NO ACCESS_DEL
        valid_sid = self.ccd._assign_user_a_session(user).sid

        invalid_pld = {"uid": "foo"}
        try:
            self.assertRaises(PermissionDenied,
                              delete_user,
                              self.ccd,
                              valid_sid,
                              invalid_pld)
        finally:
            user.delete(db)
            wg.delete(db)

    def test_non_existing_user(self):
        """ deleting a non existing user should raise a NotFoundError  """
        valid_sid = self.session.sid
        invalid_pld = {"uid": -10}
        self.assertRaises(NotFoundError,
                          delete_user,
                          self.ccd,
                          valid_sid,
                          invalid_pld)

    def test_non_dict_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid

        payload = "payload"
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                delete_user,
                                self.ccd,
                                valid_sid,
                                payload)


    def test_missing_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid
        payload = None
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                delete_user,
                                self.ccd,
                                valid_sid,
                                payload)

    def test_invalid_sid(self):
        """ withough valid session id an error must be raised """
        payload = {"uid": 1}
        invalid_sid = "AAA"
        self.assertRaises(InvalidSessionID,
                          delete_user,
                          self.ccd,
                          invalid_sid,
                          payload)

    def test_deleting_superadmin(self):
        """ deleting the superadmin must raise an error """
        payload = {"uid": 1}
        valid_sid = self.session.sid
        self.assertRaisesRegexp(InputError,
                                "Superadmin cannot be deleted!",
                                delete_user,
                                self.ccd,
                                valid_sid,
                                payload)

if __name__ == '__main__':
    unittest.main()
