"""
This unit test verifies proper handling of user password update.
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
from unittests.ccdBase import create_workgroup
from database.ccdUser import update_user_passwd
from database.ccdErrors import InvalidSessionID
from connection.ccdCrypto import getRandomBytes
from database.ccdErrors import InputError
from unittests.ccdBase import create_user
from database.ccddb import add_user2user
from database.ccddb import MAX_LEN_PASSWORD
from unittests.ccdBase import CcdTest
from database.ccdUser import new_user
from database.ccddb import getusers
import unittest
import random

class UpdateUserPwd(CcdTest):
    """
    Test checks for user password update functionality that is provided by the
    database.ccdUser module. It calls database.ccdUser.update_user_passwd(..)
    which is called in case of an OP_UPDATEUSERPWD operation.

    """

    def test_superadmin(self):
        """ verify that the superadmin is able to update user's password """
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        password = "mypassword"
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": password}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        # second, we update this user
        password2 = "mypassword2"
        update_pld = {"uid": uid,
                      "old": password,
                      "new": password2
                     }
        self.assertIsNone(update_user_passwd(self.ccd, valid_sid, update_pld))

        # third, we verify that the changed data is written to database
        users = getusers(self.ccd._db.conn, name, password2)
        self.assertEqual(len(users), 1)

    def test_addpermission(self):
        """
        verify that a user with ACCESS_ADD in user2user table is able to
        update user's passwords. note: this user must not be the superadmin.

        """
        db = self.ccd._db.conn

        # create a user and a workgroup. give the user ACCESS_ADD in
        # user2users table
        user = create_user(db, str(random.randrange(1000, 9999)))
        create_workgroup(db, "newworkgroup", user.uid, 2)
        add_user2user(db, user.uid, 2) # ACCESS_ADD
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # create user
        name = str(getRandomBytes())
        password = "mypassword"
        valid_pld = {"name": name,
                     "mail": "mail@mynewuser",
                     "password": password}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, valid_pld)
        self.assertIsInstance(uid, int)

        # second, we update this user
        password2 = "mypassword2"
        update_pld = {"uid": uid,
                      "old": password,
                      "new": password2
                     }
        self.assertIsNone(update_user_passwd(self.ccd, valid_sid, update_pld))

        # third, we verify that the changed data is written to database
        users = getusers(self.ccd._db.conn, name, password2)
        self.assertEqual(len(users), 1)

    def test_permission_denied(self):
        """
        verify that a non-superdmin user, who has no ACCESS_WRITE is not
        allowed to modify a user

        """
        db = self.ccd._db.conn

        # create a user and a workgroup. give the user ACCESS_ADD in
        # user2users table
        user = create_user(db, str(random.randrange(1000, 9999)))
        wg = create_workgroup(db, "newworkgroup", user.uid, 2)
        add_user2user(db, user.uid, 3) # No ACCESS_WRITE

        # create user
        name = str(getRandomBytes())
        password = "mypassword"
        valid_pld = {"name": name,
                     "mail": "mail@mynewuser",
                     "password": password}

        # first we create that new user with SA session
        uid = new_user(self.ccd, self.session.sid, valid_pld)
        self.assertIsInstance(uid, int)

        # second, we update this user with a user who has now allowance to do
        # so
        password2 = "mypassword2"
        update_pld = {"uid": uid,
                      "old": password,
                      "new": password2
                     }
        valid_sid = self.ccd._assign_user_a_session(user).sid
        self.assertRaises(PermissionDenied,
                          update_user_passwd,
                          self.ccd,
                          valid_sid,
                          update_pld)

    def test_uid_noint(self):
        """ verify that a non-int uid raises an InputError """
        valid_sid = self.session.sid

        # try to update a user with an illegal uid
        update_pld = {"uid": "foobar",
                      "old": "password",
                      "new": "password2"
                     }
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                update_user_passwd,
                                self.ccd,
                                valid_sid,
                                update_pld)

    def test_non_existing_user(self):
        """ deleting a non existing user should raise a NotFoundError """
        valid_sid = self.session.sid

        # try to update a user with an illegal uid
        update_pld = {"uid": -1,
                      "old": "password",
                      "new": "password2"
                     }
        self.assertRaisesRegexp(InputError,
                                "User or password wrong!",
                                update_user_passwd,
                                self.ccd,
                                valid_sid,
                                update_pld)

    def test_maxlen_oldpassword(self):
        """
        verify that an InputError is thrown in case of too long old
        password

        """
        valid_sid = self.session.sid

        update_pld = {"uid": -1,
                      "old": "A" * (MAX_LEN_PASSWORD+1),
                      "new": "password2"
                     }
        self.assertRaisesRegexp(InputError,
                                "Old password exceeds limit",
                                update_user_passwd,
                                self.ccd,
                                valid_sid,
                                update_pld)

    def test_maxlen_newpassword(self):
        """
        verify that an InputError is thrown in case of too long new
        password

        """
        valid_sid = self.session.sid

        update_pld = {"uid": -1,
                      "old": "password",
                      "new": "A" * (MAX_LEN_PASSWORD+1)
                     }
        self.assertRaisesRegexp(InputError,
                                "New password exceeds limit",
                                update_user_passwd,
                                self.ccd,
                                valid_sid,
                                update_pld)

    def test_missing_oldpassword(self):
        """ without providing an old password an InputError must be raised """
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        password = "mypassword"
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": password}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        # second, we update this user
        password2 = "mynewpassword2"
        update_pld = {"uid": uid,
                      "new": password2
                     }
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                update_user_passwd,
                                self.ccd,
                                valid_sid,
                                update_pld)

    def test_missing_newpassword(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        password = "mypassword"
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": password}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        # second, we update this user
        update_pld = {"uid": uid,
                      "old": password
                     }
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                update_user_passwd,
                                self.ccd,
                                valid_sid,
                                update_pld)

    def test_non_dict_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid

        payload = "payload"
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                update_user_passwd,
                                self.ccd,
                                valid_sid,
                                payload)


    def test_missing_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid
        payload = None
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                update_user_passwd,
                                self.ccd,
                                valid_sid,
                                payload)

    def test_invalid_sid(self):
        """ withough valid session id an error must be raised """
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        password = "mypassword"
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": password}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        # second, we update this user with an invalid sessin id
        password2 = "mypassword2"
        update_pld = {"uid": uid,
                      "old": password,
                      "new": password2
                     }
        invalid_sid = "AAA"
        self.assertRaises(InvalidSessionID,
                          update_user_passwd,
                          self.ccd,
                          invalid_sid,
                          update_pld)

    def test_empty_newpassword(self):
        """ verify that it's possible to set empty passwords """
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        password = "mypassword"
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": password}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        # second, we update this user
        password2 = ""
        update_pld = {"uid": uid,
                      "old": password,
                      "new": password2
                     }
        self.assertIsNone(update_user_passwd(self.ccd, valid_sid, update_pld))

        # third, we verify that the changed data is written to database
        users = getusers(self.ccd._db.conn, name, password2)
        self.assertEqual(len(users), 1)

if __name__ == '__main__':
    unittest.main()
