"""
This unit test verifies proper handling of user creation.
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
from database.ccddb import MAX_LEN_PASSWORD
from unittests.ccdBase import create_user
from database.ccdErrors import InputError
from database.ccddb import add_user2user
from database.ccddb import del_user2user
from database.ccddb import MAX_LEN_NAME
from database.ccddb import MAX_LEN_MAIL
from database.ccddb import MAX_LEN_DESC
from unittests.ccdBase import CcdTest
from database.ccdUser import new_user
from database.ccdUser import User
import unittest

class CreateUser(CcdTest):
    """
    Test checks for user creation functionality that is provided by the
    database.ccdUser module. A special focus is on input validation, hence
    this test neither explicitly tests the database.ccddb.create_user(..) nor
    the User.by_name/.byuid/.create_fromname/.foobar. Instead it calls
    atabase.ccdUser.new_user(..) which is called in case of an OP_NEWUSER
    operation.

    """

    def assertExceedsLimit(self, pld, to_exceed):
        """
        tries to create a new user and checks for a InputError with a
        message '* exceeds limit'

        """
        valid_sid = self.session.sid

        # first we create that new user
        self.assertRaisesRegexp(InputError,
                                "%s exceeds limit" % to_exceed,
                                new_user,
                                self.ccd,
                                valid_sid,
                                pld)

    def assertInvalidPayload(self, pld):
        """
        tries to create a new user and checks for a InputError with a
        message 'Invalid payload format'

        """
        valid_sid = self.session.sid

        # first we create that new user
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                new_user,
                                self.ccd,
                                valid_sid,
                                pld)

    def test_superadmin(self):
        """ verify that the superadmin is able to create users"""
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        valid_pld = {"name": name,
                     "mail": "mail@mynewuser",
                     "password": "mynewuser"}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, valid_pld)
        self.assertIsInstance(uid, int)

        # second, we check for the user to be in the database
        uid2 = User.by_name(self.ccd._db.conn, name).uid
        self.assertEqual(uid, uid2)

    def test_addpermission(self):
        """
        verify that a user with ACCESS_ADD in user2user table is able to
        create new users. note: this user must not be the superadmin.

        """
        db = self.ccd._db.conn

        # create a user and a workgroup. give the user ACCESS_ADD in
        # user2users table
        user = create_user(db, str(getRandomBytes()))
        wg = create_workgroup(db, "newworkgroup", user.uid, 2)
        del_user2user(db, user.uid)
        add_user2user(db, user.uid, 2) # ACCESS_ADD
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # create user
        name = str(getRandomBytes())
        valid_pld = {"name": name,
                     "mail": "mail@mynewuser",
                     "password": "mynewuser"}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, valid_pld)
        self.assertIsInstance(uid, int)

        # second, we check for the user to be in the database
        user2 = User.by_name(self.ccd._db.conn, name)
        try:
            self.assertEqual(uid, user2.uid)
        finally:
            # delete them, since they are not needed anymore
            user2.delete(db)
            user.delete(db)
            wg.delete(db)


    def test_permission_denied(self):
        """
        if the user is no superadmin and has no ACCESS_ADD a
        permissionDenied exception is raised

        """
        db = self.ccd._db.conn

        user = create_user(db, str(getRandomBytes()))
        wg = create_workgroup(db, "newworkgroup", user.uid, 3)
        add_user2user(db, user.uid, 3) # no ACCESS_ADD
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # create user
        name = str(getRandomBytes())
        valid_pld = {"name": name,
                     "mail": "mail@mynewuser",
                     "password": "mynewuser"}

        try:
            self.assertRaises(PermissionDenied,
                              new_user,
                              self.ccd,
                              valid_sid,
                              valid_pld)
        finally:
            user.delete(db)
            wg.delete(db)


    def test_non_dict_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid

        payload = "payload"
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                new_user,
                                self.ccd,
                                valid_sid,
                                payload)


    def test_missing_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid
        payload = None
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                new_user,
                                self.ccd,
                                valid_sid,
                                payload)

    def test_invalid_sid(self):
        """ withough valid session id an error must be raised """
        payload = {"name": "foobar",
                   "mail": "mail@mynewuser",
                   "password": "mynewuser"}
        invalid_sid = "AAA"
        self.assertRaises(InvalidSessionID,
                          new_user,
                          self.ccd,
                          invalid_sid,
                          payload)

    def test_missing_name(self):
        """
        a missing name should raise a InputError with a message 'Invalid
        payload format!'

        """
        invalid_pld = {"mail": "mail@mynewuser",
                       "password": "mynewuser"}
        self.assertInvalidPayload(invalid_pld)

    def test_missing_mail(self):
        """
        a missing mail should raise a InputError with a message 'Invalid
        payload format!'

        """
        name = str(getRandomBytes())
        invalid_pld = {"name": name,
                       "password": "mynewuser"}
        self.assertInvalidPayload(invalid_pld)

    def test_missing_password(self):
        """
        a missing password should raise a InputError with a message 'Invalid
        payload format!'

        """
        name = str(getRandomBytes())
        invalid_pld = {"name": name,
                       "mail": "mail@mynewuser"}
        self.assertInvalidPayload(invalid_pld)

    def test_name_length(self):
        """
        a name that exceeds database.ccddb.MAX_LEN_NAME should raise an
        database.ccdErrors.InputError with a message 'Name exceeds limit!'

        """
        name = "A" * (MAX_LEN_NAME+1)
        invalid_pld = {"name": name,
                       "mail": "mail@mynewuser",
                       "password": "mynewuser"}

        self.assertExceedsLimit(invalid_pld, "Name")

    def test_password_length(self):
        """
        a password that exceeds database.ccddb.MAX_LEN_PASSWORD should raise an
        database.ccdErrors.InputError with a message 'Password exceeds limit!'

        """
        name = str(getRandomBytes())
        invalid_pld = {"name": name,
                       "mail": "mail@mynewuser",
                       "password": "A" * (MAX_LEN_PASSWORD+1)}

        self.assertExceedsLimit(invalid_pld, "Password")

    def test_mail_length(self):
        """
        a mail that exceeds database.ccddb.MAX_LEN_MAIL should raise an
        database.ccdErrors.InputError with a message 'Mail exceeds limit!'

        """
        name = str(getRandomBytes())
        invalid_pld = {"name": name,
                       "mail": "A" * (MAX_LEN_MAIL+1),
                       "password": "mynewuser"}

        self.assertExceedsLimit(invalid_pld, "Mail")

    def test_description_length(self):
        """
        a description that exceeds database.ccddb.MAX_LEN_DESC should raise an
        database.ccdErrors.InputError with a message 'Desc exceeds limit!'

        """
        name = str(getRandomBytes())
        invalid_pld = {"name": name,
                       "mail": "mail@mynewuser",
                       "password": "mynewuser",
                       "description": "A" * (MAX_LEN_DESC+1)}

        self.assertExceedsLimit(invalid_pld, "Desc")


    def test_name_characters(self):
        """
        a name that contains other characters except for a-zA-Z0-9 should
        raise an database.ccdErrors.InputError with message 'Invalid username'

        """
        name = "$!YM=!)(>x)"
        invalid_pld = {"name": name,
                       "mail": "mail@mynewuser",
                       "password": "mynewuser"}

        valid_sid = self.session.sid

        # first we create that new user
        self.assertRaisesRegexp(InputError,
                                "Invalid username",
                                new_user,
                                self.ccd,
                                valid_sid,
                                invalid_pld)

if __name__ == '__main__':
    unittest.main()
