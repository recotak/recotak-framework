"""
This unit test verifies proper handling of user updates.
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
from database.ccddb import AlreadyExistingError
from database.ccdErrors import PermissionDenied
from database.ccdErrors import InvalidSessionID
from connection.ccdCrypto import getRandomBytes
from unittests.ccdBase import create_workgroup
from database.ccdErrors import NotFoundError
from unittests.ccdBase import create_user
from database.ccdErrors import InputError
from database.ccddb import add_user2user
from database.ccdUser import update_user
from database.ccddb import MAX_LEN_NAME
from database.ccddb import MAX_LEN_MAIL
from database.ccddb import MAX_LEN_DESC
from unittests.ccdBase import CcdTest
from database.ccdUser import new_user
from database.ccdUser import User
import unittest
import random

class UpdateUser(CcdTest):
    """
    Test checks for user update functionality that is provided by the
    database.ccdUser module. It calls database.ccdUser.update_user(..)
    which is called in case of an OP_UPDATEUSER operation.

    """

    def assertExceedsLimit(self, pld, to_exceed):
        """
        tries to update a user and checks for a InputError with a
        message '* exceeds limit'

        """
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": "mynewuser"}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        pld.update({"uid": uid})

        # now we check for arising error
        self.assertRaisesRegexp(InputError,
                                "%s exceeds limit" % to_exceed,
                                update_user,
                                self.ccd,
                                valid_sid,
                                pld)

    def assertInvalidPayload(self, pld):
        """
        tries to create a new user and checks for a InputError with a
        message 'Invalid payload format'

        """
        valid_sid = self.session.sid

        name = str(getRandomBytes())
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": "mynewuser"}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        pld.update({"uid": uid})

        # now we check for arising error
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                update_user,
                                self.ccd,
                                valid_sid,
                                pld)

    def test_superadmin(self):
        """ verify that the superadmin is able to update users """
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": "mynewuser"}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        # second, we update this user
        name2 = str(getRandomBytes())
        mail2 = "mymail%d" % random.randrange(1000, 9999)
        description2 = "mydescription%d" % random.randrange(1000, 9999)
        update_pld = {"uid": uid,
                      "name": name2,
                      "mail": mail2,
                      "description": description2}
        self.assertIsNone(update_user(self.ccd, valid_sid, update_pld))

        # third, we verify that the changed data is written to database
        user = User.by_uid(self.ccd._db.conn, uid)
        self.assertEqual(user.name, name2)
        self.assertEqual(user.mail, mail2)
        self.assertEqual(user.description, description2)

    def test_write_permission(self):
        """
        verify that a user, with ACCESS_WRITE in user2users-table is able
        to update an existing user.

        """
        db = self.ccd._db.conn

        # create a user and a workgroup. give the user ACCESS_ADD in
        # user2users table
        user = create_user(db, str(getRandomBytes()))
        create_workgroup(db, "newworkgroup", user.uid, 2)
        add_user2user(db, user.uid, 2) # ACCESS_WRITE
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # first we create that new user
        name = str(getRandomBytes())
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": "mynewuser"}
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        # second, we update this user
        name2 = str(getRandomBytes())
        mail2 = "mymail%d" % random.randrange(1000, 9999)
        description2 = "mydescription%d" % random.randrange(1000, 9999)
        update_pld = {"uid": uid,
                      "name": name2,
                      "mail": mail2,
                      "description": description2}
        self.assertIsNone(update_user(self.ccd, valid_sid, update_pld))

        # third, we verify that the changed data is written to database
        user = User.by_uid(self.ccd._db.conn, uid)
        self.assertEqual(user.name, name2)
        self.assertEqual(user.mail, mail2)
        self.assertEqual(user.description, description2)

    def test_permission_denied(self):
        """
        verify that a non-superdmin user, who has no ACCESS_WRITE is not
        allowed to modify a user

        """
        db = self.ccd._db.conn
        # first we create that new user
        uid = create_user(db, str(getRandomBytes())).uid

        # create a user and a workgroup w/o ACCESS_ADD in
        # user2users table
        user = create_user(db, str(getRandomBytes()))
        create_workgroup(db, "newworkgroup", user.uid, 3)
        add_user2user(db, user.uid, 4) # NO ACCESS_WRITE
        valid_sid = self.ccd._assign_user_a_session(user).sid

        # second, we update this user
        name2 = str(getRandomBytes())
        mail2 = "mymail%d" % random.randrange(1000, 9999)
        description2 = "mydescription%d" % random.randrange(1000, 9999)
        update_pld = {"uid": uid,
                      "name": name2,
                      "mail": mail2,
                      "description": description2}

        self.assertRaises(PermissionDenied,
                          update_user,
                          self.ccd,
                          valid_sid,
                          update_pld)

    def test_rename_user_with_existing_username(self):
        """
        renaming a user to a name of an existing user should raise an exception

        """
        db = self.ccd._db.conn
        valid_sid = self.session.sid

        # this is the user that we try to rename as
        name1 = str(getRandomBytes())
        create_user(db, name1).uid

        # this is the user that we want to rename
        name2 = str(getRandomBytes())
        uid2 = create_user(db, name2).uid

        # now renanme user2 with the name of user1
        update_pld = {"uid": uid2,
                      "name": name1,
                      "mail": "foo",
                      "description": "bar"}

        self.assertRaises(AlreadyExistingError,
                          update_user,
                          self.ccd,
                          valid_sid,
                          update_pld)

    def test_uid_noint(self):
        """ verify that a non-int uid raises an InputError """
        db = self.ccd._db.conn
        valid_sid = self.session.sid

        name1 = str(getRandomBytes())
        create_user(db, name1).uid

        update_pld = {"uid": "foobar",
                      "name": "fubar",
                      "mail": "foo",
                      "description": "bar"}

        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                update_user,
                                self.ccd,
                                valid_sid,
                                update_pld)

    def test_non_existing_user(self):
        """ updating a non existing user should raise a NotFoundError  """
        valid_sid = self.session.sid
        name = str(getRandomBytes())
        mail = "mymail%d" % random.randrange(1000, 9999)
        description = "mydescription%d" % random.randrange(1000, 9999)
        update_pld = {"uid": random.randrange(10000, 99999) * -1,
                      "name": name,
                      "mail": mail,
                      "description": description}

        self.assertRaises(NotFoundError,
                          update_user,
                          self.ccd,
                          valid_sid,
                          update_pld)


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
                       "description": "A" * (MAX_LEN_DESC+1)}

        self.assertExceedsLimit(invalid_pld, "Desc")


    def test_name_characters(self):
        """
        a name that contains other characters except for a-zA-Z0-9 should
        raise an database.ccdErrors.InputError with message 'Invalid username'

        """
        valid_sid = self.session.sid

        name = str(getRandomBytes())
        add_pld = {"name": name,
                   "mail": "mail@mynewuser",
                   "password": "mynewuser"}

        # first we create that new user
        uid = new_user(self.ccd, valid_sid, add_pld)
        self.assertIsInstance(uid, int)

        invalid_pld = {"uid": uid,
                       "name": "$!YM=!)(>x)",
                       "mail": "mail@mynewuser",
                       "password": "mynewuser"}

        self.assertRaisesRegexp(InputError,
                                "Invalid username",
                                update_user,
                                self.ccd,
                                valid_sid,
                                invalid_pld)

    def test_non_dict_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid

        payload = "payload"
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                update_user,
                                self.ccd,
                                valid_sid,
                                payload)

    def test_missing_payload(self):
        """ without providing a new password an InputError must be raised """
        valid_sid = self.session.sid
        payload = None
        self.assertRaisesRegexp(InputError,
                                "Invalid payload format!",
                                update_user,
                                self.ccd,
                                valid_sid,
                                payload)

    def test_invalid_sid(self):
        """ withough valid session id an error must be raised """
        payload = {"uid": 1}
        invalid_sid = "AAA"
        self.assertRaises(InvalidSessionID,
                          update_user,
                          self.ccd,
                          invalid_sid,
                          payload)

if __name__ == '__main__':
    unittest.main()
