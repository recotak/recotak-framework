""" unittests base class to execute the ccd testing """

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
from database.ccdWorkgroup import Workgroup
from database.ccdProject import Project
from database.ccdUser import User
import unittest
import ccd
import sys
import os

ADDR = ("127.0.0.1", 8080)
CONFIG_FN = "/home/curesec/Curesec/curesec.conf" #: path to config file

if not os.path.exists(CONFIG_FN):
    sys.stderr.write("Config file %s not found!" % CONFIG_FN)
    sys.exit(1)

class CcdTest(unittest.TestCase):
    """ base class that provides setUp and tearDown """

    def setUp(self):
        """ executed immediately before running a test method """
        myccd = ccd.Ccd(daemon=False, addr=ADDR, config_fn=CONFIG_FN)
        superadmin = User.by_name(myccd._db.conn, "curesec")
        session = myccd._assign_user_a_session(superadmin)

        self.ccd = myccd
        self.session = session

    def tearDown(self):
        """ executed after finishing a test method """
        self.session.isAlive = False
        self.ccd = None
        self.session = None

def create_user(db, name):
    """
    create a non admin ccd user, a workgroup and add the user to the
    workgroup as workgroup admin

    """
    # create non-admin user
    user = User.create_fromname(db,
                                name,
                                "mypwd", # password
                                "mymail", # mail address
                                "mydescription", # description
                                return_user=True
                                )
    return user

def create_workgroup(db, name, uid, rid):
    """ create workgroup and add user with corresponding role id """
    # create workgroup
    wg = Workgroup.create_fromname(db,
                                   name,
                                   return_workgroup=True)

    # add user to workgroup
    wg.add_member(db, uid, rid)

    return wg

def create_project(db, name, user, rid):
    """ create a project and add the user with corresponding role id """
    # create project
    proj = Project.create_fromname(
                        db,
                        name,
                        user, # creator
                        user, # owner
                        1, # type id
                        "my project", #description
                        return_project=True
                        )

    # add user to project
    proj.add_member(db,
                    user.uid, # user id
                    rid # role
                    )

    return proj

if __name__ == "__main__":
    print(sys.argv)
    if sys.argv:
        CONFIG_FN = sys.argv[-1]

    print("testing with config file %s" % CONFIG_FN)
#    sys.exit(1)
    # adding user test cases
    from unittests.databaseTests.createUser import CreateUser
    from unittests.databaseTests.deleteUser import DeleteUser
    from unittests.databaseTests.updateUser import UpdateUser
    from unittests.databaseTests.updateUserPwd import UpdateUserPwd
    from unittests.databaseTests.showUser import ShowUser

    user_suite = unittest.TestSuite()
    user_suite.addTest(unittest.makeSuite(CreateUser))
#    user_suite.addTest(unittest.makeSuite(DeleteUser))
#    user_suite.addTest(unittest.makeSuite(UpdateUser))
#    user_suite.addTest(unittest.makeSuite(UpdateUserPwd))
#    user_suite.addTest(unittest.makeSuite(ShowUser))
    unittest.TextTestRunner(verbosity=2).run(user_suite)


    # adding session tests
#    from unittests.connectionTests.ccdSession import SessionStageOne
#    from unittests.connectionTests.ccdSession import SessionStageTwo
#    from unittests.connectionTests.ccdSession import SessionStageThree

#    session_suite = unittest.TestSuite()
#    session_suite.addTest(unittest.makeSuite(SessionStageOne))
#    session_suite.addTest(unittest.makeSuite(SessionStageTwo))
#    session_suite.addTest(unittest.makeSuite(SessionStageThree))
#    unittest.TextTestRunner(verbosity=2).run(session_suite)
