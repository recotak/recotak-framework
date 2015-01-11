import imapccd
import socket
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


class ImapGet():

    def __init__(self, server, port, user, password, crypto):
        self.user = user
        self.password = password
        self.server = server
        self.conn = imapccd.CCDIMAP4(
            socket.gethostbyname(server),
            int(port),
            crypto,
            None)
        if (crypto == "STARTTLS" and port == 143
                and "STARTTLS" in self.conn.capabilities):
            self.conn.starttls()
            self.conn.capability()
        self.logged_in = False
        self.mail = None
        self.mailbox = ''
        self.mbidx = 0

    def login(self):
        if not self.logged_in:
            self.logged_in = True
            success, response = self.conn.login(self.user, self.password)
            return success
        return False

    def logout(self):
        if self.logged_in:
            self.logged_in = False
            success, response = self.conn.logout()
            return success
        return False

    def __iter__(self):
        self.fetch_mailboxes()
        for box in self.mail.keys():
            self.mailbox = box
            success, box_descr = self.conn.select(self.mailbox)
            n_recent_mails = int(box_descr[0].split(' ')[1])
            for i in range(0, n_recent_mails):
                success, data = self.conn.fetch(str(i + 1), 'body[text]')
                self.mail[self.mailbox].append('\n'.join(data))
                yield '\n'.join(data)
        self.logout()

    def fetch_mailboxes(self):
        self.login()
        self.conn.banner()
        self.mail = {}
        success, mailboxes = self.conn.list('""', '"%"')
        if not success:
            return False
        for box in mailboxes:
            self.mail[box] = []

    def save_mails(self, filename):
        pass
