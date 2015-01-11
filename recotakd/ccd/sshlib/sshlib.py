#!/usr/bin/env python2
#
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

from IPython import embed
import csockslib
import paramiko
import socket
import sys
import os
import re

OK = 0
ERROR = 1
EXIT = 10

class socketClass():
	""" simple socket class 

		self.host = '127.0.0.1'
		self.port = '22'
		self.tSocks = ''
		self.tHost = ''
		self.s = None

	"""

	def __init__(self):
		self.host = '127.0.0.1'
		self.port = '22'
		self.tSocks = ''
		self.tHost = ''
		self.s = None


	def createSocket(self):
		""" create simple sock_stream and return socket object """
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect((self.host,self.port))

		self.s = s
		return self.s

	def connectSocks(self):
		""" connect to socks server """
		try:
			s = csockslib.socks4a_connect(self.tSocks,self.tHost,timeout=30.0)
		except socket.error,e:
			print "Error: %s" % e
			sys.exit(1)

		self.s = s[1]

		return self.s


class sshClass():
	""" paramiko class abstraction 

		self.user = 'user'
		self.password = 'password'
		self.method = None
		self.key = None
		self.pm = None
		self.authSuccess = False
		self.s = None

	"""

	def __init__(self):
		self.user = 'user'
		self.password = 'password'
		self.method = None
		self.key = None
		self.pm = None
		self.authSuccess = False
		self.s = None

	def authSSH(self):
		""" wrapper function for authentication 
			ssh support 4 different ways for auth: password, key, none and interactive
			password is using user/pass
			key is using a defined private key
			none not seen so far (besides at auth bypasses ;))
			interactive is a tbd method on sshd side, older openssh used interactive even for password auth
		"""
		
		# lets define pm locally
		pm = self.pm

		# this is the basic ssh password auth, straighforward username/password
		if self.method=="password":
			pm.auth_password(username=self.user,password=self.password)

		#none auth, not seen in the wild so far, however lets put it in here as well
		elif self.method=="none":
			pm.auth_none(username=self.user)

		#key authentication, use a ssh key to authenticate to a remote system FIXME
		elif self.method=="key":
			#pm.auth_publickey(username=user,key)
			print "too implement"
		
		# keyboard interactive, worst implementation ever seen FIXME
		elif self.method=="keyboard-interactive":
			print "too implement"

		else:
			print "Unknown Auth Method"
			return 1

		if pm.is_authenticated()==True:
			print "Logged in!"
			self.authSuccess = True
			return True

		else:
			print "Wrong password!"
			self.authSuccess = False
			return 2

	def createSSH(self):
		""" do paramiko, change banner and connect """

		self.pm = paramiko.Transport(self.s)

		# change paramiko logger level
		self.pm.logger.setLevel('INFO')

		self.pm.local_version="SSH-2.0-OpenSSH_6.1"
		self.pm.connect()

		return True

	def exitSession(self):
		""" function for leaving the current session """

		self.pm.close()
		self.s.close()
		print "Connection closed"
		sys.exit(EXIT)
		return 0

class sftpClass():
	""" definition of sftp commands, class 

		self.sftp = None

	"""


	def __init__(self):
		self.sftp = None

	def listDir(self):
		""" list the directory """
		lList = self.sftp.listdir()
		for ele in lList:
			print ele
		return 0

	def listDirAttr(self):
		""" listdir with attributes """
		lList = self.sftp.listdir_attr()
		for ele in lList:
			print ele
		return 0

	def sftpGet(self,params):
		""" get a file from the remote system """

		if len(params)!=2:
			print "get remotefile localfile"
		else:
			self.sftp.get(params[0],params[1])

		return OK

	def sftpPut(self,params):
		""" put a file from local to remote """

		if len(params)!=2:
			print "put localfile remotefile"
		else:
			self.sftp.put(params[0],params[1])

		return OK

	def sftpChdir(self,params):
		""" change the directory """
		if len(params)!=1:
			print "cd dir"
		else:
			try:
				self.sftp.chdir(params[0])
			except IOError,e:
				print e

	def sftpMkdir(self,params):
		""" create directory """
		if len(params)!=1:
			print "mkdir %s" % (params[0])
		else:
			try:
				self.sftp.mkdir(params[0])
			except IOError,e:
				print e
		return OK

	def sftpRmdir(self,params):
		""" rm directory """
		if len(params)!=1:
			print "rmdir %s" % (params[0])
		else:
			try:
				self.sftp.rmdir(params[0])
			except IOError,e:
				print e
		return OK

	def sftpRmfile(self,params):
		""" rm file """
		if len(params)!=1:
			print "rm %s" % (params[0])
		else:
			try:
				self.sftp.remove(params[0])
			except IOError,e:
				print e
		return OK

	def sftpRename(self,params):
		""" rename a file or directory """
		if len(params)!=2:
			print "rename filename newfilename"
		else:
			try:
				self.sftp.rename(params[0],params[1])
			except IOError,e:
				print e
		return OK

	def sftpUnlink(self, params):
		""" unlink a file """
		if len(params)!=1:
			print "unlink %s" % (params[0])
		else:
			try:
				self.sftp.unlink(params[0])
			except IOError,e:
				print e
		return OK

	def sftpStat(self,params):
		""" stat a file """
		if len(params)!=1:
			print "stat %s" % (params[0])
		else:
			try:
				stat = self.sftp.stat(params[0])
				print stat
			except IOError,e:
				print e
		return OK

	def sftpLstat(self,params):
		""" lstat a file """
		if len(params)!=1:
			print "lstat %s" % (params[0])
		else:
			try:
				lstat = self.sftp.lstat(params[0])
				print lstat
			except IOError,e:
				print e
		return OK

	def sftpSymlink(self,params):
		""" symlink a file, guess why we need unlink """
		if len(params)!=2:
			print "symlink file link"
		else:
			try:
				self.sftp.symlink(params[0],params[1])
			except IOError,e:
				print e
		return OK

	def sftpOpen(self,params):
		""" opens a file
			this function allows the user via sftp to read files """
		if len(params)!=1:
			print "open %s" % (params[0])
		else:
			try:
				f = self.sftp.open(params[0])
				buf = f.readlines()
				for line in buf:
					print line,
			except IOError,e:
				print e
		return OK

	def sftpCopy(self,params):
		""" copy a file
			copy a file from one place to another on the remote system
			the function itself just opens the file remotely, reads into buffer
			and writes data to the new location
			ATTENTION: file is read one time, if it is huge, you will run into
			memory problems. as well it might result in huge traffic. i warned you.
		"""

		if len(params)!=2:
			print "copy %s %s" % (params[0],params[1])
		else:
			try:
				# open file with the data to read
				f = self.sftp.open(params[0])
				buf = f.readlines()

				# open file to write
				fw = self.sftp.open(params[1],'wb')
				for line in buf:
					fw.write(line)

				f.close()
				fw.close()

			except IOError,e:
				print e
		return OK

	def sftpHelp(self):
		""" display help file """

		print "cd\t\tchange directory"
		print "cwd\t\tprint remote cwd"
		print "exit or q\tleave session"
		print "lcwd\t\tprint local cwd"
		print "l or ls\t\tprint dir content with attributes"
		print "ll or la\tprint dir content"
		print "help\t\tyou are reading it"
		print "get\t\tget remote to local: get <remote> <local>"
		print "put\t\tput local to remote: put <local> <remote>"
		print "stat"
		print "lstat"
		print "mv"
		print "rename"
		print "unlink"
		print "symlink"
		print "rmdir"
		print "mkdir"
		print "mk"
		print "rm"
		print "remove"
		print "delete"

