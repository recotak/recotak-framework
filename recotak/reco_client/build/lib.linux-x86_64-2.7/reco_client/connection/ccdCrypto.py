""" crypto stuff to generate ids """

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
from Crypto.Hash import SHA256
import binascii

def getRandomBytes(n):
	""" get n random bytes and return as hex """

	with open("/dev/urandom") as f:
			_bytes = f.read(n)

	return binascii.hexlify(_bytes)

def getSHA256Hex(toHash):
	""" hash toHash value """
	sha = SHA256.new(toHash)
	shaDigest = sha.hexdigest()

	return shaDigest

def hashPassword(password):
	""" hash the password """

	hpass = getSHA256Hex(password)
	return hpass

def genPID(toHash):
	""" generates the plugin id """
	sha256 = getSHA256Hex(toHash)
	pid = sha256[0:32]
	return pid

def genRID():
	""" generate the RID """
	rid_hex = getRandomBytes(16)
	rid_hex = getSHA256Hex(rid_hex)
	rid_hex = rid_hex[0:32]
	return rid_hex

def genSID():
	""" generate the SID """
	sid_hex = getRandomBytes(16)
	sid_hex = getSHA256Hex(sid_hex)
	sid_hex = sid_hex[0:32]
	return sid_hex
