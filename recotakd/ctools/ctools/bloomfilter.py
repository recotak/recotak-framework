#!/usr/bin/env python

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
# @author curesec

__author__ = "curesec"
__version__ = 0.02

"""
v0.02
* changes array.array to multiprocessing.Array to support multiprocessing
* added default values for initialisation

v0.01
* initial bloomfilter class

"""

from multiprocessing import Array
from random import Random

def get_probes(bfilter, key):
    hasher = Random(key).randrange
    for _ in range(bfilter.num_probes):
        array_index = hasher(len(bfilter.arr))
        bit_index = hasher(32)
        yield array_index, 1 << bit_index

class BloomFilter:

    def __init__(self, num_bits=1000, num_probes=14, probe_func=get_probes):
        self.num_bits= num_bits
        num_words = (num_bits + 31) // 32
        self.arr = Array('L', [0] * num_words)
        self.num_probes = num_probes
        self.probe_func = get_probes

    def add(self, key):
        for i, mask in self.probe_func(self, key):
            self.arr[i] |= mask

    def match_template(self, bfilter):
        return (self.num_bits == bfilter.num_bits \
            and self.num_probes == bfilter.num_probes \
            and self.probe_func == bfilter.probe_func)

    def union(self, bfilter):
        if self.match_template(bfilter):
            self.arr = [a | b for a, b in zip(self.arr, bfilter.arr)]
        else:
            raise ValueError("Mismatched bloom filters")

    def intersection(self, bfilter):
        if self.match_template(bfilter):
            self.arr = [a & b for a, b in zip(self.arr, bfilter.arr)]
        else:
            raise ValueError("Mismatched bloom filters")

    def __contains__(self, key):
        return all(self.arr[i] & mask for i, mask in self.probe_func(self, key))


