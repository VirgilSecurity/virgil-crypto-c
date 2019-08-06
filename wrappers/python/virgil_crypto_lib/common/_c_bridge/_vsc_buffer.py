# Copyright (C) 2015-2019 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


from virgil_crypto_lib._libs import *
from ._vsc_data import vsc_data_t
from ctypes import *


class vsc_buffer_t(Structure):
    pass


class VscBuffer(object):
    """Encapsulates fixed byte array with variable effective data length."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.common

    def vsc_buffer_new(self):
        # vsc_buffer_new C function wrapper
        vsc_buffer_new = self._lib.vsc_buffer_new
        vsc_buffer_new.restype = POINTER(vsc_buffer_t)
        return vsc_buffer_new()

    def vsc_buffer_new_with_data(self, data):
        # vsc_buffer_new_with_data C function wrapper
        vsc_buffer_new_with_data = self._lib.vsc_buffer_new_with_data
        vsc_buffer_new_with_data.argtypes = [vsc_data_t]
        vsc_buffer_new_with_data.restype = POINTER(vsc_buffer_t)
        return vsc_buffer_new_with_data(data)

    def vsc_buffer_destroy(self, buffer):
        # vsc_buffer_destroy C function wrapper
        vsc_buffer_destroy = self._lib.vsc_buffer_destroy
        vsc_buffer_destroy.argtypes = [POINTER(POINTER(vsc_buffer_t))]
        return vsc_buffer_destroy(buffer)

    def vsc_buffer_equal(self, buffer, rhs):
        vsc_buffer_equal = self._lib.vsc_buffer_equal
        vsc_buffer_equal.argtypes = [POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsc_buffer_equal.restype = c_bool
        return vsc_buffer_equal(buffer, rhs)

    def vsc_buffer_use(self, buffer, bytes_, bytes_len):
        # vsc_buffer_use C function wrapper
        vsc_buffer_use = self._lib.vsc_buffer_use
        vsc_buffer_use.argtypes = [
            POINTER(vsc_buffer_t),
            POINTER(c_byte),
            c_size_t
        ]
        return vsc_buffer_use(buffer, bytes_, bytes_len)

    def vsc_buffer_len(self, buffer):
        vsc_buffer_len = self._lib.vsc_buffer_len
        vsc_buffer_len.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_len.restype = c_size_t
        return vsc_buffer_len(buffer)

    def vsc_buffer_shallow_copy(self, buffer):
        vsc_buffer_shallow_copy = self._lib.vsc_buffer_shallow_copy
        vsc_buffer_shallow_copy.argtypes = [POINTER(vsc_buffer_t)]
        vsc_buffer_shallow_copy.restype = POINTER(vsc_buffer_t)
        return vsc_buffer_shallow_copy(buffer)
