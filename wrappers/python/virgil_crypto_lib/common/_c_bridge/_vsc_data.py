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
from ctypes import *


class vsc_data_t(Structure):
    _fields_ = [
        ("bytes", POINTER(c_byte)),
        ("len", c_size_t)
    ]


class VscData(object):
    """Encapsulates fixed byte array."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.common

    def vsc_data(self, bytes_, len_):
        vsc_data = self._lib.vsc_data
        vsc_data.argtypes = [POINTER(c_byte), c_size_t]
        vsc_data.restype = vsc_data_t
        return vsc_data(bytes_, len_)

    def vsc_data_from_str(self, str_):
        vsc_data_from_str = self._lib.vsc_data_from_str
        vsc_data_from_str.argtypes = [c_char_p, c_size_t]
        vsc_data_from_str.restype = vsc_data_t
        return vsc_data_from_str(str_)

    def vsc_data_empty(self):
        vsc_data_empty = self._lib.vsc_data_empty
        vsc_data_empty.restype = vsc_data_t
        return vsc_data_empty()

    def vsc_data_equal(self, data, rhs):
        # type: (vsc_data_t, vsc_data_t)->bool
        vsc_data_equal = self._lib.vsc_data_equal
        vsc_data_equal.argtypes = [vsc_data_t, vsc_data_t]
        vsc_data_equal.restype = c_bool
        return vsc_data_equal(data, rhs)
