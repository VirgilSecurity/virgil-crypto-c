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


from virgil_crypto_lib.utils import Utils
from ._vsc_data import VscData
from ctypes import *


class Data(object):

    def __init__(self, predefined_value=None):
        self._lib_vsc_data = VscData()
        if predefined_value is None:
            self._bytes_ = Utils.convert_bytearray_to_c_byte_array(bytearray())
        elif isinstance(predefined_value, bytes) or isinstance(predefined_value, bytearray):
            self._bytes_ = Utils.convert_bytearray_to_c_byte_array(predefined_value)
        elif isinstance(predefined_value, str) or Utils.check_unicode(predefined_value):
            str_bytes = bytearray(Utils.strtobytes(predefined_value))
            self._bytes_ = Utils.convert_bytearray_to_c_byte_array(str_bytes)
        else:
            raise TypeError("Wrong type for instantiate Data")
        self.data = self._lib_vsc_data.vsc_data(self._bytes_, len(self._bytes_))

    def __eq__(self, other):
        return self._lib_vsc_data.vsc_data_equal(self.data, other.data)

    def __len__(self):
        return self.data.len

    def __bytes__(self):
        return bytes(bytearray((c_byte * len(self))(*self.data.bytes[:len(self)])))

    def __iter__(self):
        return iter(bytearray((c_byte * len(self))(*self.data.bytes[:len(self)])))

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsc_data = VscData()
        inst.data = c_ctx
        return inst
