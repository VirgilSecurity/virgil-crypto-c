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


from ctypes import *
from ._vsc_buffer import VscBuffer


class Buffer(object):

    def __init__(self, capacity):
        self._lib_vsc_buffer = VscBuffer()
        self._bytes_ = (c_byte * capacity)()
        self.c_buffer = self._lib_vsc_buffer.vsc_buffer_new()
        self._lib_vsc_buffer.vsc_buffer_use(
            self.c_buffer,
            self._bytes_,
            c_size_t(capacity)
        )

    def __len__(self):
        return self._lib_vsc_buffer.vsc_buffer_len(self.c_buffer)

    def __eq__(self, other):
        return self._lib_vsc_buffer.vsc_buffer_equal(self.c_buffer, other.c_buffer)

    def __bytes__(self):
        return self.get_bytes()

    def __delete__(self, instance):
        self._lib_vsc_buffer.vsc_buffer_destroy(self.c_buffer)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsc_buffer = VscBuffer()
        inst.c_buffer = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsc_buffer = VscBuffer()
        inst.c_buffer = inst._lib_vsc_buffer.vsc_buffer_shallow_copy(c_ctx)
        return inst

    def get_bytes(self):
        return bytearray(self._bytes_)[:self._lib_vsc_buffer.vsc_buffer_len(self.c_buffer)]
