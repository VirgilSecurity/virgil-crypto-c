# Copyright (C) 2015-2021 Virgil Security, Inc.
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
from ._c_bridge import VscfCipherAlgInfo
from virgil_crypto_lib.common._c_bridge import Data
from .alg_info import AlgInfo


class CipherAlgInfo(AlgInfo):
    """Handle symmetric cipher algorithm information."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_cipher_alg_info = VscfCipherAlgInfo()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_cipher_alg_info.vscf_cipher_alg_info_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_cipher_alg_info.vscf_cipher_alg_info_delete(self.ctx)

    @classmethod
    def with_members(cls, alg_id, nonce):
        """Create symmetric cipher algorithm info with identificator and input vector."""
        d_nonce = Data(nonce)
        inst = cls.__new__(cls)
        inst._lib_vscf_cipher_alg_info = VscfCipherAlgInfo()
        inst.ctx = inst._lib_vscf_cipher_alg_info.vscf_cipher_alg_info_new_with_members(alg_id, d_nonce.data)
        return inst

    def alg_id(self):
        """Provide algorithm identificator."""
        result = self._lib_vscf_cipher_alg_info.vscf_cipher_alg_info_alg_id(self.ctx)
        return result

    def nonce(self):
        """Return IV."""
        result = self._lib_vscf_cipher_alg_info.vscf_cipher_alg_info_nonce(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_cipher_alg_info = VscfCipherAlgInfo()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_cipher_alg_info = VscfCipherAlgInfo()
        inst.ctx = inst._lib_vscf_cipher_alg_info.vscf_cipher_alg_info_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_cipher_alg_info.vscf_cipher_alg_info_shallow_copy(value)
        self._c_impl = self._lib_vscf_cipher_alg_info.vscf_cipher_alg_info_impl(self.ctx)
