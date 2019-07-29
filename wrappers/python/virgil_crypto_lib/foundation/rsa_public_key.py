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
from ._c_bridge import VscfRsaPublicKey
from ._c_bridge import VscfImplTag
from .key import Key
from .public_key import PublicKey


class RsaPublicKey(Key, PublicKey):
    """Handles RSA public key."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_rsa_public_key = VscfRsaPublicKey()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_rsa_public_key.vscf_rsa_public_key_delete(self.ctx)

    def __len__(self):
        """Length of the key in bytes."""
        result = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_len(self.ctx)
        return result

    def alg_info(self):
        """Return algorithm information that can be used for serialization."""
        result = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].use_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def alg_id(self):
        """Algorithm identifier the key belongs to."""
        result = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_alg_id(self.ctx)
        return result

    def bitlen(self):
        """Length of the key in bits."""
        result = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_bitlen(self.ctx)
        return result

    def impl_tag(self):
        """Return tag of an associated algorithm that can handle this key."""
        result = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_impl_tag(self.ctx)
        return result

    def is_valid(self):
        """Check that key is valid.
        Note, this operation can be slow."""
        result = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_is_valid(self.ctx)
        return result

    def key_exponent(self):
        """Return public key exponent."""
        result = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_key_exponent(self.ctx)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_rsa_public_key = VscfRsaPublicKey()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_rsa_public_key = VscfRsaPublicKey()
        inst.ctx = inst._lib_vscf_rsa_public_key.vscf_rsa_public_key_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_shallow_copy(value)
        self._c_impl = self._lib_vscf_rsa_public_key.vscf_rsa_public_key_impl(self.ctx)
