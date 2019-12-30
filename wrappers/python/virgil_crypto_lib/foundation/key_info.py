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
from ._c_bridge import VscfKeyInfo


class KeyInfo(object):

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_key_info = VscfKeyInfo()
        self.ctx = self._lib_vscf_key_info.vscf_key_info_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_key_info.vscf_key_info_delete(self.ctx)

    @classmethod
    def with_alg_info(cls, alg_info):
        """Build key information based on the generic algorithm information."""
        inst = cls.__new__(cls)
        inst._lib_vscf_key_info = VscfKeyInfo()
        inst.ctx = inst._lib_vscf_key_info.vscf_key_info_new_with_alg_info(alg_info.c_impl)
        return inst

    def is_compound(self):
        """Return true if a key is a compound key"""
        result = self._lib_vscf_key_info.vscf_key_info_is_compound(self.ctx)
        return result

    def is_hybrid(self):
        """Return true if a key is a hybrid key"""
        result = self._lib_vscf_key_info.vscf_key_info_is_hybrid(self.ctx)
        return result

    def is_compound_hybrid(self):
        """Return true if a key is a compound key and compounds cipher key
        and signer key are hybrid keys."""
        result = self._lib_vscf_key_info.vscf_key_info_is_compound_hybrid(self.ctx)
        return result

    def is_compound_hybrid_cipher(self):
        """Return true if a key is a compound key and compounds cipher key
        is a hybrid key."""
        result = self._lib_vscf_key_info.vscf_key_info_is_compound_hybrid_cipher(self.ctx)
        return result

    def is_compound_hybrid_signer(self):
        """Return true if a key is a compound key and compounds signer key
        is a hybrid key."""
        result = self._lib_vscf_key_info.vscf_key_info_is_compound_hybrid_signer(self.ctx)
        return result

    def is_hybrid_post_quantum(self):
        """Return true if a key is a compound key that contains hybrid keys
        for encryption/decryption and signing/verifying that itself
        contains a combination of classic keys and post-quantum keys."""
        result = self._lib_vscf_key_info.vscf_key_info_is_hybrid_post_quantum(self.ctx)
        return result

    def is_hybrid_post_quantum_cipher(self):
        """Return true if a key is a compound key that contains a hybrid key
        for encryption/decryption that contains a classic key and
        a post-quantum key."""
        result = self._lib_vscf_key_info.vscf_key_info_is_hybrid_post_quantum_cipher(self.ctx)
        return result

    def is_hybrid_post_quantum_signer(self):
        """Return true if a key is a compound key that contains a hybrid key
        for signing/verifying that contains a classic key and
        a post-quantum key."""
        result = self._lib_vscf_key_info.vscf_key_info_is_hybrid_post_quantum_signer(self.ctx)
        return result

    def alg_id(self):
        """Return common type of the key."""
        result = self._lib_vscf_key_info.vscf_key_info_alg_id(self.ctx)
        return result

    def compound_cipher_alg_id(self):
        """Return compound's cipher key id, if key is compound.
        Return None, otherwise."""
        result = self._lib_vscf_key_info.vscf_key_info_compound_cipher_alg_id(self.ctx)
        return result

    def compound_signer_alg_id(self):
        """Return compound's signer key id, if key is compound.
        Return None, otherwise."""
        result = self._lib_vscf_key_info.vscf_key_info_compound_signer_alg_id(self.ctx)
        return result

    def hybrid_first_key_alg_id(self):
        """Return hybrid's first key id, if key is hybrid.
        Return None, otherwise."""
        result = self._lib_vscf_key_info.vscf_key_info_hybrid_first_key_alg_id(self.ctx)
        return result

    def hybrid_second_key_alg_id(self):
        """Return hybrid's second key id, if key is hybrid.
        Return None, otherwise."""
        result = self._lib_vscf_key_info.vscf_key_info_hybrid_second_key_alg_id(self.ctx)
        return result

    def compound_hybrid_cipher_first_key_alg_id(self):
        """Return hybrid's first key id of compound's cipher key,
        if key is compound(hybrid, ...), None - otherwise."""
        result = self._lib_vscf_key_info.vscf_key_info_compound_hybrid_cipher_first_key_alg_id(self.ctx)
        return result

    def compound_hybrid_cipher_second_key_alg_id(self):
        """Return hybrid's second key id of compound's cipher key,
        if key is compound(hybrid, ...), None - otherwise."""
        result = self._lib_vscf_key_info.vscf_key_info_compound_hybrid_cipher_second_key_alg_id(self.ctx)
        return result

    def compound_hybrid_signer_first_key_alg_id(self):
        """Return hybrid's first key id of compound's signer key,
        if key is compound(..., hybrid), None - otherwise."""
        result = self._lib_vscf_key_info.vscf_key_info_compound_hybrid_signer_first_key_alg_id(self.ctx)
        return result

    def compound_hybrid_signer_second_key_alg_id(self):
        """Return hybrid's second key id of compound's signer key,
        if key is compound(..., hybrid), None - otherwise."""
        result = self._lib_vscf_key_info.vscf_key_info_compound_hybrid_signer_second_key_alg_id(self.ctx)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_info = VscfKeyInfo()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_info = VscfKeyInfo()
        inst.ctx = inst._lib_vscf_key_info.vscf_key_info_shallow_copy(c_ctx)
        return inst
