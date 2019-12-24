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
from ._vscf_impl import vscf_impl_t


class vscf_key_info_t(Structure):
    pass


class VscfKeyInfo(object):

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_key_info_new(self):
        vscf_key_info_new = self._lib.vscf_key_info_new
        vscf_key_info_new.argtypes = []
        vscf_key_info_new.restype = POINTER(vscf_key_info_t)
        return vscf_key_info_new()

    def vscf_key_info_delete(self, ctx):
        vscf_key_info_delete = self._lib.vscf_key_info_delete
        vscf_key_info_delete.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_delete.restype = None
        return vscf_key_info_delete(ctx)

    def vscf_key_info_new_with_alg_info(self, alg_info):
        """Build key information based on the generic algorithm information."""
        vscf_key_info_new_with_alg_info = self._lib.vscf_key_info_new_with_alg_info
        vscf_key_info_new_with_alg_info.argtypes = [POINTER(vscf_impl_t)]
        vscf_key_info_new_with_alg_info.restype = POINTER(vscf_key_info_t)
        return vscf_key_info_new_with_alg_info(alg_info)

    def vscf_key_info_is_compound(self, ctx):
        """Return true if a key is a compound key"""
        vscf_key_info_is_compound = self._lib.vscf_key_info_is_compound
        vscf_key_info_is_compound.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_is_compound.restype = c_bool
        return vscf_key_info_is_compound(ctx)

    def vscf_key_info_is_hybrid(self, ctx):
        """Return true if a key is a hybrid key"""
        vscf_key_info_is_hybrid = self._lib.vscf_key_info_is_hybrid
        vscf_key_info_is_hybrid.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_is_hybrid.restype = c_bool
        return vscf_key_info_is_hybrid(ctx)

    def vscf_key_info_is_compound_hybrid(self, ctx):
        """Return true if a key is a compound key and compounds cipher key
        and signer key are hybrid keys."""
        vscf_key_info_is_compound_hybrid = self._lib.vscf_key_info_is_compound_hybrid
        vscf_key_info_is_compound_hybrid.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_is_compound_hybrid.restype = c_bool
        return vscf_key_info_is_compound_hybrid(ctx)

    def vscf_key_info_is_compound_hybrid_cipher(self, ctx):
        """Return true if a key is a compound key and compounds cipher key
        is a hybrid key."""
        vscf_key_info_is_compound_hybrid_cipher = self._lib.vscf_key_info_is_compound_hybrid_cipher
        vscf_key_info_is_compound_hybrid_cipher.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_is_compound_hybrid_cipher.restype = c_bool
        return vscf_key_info_is_compound_hybrid_cipher(ctx)

    def vscf_key_info_is_compound_hybrid_signer(self, ctx):
        """Return true if a key is a compound key and compounds signer key
        is a hybrid key."""
        vscf_key_info_is_compound_hybrid_signer = self._lib.vscf_key_info_is_compound_hybrid_signer
        vscf_key_info_is_compound_hybrid_signer.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_is_compound_hybrid_signer.restype = c_bool
        return vscf_key_info_is_compound_hybrid_signer(ctx)

    def vscf_key_info_is_hybrid_post_quantum(self, ctx):
        """Return true if a key is a compound key that contains hybrid keys
        for encryption/decryption and signing/verifying that itself
        contains a combination of classic keys and post-quantum keys."""
        vscf_key_info_is_hybrid_post_quantum = self._lib.vscf_key_info_is_hybrid_post_quantum
        vscf_key_info_is_hybrid_post_quantum.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_is_hybrid_post_quantum.restype = c_bool
        return vscf_key_info_is_hybrid_post_quantum(ctx)

    def vscf_key_info_is_hybrid_post_quantum_cipher(self, ctx):
        """Return true if a key is a compound key that contains a hybrid key
        for encryption/decryption that contains a classic key and
        a post-quantum key."""
        vscf_key_info_is_hybrid_post_quantum_cipher = self._lib.vscf_key_info_is_hybrid_post_quantum_cipher
        vscf_key_info_is_hybrid_post_quantum_cipher.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_is_hybrid_post_quantum_cipher.restype = c_bool
        return vscf_key_info_is_hybrid_post_quantum_cipher(ctx)

    def vscf_key_info_is_hybrid_post_quantum_signer(self, ctx):
        """Return true if a key is a compound key that contains a hybrid key
        for signing/verifying that contains a classic key and
        a post-quantum key."""
        vscf_key_info_is_hybrid_post_quantum_signer = self._lib.vscf_key_info_is_hybrid_post_quantum_signer
        vscf_key_info_is_hybrid_post_quantum_signer.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_is_hybrid_post_quantum_signer.restype = c_bool
        return vscf_key_info_is_hybrid_post_quantum_signer(ctx)

    def vscf_key_info_alg_id(self, ctx):
        """Return common type of the key."""
        vscf_key_info_alg_id = self._lib.vscf_key_info_alg_id
        vscf_key_info_alg_id.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_alg_id.restype = c_int
        return vscf_key_info_alg_id(ctx)

    def vscf_key_info_compound_cipher_alg_id(self, ctx):
        """Return compound's cipher key id, if key is compound.
        Return None, otherwise."""
        vscf_key_info_compound_cipher_alg_id = self._lib.vscf_key_info_compound_cipher_alg_id
        vscf_key_info_compound_cipher_alg_id.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_compound_cipher_alg_id.restype = c_int
        return vscf_key_info_compound_cipher_alg_id(ctx)

    def vscf_key_info_compound_signer_alg_id(self, ctx):
        """Return compound's signer key id, if key is compound.
        Return None, otherwise."""
        vscf_key_info_compound_signer_alg_id = self._lib.vscf_key_info_compound_signer_alg_id
        vscf_key_info_compound_signer_alg_id.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_compound_signer_alg_id.restype = c_int
        return vscf_key_info_compound_signer_alg_id(ctx)

    def vscf_key_info_hybrid_first_key_alg_id(self, ctx):
        """Return hybrid's first key id, if key is hybrid.
        Return None, otherwise."""
        vscf_key_info_hybrid_first_key_alg_id = self._lib.vscf_key_info_hybrid_first_key_alg_id
        vscf_key_info_hybrid_first_key_alg_id.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_hybrid_first_key_alg_id.restype = c_int
        return vscf_key_info_hybrid_first_key_alg_id(ctx)

    def vscf_key_info_hybrid_second_key_alg_id(self, ctx):
        """Return hybrid's second key id, if key is hybrid.
        Return None, otherwise."""
        vscf_key_info_hybrid_second_key_alg_id = self._lib.vscf_key_info_hybrid_second_key_alg_id
        vscf_key_info_hybrid_second_key_alg_id.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_hybrid_second_key_alg_id.restype = c_int
        return vscf_key_info_hybrid_second_key_alg_id(ctx)

    def vscf_key_info_compound_hybrid_cipher_first_key_alg_id(self, ctx):
        """Return hybrid's first key id of compound's cipher key,
        if key is compound(hybrid, ...), None - otherwise."""
        vscf_key_info_compound_hybrid_cipher_first_key_alg_id = self._lib.vscf_key_info_compound_hybrid_cipher_first_key_alg_id
        vscf_key_info_compound_hybrid_cipher_first_key_alg_id.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_compound_hybrid_cipher_first_key_alg_id.restype = c_int
        return vscf_key_info_compound_hybrid_cipher_first_key_alg_id(ctx)

    def vscf_key_info_compound_hybrid_cipher_second_key_alg_id(self, ctx):
        """Return hybrid's second key id of compound's cipher key,
        if key is compound(hybrid, ...), None - otherwise."""
        vscf_key_info_compound_hybrid_cipher_second_key_alg_id = self._lib.vscf_key_info_compound_hybrid_cipher_second_key_alg_id
        vscf_key_info_compound_hybrid_cipher_second_key_alg_id.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_compound_hybrid_cipher_second_key_alg_id.restype = c_int
        return vscf_key_info_compound_hybrid_cipher_second_key_alg_id(ctx)

    def vscf_key_info_compound_hybrid_signer_first_key_alg_id(self, ctx):
        """Return hybrid's first key id of compound's signer key,
        if key is compound(..., hybrid), None - otherwise."""
        vscf_key_info_compound_hybrid_signer_first_key_alg_id = self._lib.vscf_key_info_compound_hybrid_signer_first_key_alg_id
        vscf_key_info_compound_hybrid_signer_first_key_alg_id.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_compound_hybrid_signer_first_key_alg_id.restype = c_int
        return vscf_key_info_compound_hybrid_signer_first_key_alg_id(ctx)

    def vscf_key_info_compound_hybrid_signer_second_key_alg_id(self, ctx):
        """Return hybrid's second key id of compound's signer key,
        if key is compound(..., hybrid), None - otherwise."""
        vscf_key_info_compound_hybrid_signer_second_key_alg_id = self._lib.vscf_key_info_compound_hybrid_signer_second_key_alg_id
        vscf_key_info_compound_hybrid_signer_second_key_alg_id.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_compound_hybrid_signer_second_key_alg_id.restype = c_int
        return vscf_key_info_compound_hybrid_signer_second_key_alg_id(ctx)

    def vscf_key_info_shallow_copy(self, ctx):
        vscf_key_info_shallow_copy = self._lib.vscf_key_info_shallow_copy
        vscf_key_info_shallow_copy.argtypes = [POINTER(vscf_key_info_t)]
        vscf_key_info_shallow_copy.restype = POINTER(vscf_key_info_t)
        return vscf_key_info_shallow_copy(ctx)
