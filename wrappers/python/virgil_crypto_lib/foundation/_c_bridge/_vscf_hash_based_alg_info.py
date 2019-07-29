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


class vscf_hash_based_alg_info_t(Structure):
    pass


class VscfHashBasedAlgInfo(object):
    """Handle hashed based algorithm information, i.e. HKDF, HMAC, etc."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_hash_based_alg_info_new(self):
        vscf_hash_based_alg_info_new = self._lib.vscf_hash_based_alg_info_new
        vscf_hash_based_alg_info_new.argtypes = []
        vscf_hash_based_alg_info_new.restype = POINTER(vscf_hash_based_alg_info_t)
        return vscf_hash_based_alg_info_new()

    def vscf_hash_based_alg_info_delete(self, ctx):
        vscf_hash_based_alg_info_delete = self._lib.vscf_hash_based_alg_info_delete
        vscf_hash_based_alg_info_delete.argtypes = [POINTER(vscf_hash_based_alg_info_t)]
        vscf_hash_based_alg_info_delete.restype = None
        return vscf_hash_based_alg_info_delete(ctx)

    def vscf_hash_based_alg_info_new_with_members(self, alg_id, hash_alg_info):
        """Create algorithm info with identificator and HASH algorithm info."""
        vscf_hash_based_alg_info_new_with_members = self._lib.vscf_hash_based_alg_info_new_with_members
        vscf_hash_based_alg_info_new_with_members.argtypes = [c_int, POINTER(vscf_impl_t)]
        vscf_hash_based_alg_info_new_with_members.restype = POINTER(vscf_hash_based_alg_info_t)
        return vscf_hash_based_alg_info_new_with_members(alg_id, hash_alg_info)

    def vscf_hash_based_alg_info_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_hash_based_alg_info_alg_id = self._lib.vscf_hash_based_alg_info_alg_id
        vscf_hash_based_alg_info_alg_id.argtypes = [POINTER(vscf_hash_based_alg_info_t)]
        vscf_hash_based_alg_info_alg_id.restype = c_int
        return vscf_hash_based_alg_info_alg_id(ctx)

    def vscf_hash_based_alg_info_hash_alg_info(self, ctx):
        """Return hash algorithm information."""
        vscf_hash_based_alg_info_hash_alg_info = self._lib.vscf_hash_based_alg_info_hash_alg_info
        vscf_hash_based_alg_info_hash_alg_info.argtypes = [POINTER(vscf_hash_based_alg_info_t)]
        vscf_hash_based_alg_info_hash_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_hash_based_alg_info_hash_alg_info(ctx)

    def vscf_hash_based_alg_info_shallow_copy(self, ctx):
        vscf_hash_based_alg_info_shallow_copy = self._lib.vscf_hash_based_alg_info_shallow_copy
        vscf_hash_based_alg_info_shallow_copy.argtypes = [POINTER(vscf_hash_based_alg_info_t)]
        vscf_hash_based_alg_info_shallow_copy.restype = POINTER(vscf_hash_based_alg_info_t)
        return vscf_hash_based_alg_info_shallow_copy(ctx)

    def vscf_hash_based_alg_info_impl(self, ctx):
        vscf_hash_based_alg_info_impl = self._lib.vscf_hash_based_alg_info_impl
        vscf_hash_based_alg_info_impl.argtypes = [POINTER(vscf_hash_based_alg_info_t)]
        vscf_hash_based_alg_info_impl.restype = POINTER(vscf_impl_t)
        return vscf_hash_based_alg_info_impl(ctx)
