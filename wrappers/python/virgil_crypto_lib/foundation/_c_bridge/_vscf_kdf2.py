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
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_kdf2_t(Structure):
    pass


class VscfKdf2(object):
    """Virgil Security implementation of the KDF2 (ISO-18033-2) algorithm."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_kdf2_new(self):
        vscf_kdf2_new = self._lib.vscf_kdf2_new
        vscf_kdf2_new.argtypes = []
        vscf_kdf2_new.restype = POINTER(vscf_kdf2_t)
        return vscf_kdf2_new()

    def vscf_kdf2_delete(self, ctx):
        vscf_kdf2_delete = self._lib.vscf_kdf2_delete
        vscf_kdf2_delete.argtypes = [POINTER(vscf_kdf2_t)]
        vscf_kdf2_delete.restype = None
        return vscf_kdf2_delete(ctx)

    def vscf_kdf2_use_hash(self, ctx, hash):
        vscf_kdf2_use_hash = self._lib.vscf_kdf2_use_hash
        vscf_kdf2_use_hash.argtypes = [POINTER(vscf_kdf2_t), POINTER(vscf_impl_t)]
        vscf_kdf2_use_hash.restype = None
        return vscf_kdf2_use_hash(ctx, hash)

    def vscf_kdf2_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_kdf2_alg_id = self._lib.vscf_kdf2_alg_id
        vscf_kdf2_alg_id.argtypes = [POINTER(vscf_kdf2_t)]
        vscf_kdf2_alg_id.restype = c_int
        return vscf_kdf2_alg_id(ctx)

    def vscf_kdf2_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_kdf2_produce_alg_info = self._lib.vscf_kdf2_produce_alg_info
        vscf_kdf2_produce_alg_info.argtypes = [POINTER(vscf_kdf2_t)]
        vscf_kdf2_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_kdf2_produce_alg_info(ctx)

    def vscf_kdf2_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_kdf2_restore_alg_info = self._lib.vscf_kdf2_restore_alg_info
        vscf_kdf2_restore_alg_info.argtypes = [POINTER(vscf_kdf2_t), POINTER(vscf_impl_t)]
        vscf_kdf2_restore_alg_info.restype = c_int
        return vscf_kdf2_restore_alg_info(ctx, alg_info)

    def vscf_kdf2_derive(self, ctx, data, key_len, key):
        """Derive key of the requested length from the given data."""
        vscf_kdf2_derive = self._lib.vscf_kdf2_derive
        vscf_kdf2_derive.argtypes = [POINTER(vscf_kdf2_t), vsc_data_t, c_size_t, POINTER(vsc_buffer_t)]
        vscf_kdf2_derive.restype = None
        return vscf_kdf2_derive(ctx, data, key_len, key)

    def vscf_kdf2_shallow_copy(self, ctx):
        vscf_kdf2_shallow_copy = self._lib.vscf_kdf2_shallow_copy
        vscf_kdf2_shallow_copy.argtypes = [POINTER(vscf_kdf2_t)]
        vscf_kdf2_shallow_copy.restype = POINTER(vscf_kdf2_t)
        return vscf_kdf2_shallow_copy(ctx)

    def vscf_kdf2_impl(self, ctx):
        vscf_kdf2_impl = self._lib.vscf_kdf2_impl
        vscf_kdf2_impl.argtypes = [POINTER(vscf_kdf2_t)]
        vscf_kdf2_impl.restype = POINTER(vscf_impl_t)
        return vscf_kdf2_impl(ctx)
