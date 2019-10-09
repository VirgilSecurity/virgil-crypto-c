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


class vscf_hkdf_t(Structure):
    pass


class VscfHkdf(object):
    """Virgil Security implementation of the HKDF (RFC 6234) algorithm."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_hkdf_new(self):
        vscf_hkdf_new = self._lib.vscf_hkdf_new
        vscf_hkdf_new.argtypes = []
        vscf_hkdf_new.restype = POINTER(vscf_hkdf_t)
        return vscf_hkdf_new()

    def vscf_hkdf_delete(self, ctx):
        vscf_hkdf_delete = self._lib.vscf_hkdf_delete
        vscf_hkdf_delete.argtypes = [POINTER(vscf_hkdf_t)]
        vscf_hkdf_delete.restype = None
        return vscf_hkdf_delete(ctx)

    def vscf_hkdf_use_hash(self, ctx, hash):
        vscf_hkdf_use_hash = self._lib.vscf_hkdf_use_hash
        vscf_hkdf_use_hash.argtypes = [POINTER(vscf_hkdf_t), POINTER(vscf_impl_t)]
        vscf_hkdf_use_hash.restype = None
        return vscf_hkdf_use_hash(ctx, hash)

    def vscf_hkdf_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_hkdf_alg_id = self._lib.vscf_hkdf_alg_id
        vscf_hkdf_alg_id.argtypes = [POINTER(vscf_hkdf_t)]
        vscf_hkdf_alg_id.restype = c_int
        return vscf_hkdf_alg_id(ctx)

    def vscf_hkdf_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_hkdf_produce_alg_info = self._lib.vscf_hkdf_produce_alg_info
        vscf_hkdf_produce_alg_info.argtypes = [POINTER(vscf_hkdf_t)]
        vscf_hkdf_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_hkdf_produce_alg_info(ctx)

    def vscf_hkdf_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_hkdf_restore_alg_info = self._lib.vscf_hkdf_restore_alg_info
        vscf_hkdf_restore_alg_info.argtypes = [POINTER(vscf_hkdf_t), POINTER(vscf_impl_t)]
        vscf_hkdf_restore_alg_info.restype = c_int
        return vscf_hkdf_restore_alg_info(ctx, alg_info)

    def vscf_hkdf_derive(self, ctx, data, key_len, key):
        """Derive key of the requested length from the given data."""
        vscf_hkdf_derive = self._lib.vscf_hkdf_derive
        vscf_hkdf_derive.argtypes = [POINTER(vscf_hkdf_t), vsc_data_t, c_size_t, POINTER(vsc_buffer_t)]
        vscf_hkdf_derive.restype = None
        return vscf_hkdf_derive(ctx, data, key_len, key)

    def vscf_hkdf_reset(self, ctx, salt, iteration_count):
        """Prepare algorithm to derive new key."""
        vscf_hkdf_reset = self._lib.vscf_hkdf_reset
        vscf_hkdf_reset.argtypes = [POINTER(vscf_hkdf_t), vsc_data_t, c_size_t]
        vscf_hkdf_reset.restype = None
        return vscf_hkdf_reset(ctx, salt, iteration_count)

    def vscf_hkdf_set_info(self, ctx, info):
        """Setup application specific information (optional).
        Can be empty."""
        vscf_hkdf_set_info = self._lib.vscf_hkdf_set_info
        vscf_hkdf_set_info.argtypes = [POINTER(vscf_hkdf_t), vsc_data_t]
        vscf_hkdf_set_info.restype = None
        return vscf_hkdf_set_info(ctx, info)

    def vscf_hkdf_shallow_copy(self, ctx):
        vscf_hkdf_shallow_copy = self._lib.vscf_hkdf_shallow_copy
        vscf_hkdf_shallow_copy.argtypes = [POINTER(vscf_hkdf_t)]
        vscf_hkdf_shallow_copy.restype = POINTER(vscf_hkdf_t)
        return vscf_hkdf_shallow_copy(ctx)

    def vscf_hkdf_impl(self, ctx):
        vscf_hkdf_impl = self._lib.vscf_hkdf_impl
        vscf_hkdf_impl.argtypes = [POINTER(vscf_hkdf_t)]
        vscf_hkdf_impl.restype = POINTER(vscf_impl_t)
        return vscf_hkdf_impl(ctx)
