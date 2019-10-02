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


class vscf_pkcs5_pbkdf2_t(Structure):
    pass


class VscfPkcs5Pbkdf2(object):
    """Virgil Security implementation of the PBKDF2 (RFC 8018) algorithm."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_pkcs5_pbkdf2_new(self):
        vscf_pkcs5_pbkdf2_new = self._lib.vscf_pkcs5_pbkdf2_new
        vscf_pkcs5_pbkdf2_new.argtypes = []
        vscf_pkcs5_pbkdf2_new.restype = POINTER(vscf_pkcs5_pbkdf2_t)
        return vscf_pkcs5_pbkdf2_new()

    def vscf_pkcs5_pbkdf2_delete(self, ctx):
        vscf_pkcs5_pbkdf2_delete = self._lib.vscf_pkcs5_pbkdf2_delete
        vscf_pkcs5_pbkdf2_delete.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t)]
        vscf_pkcs5_pbkdf2_delete.restype = None
        return vscf_pkcs5_pbkdf2_delete(ctx)

    def vscf_pkcs5_pbkdf2_use_hmac(self, ctx, hmac):
        vscf_pkcs5_pbkdf2_use_hmac = self._lib.vscf_pkcs5_pbkdf2_use_hmac
        vscf_pkcs5_pbkdf2_use_hmac.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t), POINTER(vscf_impl_t)]
        vscf_pkcs5_pbkdf2_use_hmac.restype = None
        return vscf_pkcs5_pbkdf2_use_hmac(ctx, hmac)

    def vscf_pkcs5_pbkdf2_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_pkcs5_pbkdf2_alg_id = self._lib.vscf_pkcs5_pbkdf2_alg_id
        vscf_pkcs5_pbkdf2_alg_id.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t)]
        vscf_pkcs5_pbkdf2_alg_id.restype = c_int
        return vscf_pkcs5_pbkdf2_alg_id(ctx)

    def vscf_pkcs5_pbkdf2_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_pkcs5_pbkdf2_produce_alg_info = self._lib.vscf_pkcs5_pbkdf2_produce_alg_info
        vscf_pkcs5_pbkdf2_produce_alg_info.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t)]
        vscf_pkcs5_pbkdf2_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_pkcs5_pbkdf2_produce_alg_info(ctx)

    def vscf_pkcs5_pbkdf2_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_pkcs5_pbkdf2_restore_alg_info = self._lib.vscf_pkcs5_pbkdf2_restore_alg_info
        vscf_pkcs5_pbkdf2_restore_alg_info.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t), POINTER(vscf_impl_t)]
        vscf_pkcs5_pbkdf2_restore_alg_info.restype = c_int
        return vscf_pkcs5_pbkdf2_restore_alg_info(ctx, alg_info)

    def vscf_pkcs5_pbkdf2_derive(self, ctx, data, key_len, key):
        """Derive key of the requested length from the given data."""
        vscf_pkcs5_pbkdf2_derive = self._lib.vscf_pkcs5_pbkdf2_derive
        vscf_pkcs5_pbkdf2_derive.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t), vsc_data_t, c_size_t, POINTER(vsc_buffer_t)]
        vscf_pkcs5_pbkdf2_derive.restype = None
        return vscf_pkcs5_pbkdf2_derive(ctx, data, key_len, key)

    def vscf_pkcs5_pbkdf2_reset(self, ctx, salt, iteration_count):
        """Prepare algorithm to derive new key."""
        vscf_pkcs5_pbkdf2_reset = self._lib.vscf_pkcs5_pbkdf2_reset
        vscf_pkcs5_pbkdf2_reset.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t), vsc_data_t, c_size_t]
        vscf_pkcs5_pbkdf2_reset.restype = None
        return vscf_pkcs5_pbkdf2_reset(ctx, salt, iteration_count)

    def vscf_pkcs5_pbkdf2_set_info(self, ctx, info):
        """Setup application specific information (optional).
        Can be empty."""
        vscf_pkcs5_pbkdf2_set_info = self._lib.vscf_pkcs5_pbkdf2_set_info
        vscf_pkcs5_pbkdf2_set_info.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t), vsc_data_t]
        vscf_pkcs5_pbkdf2_set_info.restype = None
        return vscf_pkcs5_pbkdf2_set_info(ctx, info)

    def vscf_pkcs5_pbkdf2_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_pkcs5_pbkdf2_setup_defaults = self._lib.vscf_pkcs5_pbkdf2_setup_defaults
        vscf_pkcs5_pbkdf2_setup_defaults.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t)]
        vscf_pkcs5_pbkdf2_setup_defaults.restype = None
        return vscf_pkcs5_pbkdf2_setup_defaults(ctx)

    def vscf_pkcs5_pbkdf2_shallow_copy(self, ctx):
        vscf_pkcs5_pbkdf2_shallow_copy = self._lib.vscf_pkcs5_pbkdf2_shallow_copy
        vscf_pkcs5_pbkdf2_shallow_copy.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t)]
        vscf_pkcs5_pbkdf2_shallow_copy.restype = POINTER(vscf_pkcs5_pbkdf2_t)
        return vscf_pkcs5_pbkdf2_shallow_copy(ctx)

    def vscf_pkcs5_pbkdf2_impl(self, ctx):
        vscf_pkcs5_pbkdf2_impl = self._lib.vscf_pkcs5_pbkdf2_impl
        vscf_pkcs5_pbkdf2_impl.argtypes = [POINTER(vscf_pkcs5_pbkdf2_t)]
        vscf_pkcs5_pbkdf2_impl.restype = POINTER(vscf_impl_t)
        return vscf_pkcs5_pbkdf2_impl(ctx)
