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


class vscf_hmac_t(Structure):
    pass


class VscfHmac(object):
    """Virgil Security implementation of HMAC algorithm (RFC 2104) (FIPS PUB 198-1)."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_hmac_new(self):
        vscf_hmac_new = self._lib.vscf_hmac_new
        vscf_hmac_new.argtypes = []
        vscf_hmac_new.restype = POINTER(vscf_hmac_t)
        return vscf_hmac_new()

    def vscf_hmac_delete(self, ctx):
        vscf_hmac_delete = self._lib.vscf_hmac_delete
        vscf_hmac_delete.argtypes = [POINTER(vscf_hmac_t)]
        vscf_hmac_delete.restype = None
        return vscf_hmac_delete(ctx)

    def vscf_hmac_use_hash(self, ctx, hash):
        vscf_hmac_use_hash = self._lib.vscf_hmac_use_hash
        vscf_hmac_use_hash.argtypes = [POINTER(vscf_hmac_t), POINTER(vscf_impl_t)]
        vscf_hmac_use_hash.restype = None
        return vscf_hmac_use_hash(ctx, hash)

    def vscf_hmac_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_hmac_alg_id = self._lib.vscf_hmac_alg_id
        vscf_hmac_alg_id.argtypes = [POINTER(vscf_hmac_t)]
        vscf_hmac_alg_id.restype = c_int
        return vscf_hmac_alg_id(ctx)

    def vscf_hmac_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_hmac_produce_alg_info = self._lib.vscf_hmac_produce_alg_info
        vscf_hmac_produce_alg_info.argtypes = [POINTER(vscf_hmac_t)]
        vscf_hmac_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_hmac_produce_alg_info(ctx)

    def vscf_hmac_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_hmac_restore_alg_info = self._lib.vscf_hmac_restore_alg_info
        vscf_hmac_restore_alg_info.argtypes = [POINTER(vscf_hmac_t), POINTER(vscf_impl_t)]
        vscf_hmac_restore_alg_info.restype = c_int
        return vscf_hmac_restore_alg_info(ctx, alg_info)

    def vscf_hmac_digest_len(self, ctx):
        """Size of the digest (mac output) in bytes."""
        vscf_hmac_digest_len = self._lib.vscf_hmac_digest_len
        vscf_hmac_digest_len.argtypes = [POINTER(vscf_hmac_t)]
        vscf_hmac_digest_len.restype = c_size_t
        return vscf_hmac_digest_len(ctx)

    def vscf_hmac_mac(self, ctx, key, data, mac):
        """Calculate MAC over given data."""
        vscf_hmac_mac = self._lib.vscf_hmac_mac
        vscf_hmac_mac.argtypes = [POINTER(vscf_hmac_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_hmac_mac.restype = None
        return vscf_hmac_mac(ctx, key, data, mac)

    def vscf_hmac_start(self, ctx, key):
        """Start a new MAC."""
        vscf_hmac_start = self._lib.vscf_hmac_start
        vscf_hmac_start.argtypes = [POINTER(vscf_hmac_t), vsc_data_t]
        vscf_hmac_start.restype = None
        return vscf_hmac_start(ctx, key)

    def vscf_hmac_update(self, ctx, data):
        """Add given data to the MAC."""
        vscf_hmac_update = self._lib.vscf_hmac_update
        vscf_hmac_update.argtypes = [POINTER(vscf_hmac_t), vsc_data_t]
        vscf_hmac_update.restype = None
        return vscf_hmac_update(ctx, data)

    def vscf_hmac_finish(self, ctx, mac):
        """Accomplish MAC and return it's result (a message digest)."""
        vscf_hmac_finish = self._lib.vscf_hmac_finish
        vscf_hmac_finish.argtypes = [POINTER(vscf_hmac_t), POINTER(vsc_buffer_t)]
        vscf_hmac_finish.restype = None
        return vscf_hmac_finish(ctx, mac)

    def vscf_hmac_reset(self, ctx):
        """Prepare to authenticate a new message with the same key
        as the previous MAC operation."""
        vscf_hmac_reset = self._lib.vscf_hmac_reset
        vscf_hmac_reset.argtypes = [POINTER(vscf_hmac_t)]
        vscf_hmac_reset.restype = None
        return vscf_hmac_reset(ctx)

    def vscf_hmac_shallow_copy(self, ctx):
        vscf_hmac_shallow_copy = self._lib.vscf_hmac_shallow_copy
        vscf_hmac_shallow_copy.argtypes = [POINTER(vscf_hmac_t)]
        vscf_hmac_shallow_copy.restype = POINTER(vscf_hmac_t)
        return vscf_hmac_shallow_copy(ctx)

    def vscf_hmac_impl(self, ctx):
        vscf_hmac_impl = self._lib.vscf_hmac_impl
        vscf_hmac_impl.argtypes = [POINTER(vscf_hmac_t)]
        vscf_hmac_impl.restype = POINTER(vscf_impl_t)
        return vscf_hmac_impl(ctx)
