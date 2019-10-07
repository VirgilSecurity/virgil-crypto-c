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


class vscf_sha512_t(Structure):
    pass


class VscfSha512(object):
    """This is MbedTLS implementation of SHA512."""

    # Length of the digest (hashing output) in bytes.
    DIGEST_LEN = 64
    # Block length of the digest function in bytes.
    BLOCK_LEN = 128

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_sha512_new(self):
        vscf_sha512_new = self._lib.vscf_sha512_new
        vscf_sha512_new.argtypes = []
        vscf_sha512_new.restype = POINTER(vscf_sha512_t)
        return vscf_sha512_new()

    def vscf_sha512_delete(self, ctx):
        vscf_sha512_delete = self._lib.vscf_sha512_delete
        vscf_sha512_delete.argtypes = [POINTER(vscf_sha512_t)]
        vscf_sha512_delete.restype = None
        return vscf_sha512_delete(ctx)

    def vscf_sha512_alg_id(self, ctx):
        """Provide algorithm identificator."""
        vscf_sha512_alg_id = self._lib.vscf_sha512_alg_id
        vscf_sha512_alg_id.argtypes = [POINTER(vscf_sha512_t)]
        vscf_sha512_alg_id.restype = c_int
        return vscf_sha512_alg_id(ctx)

    def vscf_sha512_produce_alg_info(self, ctx):
        """Produce object with algorithm information and configuration parameters."""
        vscf_sha512_produce_alg_info = self._lib.vscf_sha512_produce_alg_info
        vscf_sha512_produce_alg_info.argtypes = [POINTER(vscf_sha512_t)]
        vscf_sha512_produce_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_sha512_produce_alg_info(ctx)

    def vscf_sha512_restore_alg_info(self, ctx, alg_info):
        """Restore algorithm configuration from the given object."""
        vscf_sha512_restore_alg_info = self._lib.vscf_sha512_restore_alg_info
        vscf_sha512_restore_alg_info.argtypes = [POINTER(vscf_sha512_t), POINTER(vscf_impl_t)]
        vscf_sha512_restore_alg_info.restype = c_int
        return vscf_sha512_restore_alg_info(ctx, alg_info)

    def vscf_sha512_hash(self, data, digest):
        """Calculate hash over given data."""
        vscf_sha512_hash = self._lib.vscf_sha512_hash
        vscf_sha512_hash.argtypes = [vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_sha512_hash.restype = None
        return vscf_sha512_hash(data, digest)

    def vscf_sha512_start(self, ctx):
        """Start a new hashing."""
        vscf_sha512_start = self._lib.vscf_sha512_start
        vscf_sha512_start.argtypes = [POINTER(vscf_sha512_t)]
        vscf_sha512_start.restype = None
        return vscf_sha512_start(ctx)

    def vscf_sha512_update(self, ctx, data):
        """Add given data to the hash."""
        vscf_sha512_update = self._lib.vscf_sha512_update
        vscf_sha512_update.argtypes = [POINTER(vscf_sha512_t), vsc_data_t]
        vscf_sha512_update.restype = None
        return vscf_sha512_update(ctx, data)

    def vscf_sha512_finish(self, ctx, digest):
        """Accompilsh hashing and return it's result (a message digest)."""
        vscf_sha512_finish = self._lib.vscf_sha512_finish
        vscf_sha512_finish.argtypes = [POINTER(vscf_sha512_t), POINTER(vsc_buffer_t)]
        vscf_sha512_finish.restype = None
        return vscf_sha512_finish(ctx, digest)

    def vscf_sha512_shallow_copy(self, ctx):
        vscf_sha512_shallow_copy = self._lib.vscf_sha512_shallow_copy
        vscf_sha512_shallow_copy.argtypes = [POINTER(vscf_sha512_t)]
        vscf_sha512_shallow_copy.restype = POINTER(vscf_sha512_t)
        return vscf_sha512_shallow_copy(ctx)

    def vscf_sha512_impl(self, ctx):
        vscf_sha512_impl = self._lib.vscf_sha512_impl
        vscf_sha512_impl.argtypes = [POINTER(vscf_sha512_t)]
        vscf_sha512_impl.restype = POINTER(vscf_impl_t)
        return vscf_sha512_impl(ctx)
