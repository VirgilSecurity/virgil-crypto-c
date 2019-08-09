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


class vscf_signer_t(Structure):
    pass


class VscfSigner(object):
    """Sign data of any size."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_signer_new(self):
        vscf_signer_new = self._lib.vscf_signer_new
        vscf_signer_new.argtypes = []
        vscf_signer_new.restype = POINTER(vscf_signer_t)
        return vscf_signer_new()

    def vscf_signer_delete(self, ctx):
        vscf_signer_delete = self._lib.vscf_signer_delete
        vscf_signer_delete.argtypes = [POINTER(vscf_signer_t)]
        vscf_signer_delete.restype = None
        return vscf_signer_delete(ctx)

    def vscf_signer_use_hash(self, ctx, hash):
        vscf_signer_use_hash = self._lib.vscf_signer_use_hash
        vscf_signer_use_hash.argtypes = [POINTER(vscf_signer_t), POINTER(vscf_impl_t)]
        vscf_signer_use_hash.restype = None
        return vscf_signer_use_hash(ctx, hash)

    def vscf_signer_use_random(self, ctx, random):
        vscf_signer_use_random = self._lib.vscf_signer_use_random
        vscf_signer_use_random.argtypes = [POINTER(vscf_signer_t), POINTER(vscf_impl_t)]
        vscf_signer_use_random.restype = None
        return vscf_signer_use_random(ctx, random)

    def vscf_signer_reset(self, ctx):
        """Start a processing a new signature."""
        vscf_signer_reset = self._lib.vscf_signer_reset
        vscf_signer_reset.argtypes = [POINTER(vscf_signer_t)]
        vscf_signer_reset.restype = None
        return vscf_signer_reset(ctx)

    def vscf_signer_append_data(self, ctx, data):
        """Add given data to the signed data."""
        vscf_signer_append_data = self._lib.vscf_signer_append_data
        vscf_signer_append_data.argtypes = [POINTER(vscf_signer_t), vsc_data_t]
        vscf_signer_append_data.restype = None
        return vscf_signer_append_data(ctx, data)

    def vscf_signer_signature_len(self, ctx, private_key):
        """Return length of the signature."""
        vscf_signer_signature_len = self._lib.vscf_signer_signature_len
        vscf_signer_signature_len.argtypes = [POINTER(vscf_signer_t), POINTER(vscf_impl_t)]
        vscf_signer_signature_len.restype = c_size_t
        return vscf_signer_signature_len(ctx, private_key)

    def vscf_signer_sign(self, ctx, private_key, signature):
        """Accomplish signing and return signature."""
        vscf_signer_sign = self._lib.vscf_signer_sign
        vscf_signer_sign.argtypes = [POINTER(vscf_signer_t), POINTER(vscf_impl_t), POINTER(vsc_buffer_t)]
        vscf_signer_sign.restype = c_int
        return vscf_signer_sign(ctx, private_key, signature)

    def vscf_signer_shallow_copy(self, ctx):
        vscf_signer_shallow_copy = self._lib.vscf_signer_shallow_copy
        vscf_signer_shallow_copy.argtypes = [POINTER(vscf_signer_t)]
        vscf_signer_shallow_copy.restype = POINTER(vscf_signer_t)
        return vscf_signer_shallow_copy(ctx)
