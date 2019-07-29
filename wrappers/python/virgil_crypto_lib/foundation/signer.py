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
from ._c_bridge import VscfSigner
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge import VscfStatus


class Signer(object):
    """Sign data of any size."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_signer = VscfSigner()
        self.ctx = self._lib_vscf_signer.vscf_signer_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_signer.vscf_signer_delete(self.ctx)

    def set_hash(self, hash):
        self._lib_vscf_signer.vscf_signer_use_hash(self.ctx, hash.c_impl)

    def set_random(self, random):
        self._lib_vscf_signer.vscf_signer_use_random(self.ctx, random.c_impl)

    def reset(self):
        """Start a processing a new signature."""
        self._lib_vscf_signer.vscf_signer_reset(self.ctx)

    def append_data(self, data):
        """Add given data to the signed data."""
        d_data = Data(data)
        self._lib_vscf_signer.vscf_signer_append_data(self.ctx, d_data.data)

    def signature_len(self, private_key):
        """Return length of the signature."""
        result = self._lib_vscf_signer.vscf_signer_signature_len(self.ctx, private_key.c_impl)
        return result

    def sign(self, private_key):
        """Accomplish signing and return signature."""
        signature = Buffer(self.signature_len(private_key=private_key))
        status = self._lib_vscf_signer.vscf_signer_sign(self.ctx, private_key.c_impl, signature.c_buffer)
        VscfStatus.handle_status(status)
        return signature.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_signer = VscfSigner()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_signer = VscfSigner()
        inst.ctx = inst._lib_vscf_signer.vscf_signer_shallow_copy(c_ctx)
        return inst
