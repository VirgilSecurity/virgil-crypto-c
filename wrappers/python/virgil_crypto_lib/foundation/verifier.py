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
from ._c_bridge import VscfVerifier
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge import VscfStatus


class Verifier(object):
    """Verify data of any size.
    Compatible with the class "signer"."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_verifier = VscfVerifier()
        self.ctx = self._lib_vscf_verifier.vscf_verifier_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_verifier.vscf_verifier_delete(self.ctx)

    def reset(self, signature):
        """Start verifying a signature."""
        d_signature = Data(signature)
        status = self._lib_vscf_verifier.vscf_verifier_reset(self.ctx, d_signature.data)
        VscfStatus.handle_status(status)

    def append_data(self, data):
        """Add given data to the signed data."""
        d_data = Data(data)
        self._lib_vscf_verifier.vscf_verifier_append_data(self.ctx, d_data.data)

    def verify(self, public_key):
        """Verify accumulated data."""
        result = self._lib_vscf_verifier.vscf_verifier_verify(self.ctx, public_key.c_impl)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_verifier = VscfVerifier()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_verifier = VscfVerifier()
        inst.ctx = inst._lib_vscf_verifier.vscf_verifier_shallow_copy(c_ctx)
        return inst
