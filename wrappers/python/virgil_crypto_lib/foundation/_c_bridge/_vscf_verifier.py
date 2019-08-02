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
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_impl import vscf_impl_t


class vscf_verifier_t(Structure):
    pass


class VscfVerifier(object):
    """Verify data of any size.
    Compatible with the class "signer"."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_verifier_new(self):
        vscf_verifier_new = self._lib.vscf_verifier_new
        vscf_verifier_new.argtypes = []
        vscf_verifier_new.restype = POINTER(vscf_verifier_t)
        return vscf_verifier_new()

    def vscf_verifier_delete(self, ctx):
        vscf_verifier_delete = self._lib.vscf_verifier_delete
        vscf_verifier_delete.argtypes = [POINTER(vscf_verifier_t)]
        vscf_verifier_delete.restype = None
        return vscf_verifier_delete(ctx)

    def vscf_verifier_reset(self, ctx, signature):
        """Start verifying a signature."""
        vscf_verifier_reset = self._lib.vscf_verifier_reset
        vscf_verifier_reset.argtypes = [POINTER(vscf_verifier_t), vsc_data_t]
        vscf_verifier_reset.restype = c_int
        return vscf_verifier_reset(ctx, signature)

    def vscf_verifier_append_data(self, ctx, data):
        """Add given data to the signed data."""
        vscf_verifier_append_data = self._lib.vscf_verifier_append_data
        vscf_verifier_append_data.argtypes = [POINTER(vscf_verifier_t), vsc_data_t]
        vscf_verifier_append_data.restype = None
        return vscf_verifier_append_data(ctx, data)

    def vscf_verifier_verify(self, ctx, public_key):
        """Verify accumulated data."""
        vscf_verifier_verify = self._lib.vscf_verifier_verify
        vscf_verifier_verify.argtypes = [POINTER(vscf_verifier_t), POINTER(vscf_impl_t)]
        vscf_verifier_verify.restype = c_bool
        return vscf_verifier_verify(ctx, public_key)

    def vscf_verifier_shallow_copy(self, ctx):
        vscf_verifier_shallow_copy = self._lib.vscf_verifier_shallow_copy
        vscf_verifier_shallow_copy.argtypes = [POINTER(vscf_verifier_t)]
        vscf_verifier_shallow_copy.restype = POINTER(vscf_verifier_t)
        return vscf_verifier_shallow_copy(ctx)
