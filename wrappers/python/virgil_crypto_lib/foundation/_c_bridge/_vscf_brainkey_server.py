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
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t


class vscf_brainkey_server_t(Structure):
    pass


class VscfBrainkeyServer(object):

    POINT_LEN = 65
    MPI_LEN = 32

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_brainkey_server_new(self):
        vscf_brainkey_server_new = self._lib.vscf_brainkey_server_new
        vscf_brainkey_server_new.argtypes = []
        vscf_brainkey_server_new.restype = POINTER(vscf_brainkey_server_t)
        return vscf_brainkey_server_new()

    def vscf_brainkey_server_delete(self, ctx):
        vscf_brainkey_server_delete = self._lib.vscf_brainkey_server_delete
        vscf_brainkey_server_delete.argtypes = [POINTER(vscf_brainkey_server_t)]
        vscf_brainkey_server_delete.restype = None
        return vscf_brainkey_server_delete(ctx)

    def vscf_brainkey_server_use_random(self, ctx, random):
        """Random used for key generation, proofs, etc."""
        vscf_brainkey_server_use_random = self._lib.vscf_brainkey_server_use_random
        vscf_brainkey_server_use_random.argtypes = [POINTER(vscf_brainkey_server_t), POINTER(vscf_impl_t)]
        vscf_brainkey_server_use_random.restype = None
        return vscf_brainkey_server_use_random(ctx, random)

    def vscf_brainkey_server_use_operation_random(self, ctx, operation_random):
        """Random used for crypto operations to make them const-time"""
        vscf_brainkey_server_use_operation_random = self._lib.vscf_brainkey_server_use_operation_random
        vscf_brainkey_server_use_operation_random.argtypes = [POINTER(vscf_brainkey_server_t), POINTER(vscf_impl_t)]
        vscf_brainkey_server_use_operation_random.restype = None
        return vscf_brainkey_server_use_operation_random(ctx, operation_random)

    def vscf_brainkey_server_setup_defaults(self, ctx):
        vscf_brainkey_server_setup_defaults = self._lib.vscf_brainkey_server_setup_defaults
        vscf_brainkey_server_setup_defaults.argtypes = [POINTER(vscf_brainkey_server_t)]
        vscf_brainkey_server_setup_defaults.restype = c_int
        return vscf_brainkey_server_setup_defaults(ctx)

    def vscf_brainkey_server_generate_identity_secret(self, ctx, identity_secret):
        vscf_brainkey_server_generate_identity_secret = self._lib.vscf_brainkey_server_generate_identity_secret
        vscf_brainkey_server_generate_identity_secret.argtypes = [POINTER(vscf_brainkey_server_t), POINTER(vsc_buffer_t)]
        vscf_brainkey_server_generate_identity_secret.restype = c_int
        return vscf_brainkey_server_generate_identity_secret(ctx, identity_secret)

    def vscf_brainkey_server_harden(self, ctx, identity_secret, blinded_point, hardened_point):
        vscf_brainkey_server_harden = self._lib.vscf_brainkey_server_harden
        vscf_brainkey_server_harden.argtypes = [POINTER(vscf_brainkey_server_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_brainkey_server_harden.restype = c_int
        return vscf_brainkey_server_harden(ctx, identity_secret, blinded_point, hardened_point)

    def vscf_brainkey_server_shallow_copy(self, ctx):
        vscf_brainkey_server_shallow_copy = self._lib.vscf_brainkey_server_shallow_copy
        vscf_brainkey_server_shallow_copy.argtypes = [POINTER(vscf_brainkey_server_t)]
        vscf_brainkey_server_shallow_copy.restype = POINTER(vscf_brainkey_server_t)
        return vscf_brainkey_server_shallow_copy(ctx)
