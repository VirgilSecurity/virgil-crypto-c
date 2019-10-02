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


class vscf_brainkey_client_t(Structure):
    pass


class VscfBrainkeyClient(object):

    POINT_LEN = 65
    MPI_LEN = 32
    SEED_LEN = 32
    MAX_PASSWORD_LEN = 128
    MAX_KEY_NAME_LEN = 128

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_brainkey_client_new(self):
        vscf_brainkey_client_new = self._lib.vscf_brainkey_client_new
        vscf_brainkey_client_new.argtypes = []
        vscf_brainkey_client_new.restype = POINTER(vscf_brainkey_client_t)
        return vscf_brainkey_client_new()

    def vscf_brainkey_client_delete(self, ctx):
        vscf_brainkey_client_delete = self._lib.vscf_brainkey_client_delete
        vscf_brainkey_client_delete.argtypes = [POINTER(vscf_brainkey_client_t)]
        vscf_brainkey_client_delete.restype = None
        return vscf_brainkey_client_delete(ctx)

    def vscf_brainkey_client_use_random(self, ctx, random):
        """Random used for key generation, proofs, etc."""
        vscf_brainkey_client_use_random = self._lib.vscf_brainkey_client_use_random
        vscf_brainkey_client_use_random.argtypes = [POINTER(vscf_brainkey_client_t), POINTER(vscf_impl_t)]
        vscf_brainkey_client_use_random.restype = None
        return vscf_brainkey_client_use_random(ctx, random)

    def vscf_brainkey_client_use_operation_random(self, ctx, operation_random):
        """Random used for crypto operations to make them const-time"""
        vscf_brainkey_client_use_operation_random = self._lib.vscf_brainkey_client_use_operation_random
        vscf_brainkey_client_use_operation_random.argtypes = [POINTER(vscf_brainkey_client_t), POINTER(vscf_impl_t)]
        vscf_brainkey_client_use_operation_random.restype = None
        return vscf_brainkey_client_use_operation_random(ctx, operation_random)

    def vscf_brainkey_client_setup_defaults(self, ctx):
        vscf_brainkey_client_setup_defaults = self._lib.vscf_brainkey_client_setup_defaults
        vscf_brainkey_client_setup_defaults.argtypes = [POINTER(vscf_brainkey_client_t)]
        vscf_brainkey_client_setup_defaults.restype = c_int
        return vscf_brainkey_client_setup_defaults(ctx)

    def vscf_brainkey_client_blind(self, ctx, password, deblind_factor, blinded_point):
        vscf_brainkey_client_blind = self._lib.vscf_brainkey_client_blind
        vscf_brainkey_client_blind.argtypes = [POINTER(vscf_brainkey_client_t), vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vscf_brainkey_client_blind.restype = c_int
        return vscf_brainkey_client_blind(ctx, password, deblind_factor, blinded_point)

    def vscf_brainkey_client_deblind(self, ctx, password, hardened_point, deblind_factor, key_name, seed):
        vscf_brainkey_client_deblind = self._lib.vscf_brainkey_client_deblind
        vscf_brainkey_client_deblind.argtypes = [POINTER(vscf_brainkey_client_t), vsc_data_t, vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_brainkey_client_deblind.restype = c_int
        return vscf_brainkey_client_deblind(ctx, password, hardened_point, deblind_factor, key_name, seed)

    def vscf_brainkey_client_shallow_copy(self, ctx):
        vscf_brainkey_client_shallow_copy = self._lib.vscf_brainkey_client_shallow_copy
        vscf_brainkey_client_shallow_copy.argtypes = [POINTER(vscf_brainkey_client_t)]
        vscf_brainkey_client_shallow_copy.restype = POINTER(vscf_brainkey_client_t)
        return vscf_brainkey_client_shallow_copy(ctx)
