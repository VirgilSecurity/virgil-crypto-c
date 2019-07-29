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
from ._c_bridge import VscfBrainkeyClient
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer


class BrainkeyClient(object):

    POINT_LEN = 65
    MPI_LEN = 32
    SEED_LEN = 32
    MAX_PASSWORD_LEN = 128
    MAX_KEY_NAME_LEN = 128

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_brainkey_client = VscfBrainkeyClient()
        self.ctx = self._lib_vscf_brainkey_client.vscf_brainkey_client_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_brainkey_client.vscf_brainkey_client_delete(self.ctx)

    def set_random(self, random):
        """Random used for key generation, proofs, etc."""
        self._lib_vscf_brainkey_client.vscf_brainkey_client_use_random(self.ctx, random.c_impl)

    def set_operation_random(self, operation_random):
        """Random used for crypto operations to make them const-time"""
        self._lib_vscf_brainkey_client.vscf_brainkey_client_use_operation_random(self.ctx, operation_random.c_impl)

    def setup_defaults(self):
        status = self._lib_vscf_brainkey_client.vscf_brainkey_client_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def blind(self, password):
        d_password = Data(password)
        deblind_factor = Buffer(self.MPI_LEN)
        blinded_point = Buffer(self.POINT_LEN)
        status = self._lib_vscf_brainkey_client.vscf_brainkey_client_blind(self.ctx, d_password.data, deblind_factor.c_buffer, blinded_point.c_buffer)
        VscfStatus.handle_status(status)
        return deblind_factor.get_bytes(), blinded_point.get_bytes()

    def deblind(self, password, hardened_point, deblind_factor, key_name):
        d_password = Data(password)
        d_hardened_point = Data(hardened_point)
        d_deblind_factor = Data(deblind_factor)
        d_key_name = Data(key_name)
        seed = Buffer(self.POINT_LEN)
        status = self._lib_vscf_brainkey_client.vscf_brainkey_client_deblind(self.ctx, d_password.data, d_hardened_point.data, d_deblind_factor.data, d_key_name.data, seed.c_buffer)
        VscfStatus.handle_status(status)
        return seed.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_brainkey_client = VscfBrainkeyClient()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_brainkey_client = VscfBrainkeyClient()
        inst.ctx = inst._lib_vscf_brainkey_client.vscf_brainkey_client_shallow_copy(c_ctx)
        return inst
