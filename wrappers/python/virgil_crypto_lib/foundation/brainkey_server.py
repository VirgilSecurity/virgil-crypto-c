# Copyright (C) 2015-2026 Virgil Security, Inc.
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
from ._c_bridge import VscfBrainkeyServer
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge._vscf_error import vscf_error_t


class BrainkeyServer(object):

    POINT_LEN = 65
    MPI_LEN = 32
    PROOF_VALUE_LEN = 32

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_brainkey_server = VscfBrainkeyServer()
        self.ctx = self._lib_vscf_brainkey_server.vscf_brainkey_server_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_brainkey_server.vscf_brainkey_server_delete(self.ctx)

    def set_random(self, random):
        """Random used for key generation, proofs, etc."""
        self._lib_vscf_brainkey_server.vscf_brainkey_server_use_random(self.ctx, random.c_impl)

    def set_operation_random(self, operation_random):
        """Random used for crypto operations to make them const-time"""
        self._lib_vscf_brainkey_server.vscf_brainkey_server_use_operation_random(self.ctx, operation_random.c_impl)

    def setup_defaults(self):
        status = self._lib_vscf_brainkey_server.vscf_brainkey_server_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def generate_identity_secret(self):
        identity_secret = Buffer(self.MPI_LEN)
        status = self._lib_vscf_brainkey_server.vscf_brainkey_server_generate_identity_secret(self.ctx, identity_secret.c_buffer)
        VscfStatus.handle_status(status)
        return identity_secret.get_bytes()

    def harden(self, identity_secret, blinded_point):
        d_identity_secret = Data(identity_secret)
        d_blinded_point = Data(blinded_point)
        hardened_point = Buffer(self.POINT_LEN)
        status = self._lib_vscf_brainkey_server.vscf_brainkey_server_harden(self.ctx, d_identity_secret.data, d_blinded_point.data, hardened_point.c_buffer)
        VscfStatus.handle_status(status)
        return hardened_point.get_bytes()

    def compute_public_key(self, identity_secret):
        """Computes the server's public key G_x = x*G from the given identity secret x.
Required by the client to verify DLEQ proofs."""
        d_identity_secret = Data(identity_secret)
        public_key = Buffer(self.POINT_LEN)
        status = self._lib_vscf_brainkey_server.vscf_brainkey_server_compute_public_key(self.ctx, d_identity_secret.data, public_key.c_buffer)
        VscfStatus.handle_status(status)
        return public_key.get_bytes()

    def prove(self, blinded_point, hardened_point, identity_secret, server_public_key):
        """Generates a DLEQ proof that hardened_point = x * blinded_point using the same
identity secret x as server_public_key = x * G.
Client must call verify() before deblind() to authenticate the server response."""
        d_blinded_point = Data(blinded_point)
        d_hardened_point = Data(hardened_point)
        d_identity_secret = Data(identity_secret)
        d_server_public_key = Data(server_public_key)
        error = vscf_error_t()
        proof_value_c = Buffer(self.PROOF_VALUE_LEN)
        proof_value_s = Buffer(self.PROOF_VALUE_LEN)
        result = self._lib_vscf_brainkey_server.vscf_brainkey_server_prove(self.ctx, d_blinded_point.data, d_hardened_point.data, d_identity_secret.data, d_server_public_key.data, proof_value_c.c_buffer, proof_value_s.c_buffer, error)
        VscfStatus.handle_status(error.status)
        return result, proof_value_c.get_bytes(), proof_value_s.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_brainkey_server = VscfBrainkeyServer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_brainkey_server = VscfBrainkeyServer()
        inst.ctx = inst._lib_vscf_brainkey_server.vscf_brainkey_server_shallow_copy(c_ctx)
        return inst
