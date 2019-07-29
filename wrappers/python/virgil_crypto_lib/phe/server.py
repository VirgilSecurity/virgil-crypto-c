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
from ._c_bridge import VscePheServer
from ._c_bridge import VsceStatus
from .common import Common
from virgil_crypto_lib.common._c_bridge import Buffer
from virgil_crypto_lib.common._c_bridge import Data


class Server(object):
    """Class for server-side PHE crypto operations.
    This class is thread-safe in case if VSCE_MULTI_THREADING defined."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vsce_phe_server = VscePheServer()
        self.ctx = self._lib_vsce_phe_server.vsce_phe_server_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vsce_phe_server.vsce_phe_server_delete(self.ctx)

    def set_random(self, random):
        """Random used for key generation, proofs, etc."""
        self._lib_vsce_phe_server.vsce_phe_server_use_random(self.ctx, random.c_impl)

    def set_operation_random(self, operation_random):
        """Random used for crypto operations to make them const-time"""
        self._lib_vsce_phe_server.vsce_phe_server_use_operation_random(self.ctx, operation_random.c_impl)

    def setup_defaults(self):
        status = self._lib_vsce_phe_server.vsce_phe_server_setup_defaults(self.ctx)
        VsceStatus.handle_status(status)

    def generate_server_key_pair(self):
        """Generates new NIST P-256 server key pair for some client"""
        server_private_key = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        server_public_key = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        status = self._lib_vsce_phe_server.vsce_phe_server_generate_server_key_pair(self.ctx, server_private_key.c_buffer, server_public_key.c_buffer)
        VsceStatus.handle_status(status)
        return server_private_key.get_bytes(), server_public_key.get_bytes()

    def enrollment_response_len(self):
        """Buffer size needed to fit EnrollmentResponse"""
        result = self._lib_vsce_phe_server.vsce_phe_server_enrollment_response_len(self.ctx)
        return result

    def get_enrollment(self, server_private_key, server_public_key):
        """Generates a new random enrollment and proof for a new user"""
        d_server_private_key = Data(server_private_key)
        d_server_public_key = Data(server_public_key)
        enrollment_response = Buffer(self.enrollment_response_len())
        status = self._lib_vsce_phe_server.vsce_phe_server_get_enrollment(self.ctx, d_server_private_key.data, d_server_public_key.data, enrollment_response.c_buffer)
        VsceStatus.handle_status(status)
        return enrollment_response.get_bytes()

    def verify_password_response_len(self):
        """Buffer size needed to fit VerifyPasswordResponse"""
        result = self._lib_vsce_phe_server.vsce_phe_server_verify_password_response_len(self.ctx)
        return result

    def verify_password(self, server_private_key, server_public_key, verify_password_request):
        """Verifies existing user's password and generates response with proof"""
        d_server_private_key = Data(server_private_key)
        d_server_public_key = Data(server_public_key)
        d_verify_password_request = Data(verify_password_request)
        verify_password_response = Buffer(self.verify_password_response_len())
        status = self._lib_vsce_phe_server.vsce_phe_server_verify_password(self.ctx, d_server_private_key.data, d_server_public_key.data, d_verify_password_request.data, verify_password_response.c_buffer)
        VsceStatus.handle_status(status)
        return verify_password_response.get_bytes()

    def update_token_len(self):
        """Buffer size needed to fit UpdateToken"""
        result = self._lib_vsce_phe_server.vsce_phe_server_update_token_len(self.ctx)
        return result

    def rotate_keys(self, server_private_key):
        """Updates server's private and public keys and issues an update token for use on client's side"""
        d_server_private_key = Data(server_private_key)
        new_server_private_key = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        new_server_public_key = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        update_token = Buffer(self.update_token_len())
        status = self._lib_vsce_phe_server.vsce_phe_server_rotate_keys(self.ctx, d_server_private_key.data, new_server_private_key.c_buffer, new_server_public_key.c_buffer, update_token.c_buffer)
        VsceStatus.handle_status(status)
        return new_server_private_key.get_bytes(), new_server_public_key.get_bytes(), update_token.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_phe_server = VscePheServer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_phe_server = VscePheServer()
        inst.ctx = inst._lib_vsce_phe_server.vsce_phe_server_shallow_copy(c_ctx)
        return inst
