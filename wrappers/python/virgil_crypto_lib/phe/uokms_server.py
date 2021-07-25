# Copyright (C) 2015-2021 Virgil Security, Inc.
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
from ._c_bridge import VsceUokmsServer
from ._c_bridge import VsceStatus
from .common import Common
from virgil_crypto_lib.common._c_bridge import Buffer
from virgil_crypto_lib.common._c_bridge import Data


class UokmsServer(object):
    """Class implements UOKMS for server-side."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vsce_uokms_server = VsceUokmsServer()
        self.ctx = self._lib_vsce_uokms_server.vsce_uokms_server_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vsce_uokms_server.vsce_uokms_server_delete(self.ctx)

    def set_random(self, random):
        """Random used for key generation, proofs, etc."""
        self._lib_vsce_uokms_server.vsce_uokms_server_use_random(self.ctx, random.c_impl)

    def set_operation_random(self, operation_random):
        """Random used for crypto operations to make them const-time"""
        self._lib_vsce_uokms_server.vsce_uokms_server_use_operation_random(self.ctx, operation_random.c_impl)

    def setup_defaults(self):
        """Setups dependencies with default values."""
        status = self._lib_vsce_uokms_server.vsce_uokms_server_setup_defaults(self.ctx)
        VsceStatus.handle_status(status)

    def generate_server_key_pair(self):
        """Generates new NIST P-256 server key pair for some client"""
        server_private_key = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        server_public_key = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        status = self._lib_vsce_uokms_server.vsce_uokms_server_generate_server_key_pair(self.ctx, server_private_key.c_buffer, server_public_key.c_buffer)
        VsceStatus.handle_status(status)
        return server_private_key.get_bytes(), server_public_key.get_bytes()

    def decrypt_response_len(self):
        """Buffer size needed to fit DecryptResponse"""
        result = self._lib_vsce_uokms_server.vsce_uokms_server_decrypt_response_len(self.ctx)
        return result

    def process_decrypt_request(self, server_private_key, decrypt_request):
        """Processed client's decrypt request"""
        d_server_private_key = Data(server_private_key)
        d_decrypt_request = Data(decrypt_request)
        decrypt_response = Buffer(self.decrypt_response_len())
        status = self._lib_vsce_uokms_server.vsce_uokms_server_process_decrypt_request(self.ctx, d_server_private_key.data, d_decrypt_request.data, decrypt_response.c_buffer)
        VsceStatus.handle_status(status)
        return decrypt_response.get_bytes()

    def rotate_keys(self, server_private_key):
        """Updates server's private and public keys and issues an update token for use on client's side"""
        d_server_private_key = Data(server_private_key)
        new_server_private_key = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        new_server_public_key = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        update_token = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        status = self._lib_vsce_uokms_server.vsce_uokms_server_rotate_keys(self.ctx, d_server_private_key.data, new_server_private_key.c_buffer, new_server_public_key.c_buffer, update_token.c_buffer)
        VsceStatus.handle_status(status)
        return new_server_private_key.get_bytes(), new_server_public_key.get_bytes(), update_token.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_uokms_server = VsceUokmsServer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_uokms_server = VsceUokmsServer()
        inst.ctx = inst._lib_vsce_uokms_server.vsce_uokms_server_shallow_copy(c_ctx)
        return inst
