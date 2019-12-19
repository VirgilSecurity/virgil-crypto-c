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
from ._c_bridge import VsceUokmsClient
from ._c_bridge import VsceStatus
from virgil_crypto_lib.common._c_bridge import Data
from .common import Common
from virgil_crypto_lib.common._c_bridge import Buffer


class UokmsClient(object):
    """Class implements UOKMS for client-side."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vsce_uokms_client = VsceUokmsClient()
        self.ctx = self._lib_vsce_uokms_client.vsce_uokms_client_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vsce_uokms_client.vsce_uokms_client_delete(self.ctx)

    def set_random(self, random):
        """Random used for key generation, proofs, etc."""
        self._lib_vsce_uokms_client.vsce_uokms_client_use_random(self.ctx, random.c_impl)

    def set_operation_random(self, operation_random):
        """Random used for crypto operations to make them const-time"""
        self._lib_vsce_uokms_client.vsce_uokms_client_use_operation_random(self.ctx, operation_random.c_impl)

    def setup_defaults(self):
        """Setups dependencies with default values."""
        status = self._lib_vsce_uokms_client.vsce_uokms_client_setup_defaults(self.ctx)
        VsceStatus.handle_status(status)

    def set_keys(self, client_private_key, server_public_key):
        """Sets client private and server public key
        Call this method before any other methods
        This function should be called only once"""
        d_client_private_key = Data(client_private_key)
        d_server_public_key = Data(server_public_key)
        status = self._lib_vsce_uokms_client.vsce_uokms_client_set_keys(self.ctx, d_client_private_key.data, d_server_public_key.data)
        VsceStatus.handle_status(status)

    def generate_client_private_key(self):
        """Generates client private key"""
        client_private_key = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        status = self._lib_vsce_uokms_client.vsce_uokms_client_generate_client_private_key(self.ctx, client_private_key.c_buffer)
        VsceStatus.handle_status(status)
        return client_private_key.get_bytes()

    def generate_encrypt_wrap(self, encryption_key_len):
        """Generates new encrypt wrap (which should be stored and then used for decryption) + encryption key
        of "encryption key len" that can be used for symmetric encryption"""
        wrap = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        encryption_key = Buffer(encryption_key_len)
        status = self._lib_vsce_uokms_client.vsce_uokms_client_generate_encrypt_wrap(self.ctx, encryption_key_len, wrap.c_buffer, encryption_key.c_buffer)
        VsceStatus.handle_status(status)
        return wrap.get_bytes(), encryption_key.get_bytes()

    def generate_decrypt_request(self, wrap):
        """Generates request to decrypt data, this request should be sent to the server.
        Server response is then passed to "process decrypt response" where encryption key can be decapsulated"""
        d_wrap = Data(wrap)
        deblind_factor = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        decrypt_request = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        status = self._lib_vsce_uokms_client.vsce_uokms_client_generate_decrypt_request(self.ctx, d_wrap.data, deblind_factor.c_buffer, decrypt_request.c_buffer)
        VsceStatus.handle_status(status)
        return deblind_factor.get_bytes(), decrypt_request.get_bytes()

    def process_decrypt_response(self, wrap, decrypt_request, decrypt_response, deblind_factor, encryption_key_len):
        """Processed server response, checks server proof and decapsulates encryption key"""
        d_wrap = Data(wrap)
        d_decrypt_request = Data(decrypt_request)
        d_decrypt_response = Data(decrypt_response)
        d_deblind_factor = Data(deblind_factor)
        encryption_key = Buffer(encryption_key_len)
        status = self._lib_vsce_uokms_client.vsce_uokms_client_process_decrypt_response(self.ctx, d_wrap.data, d_decrypt_request.data, d_decrypt_response.data, d_deblind_factor.data, encryption_key_len, encryption_key.c_buffer)
        VsceStatus.handle_status(status)
        return encryption_key.get_bytes()

    def rotate_keys(self, update_token):
        """Rotates client and server keys using given update token obtained from server"""
        d_update_token = Data(update_token)
        new_client_private_key = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        new_server_public_key = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        status = self._lib_vsce_uokms_client.vsce_uokms_client_rotate_keys(self.ctx, d_update_token.data, new_client_private_key.c_buffer, new_server_public_key.c_buffer)
        VsceStatus.handle_status(status)
        return new_client_private_key.get_bytes(), new_server_public_key.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_uokms_client = VsceUokmsClient()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_uokms_client = VsceUokmsClient()
        inst.ctx = inst._lib_vsce_uokms_client.vsce_uokms_client_shallow_copy(c_ctx)
        return inst
