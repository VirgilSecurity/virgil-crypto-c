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
        status = self._lib_vsce_uokms_client.vsce_uokms_client_setup_defaults(self.ctx)
        VsceStatus.handle_status(status)

    def set_keys(self, client_private_key, server_public_key):
        """Sets client private and server public key
        Call this method before any other methods except `update enrollment record` and `generate client private key`
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
        """Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
        a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
        Also generates a random seed which then can be used to generate symmetric or private key to protect user's data"""
        wrap = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        encryption_key = Buffer(encryption_key_len)
        status = self._lib_vsce_uokms_client.vsce_uokms_client_generate_encrypt_wrap(self.ctx, encryption_key_len, wrap.c_buffer, encryption_key.c_buffer)
        VsceStatus.handle_status(status)
        return wrap.get_bytes(), encryption_key.get_bytes()

    def generate_decrypt_request(self, wrap):
        """Decrypts data (and verifies additional data) using account key"""
        d_wrap = Data(wrap)
        deblind_factor = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        decrypt_request = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        status = self._lib_vsce_uokms_client.vsce_uokms_client_generate_decrypt_request(self.ctx, d_wrap.data, deblind_factor.c_buffer, decrypt_request.c_buffer)
        VsceStatus.handle_status(status)
        return deblind_factor.get_bytes(), decrypt_request.get_bytes()

    def process_decrypt_response(self, wrap, decrypt_response, deblind_factor, encryption_key_len):
        """Decrypts data (and verifies additional data) using account key"""
        d_wrap = Data(wrap)
        d_decrypt_response = Data(decrypt_response)
        d_deblind_factor = Data(deblind_factor)
        encryption_key = Buffer(encryption_key_len)
        status = self._lib_vsce_uokms_client.vsce_uokms_client_process_decrypt_response(self.ctx, d_wrap.data, d_decrypt_response.data, d_deblind_factor.data, encryption_key_len, encryption_key.c_buffer)
        VsceStatus.handle_status(status)
        return encryption_key.get_bytes()

    def rotate_keys(self, update_token):
        """Updates client's private key and server's public key using server's update token
        Use output values to instantiate new client instance with new keys"""
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
