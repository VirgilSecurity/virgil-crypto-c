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
from virgil_crypto_lib.foundation._c_bridge._vscf_impl import vscf_impl_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vsce_uokms_client_t(Structure):
    pass


class VsceUokmsClient(object):
    """Class implements UOKMS for client-side."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.phe

    def vsce_uokms_client_new(self):
        vsce_uokms_client_new = self._lib.vsce_uokms_client_new
        vsce_uokms_client_new.argtypes = []
        vsce_uokms_client_new.restype = POINTER(vsce_uokms_client_t)
        return vsce_uokms_client_new()

    def vsce_uokms_client_delete(self, ctx):
        vsce_uokms_client_delete = self._lib.vsce_uokms_client_delete
        vsce_uokms_client_delete.argtypes = [POINTER(vsce_uokms_client_t)]
        vsce_uokms_client_delete.restype = None
        return vsce_uokms_client_delete(ctx)

    def vsce_uokms_client_use_random(self, ctx, random):
        """Random used for key generation, proofs, etc."""
        vsce_uokms_client_use_random = self._lib.vsce_uokms_client_use_random
        vsce_uokms_client_use_random.argtypes = [POINTER(vsce_uokms_client_t), POINTER(vscf_impl_t)]
        vsce_uokms_client_use_random.restype = None
        return vsce_uokms_client_use_random(ctx, random)

    def vsce_uokms_client_use_operation_random(self, ctx, operation_random):
        """Random used for crypto operations to make them const-time"""
        vsce_uokms_client_use_operation_random = self._lib.vsce_uokms_client_use_operation_random
        vsce_uokms_client_use_operation_random.argtypes = [POINTER(vsce_uokms_client_t), POINTER(vscf_impl_t)]
        vsce_uokms_client_use_operation_random.restype = None
        return vsce_uokms_client_use_operation_random(ctx, operation_random)

    def vsce_uokms_client_setup_defaults(self, ctx):
        """Setups dependencies with default values."""
        vsce_uokms_client_setup_defaults = self._lib.vsce_uokms_client_setup_defaults
        vsce_uokms_client_setup_defaults.argtypes = [POINTER(vsce_uokms_client_t)]
        vsce_uokms_client_setup_defaults.restype = c_int
        return vsce_uokms_client_setup_defaults(ctx)

    def vsce_uokms_client_set_keys(self, ctx, client_private_key, server_public_key):
        """Sets client private and server public key
        Call this method before any other methods
        This function should be called only once"""
        vsce_uokms_client_set_keys = self._lib.vsce_uokms_client_set_keys
        vsce_uokms_client_set_keys.argtypes = [POINTER(vsce_uokms_client_t), vsc_data_t, vsc_data_t]
        vsce_uokms_client_set_keys.restype = c_int
        return vsce_uokms_client_set_keys(ctx, client_private_key, server_public_key)

    def vsce_uokms_client_generate_client_private_key(self, ctx, client_private_key):
        """Generates client private key"""
        vsce_uokms_client_generate_client_private_key = self._lib.vsce_uokms_client_generate_client_private_key
        vsce_uokms_client_generate_client_private_key.argtypes = [POINTER(vsce_uokms_client_t), POINTER(vsc_buffer_t)]
        vsce_uokms_client_generate_client_private_key.restype = c_int
        return vsce_uokms_client_generate_client_private_key(ctx, client_private_key)

    def vsce_uokms_client_generate_encrypt_wrap(self, ctx, wrap, encryption_key_len, encryption_key):
        """Generates new encrypt wrap (which should be stored and then used for decryption) + encryption key
        of "encryption key len" that can be used for symmetric encryption"""
        vsce_uokms_client_generate_encrypt_wrap = self._lib.vsce_uokms_client_generate_encrypt_wrap
        vsce_uokms_client_generate_encrypt_wrap.argtypes = [POINTER(vsce_uokms_client_t), POINTER(vsc_buffer_t), c_size_t, POINTER(vsc_buffer_t)]
        vsce_uokms_client_generate_encrypt_wrap.restype = c_int
        return vsce_uokms_client_generate_encrypt_wrap(ctx, wrap, encryption_key_len, encryption_key)

    def vsce_uokms_client_generate_decrypt_request(self, ctx, wrap, deblind_factor, decrypt_request):
        """Generates request to decrypt data, this request should be sent to the server.
        Server response is then passed to "process decrypt response" where encryption key can be decapsulated"""
        vsce_uokms_client_generate_decrypt_request = self._lib.vsce_uokms_client_generate_decrypt_request
        vsce_uokms_client_generate_decrypt_request.argtypes = [POINTER(vsce_uokms_client_t), vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsce_uokms_client_generate_decrypt_request.restype = c_int
        return vsce_uokms_client_generate_decrypt_request(ctx, wrap, deblind_factor, decrypt_request)

    def vsce_uokms_client_process_decrypt_response(self, ctx, wrap, decrypt_request, decrypt_response, deblind_factor, encryption_key_len, encryption_key):
        """Processed server response, checks server proof and decapsulates encryption key"""
        vsce_uokms_client_process_decrypt_response = self._lib.vsce_uokms_client_process_decrypt_response
        vsce_uokms_client_process_decrypt_response.argtypes = [POINTER(vsce_uokms_client_t), vsc_data_t, vsc_data_t, vsc_data_t, vsc_data_t, c_size_t, POINTER(vsc_buffer_t)]
        vsce_uokms_client_process_decrypt_response.restype = c_int
        return vsce_uokms_client_process_decrypt_response(ctx, wrap, decrypt_request, decrypt_response, deblind_factor, encryption_key_len, encryption_key)

    def vsce_uokms_client_rotate_keys(self, ctx, update_token, new_client_private_key, new_server_public_key):
        """Rotates client and server keys using given update token obtained from server"""
        vsce_uokms_client_rotate_keys = self._lib.vsce_uokms_client_rotate_keys
        vsce_uokms_client_rotate_keys.argtypes = [POINTER(vsce_uokms_client_t), vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsce_uokms_client_rotate_keys.restype = c_int
        return vsce_uokms_client_rotate_keys(ctx, update_token, new_client_private_key, new_server_public_key)

    def vsce_uokms_client_shallow_copy(self, ctx):
        vsce_uokms_client_shallow_copy = self._lib.vsce_uokms_client_shallow_copy
        vsce_uokms_client_shallow_copy.argtypes = [POINTER(vsce_uokms_client_t)]
        vsce_uokms_client_shallow_copy.restype = POINTER(vsce_uokms_client_t)
        return vsce_uokms_client_shallow_copy(ctx)
