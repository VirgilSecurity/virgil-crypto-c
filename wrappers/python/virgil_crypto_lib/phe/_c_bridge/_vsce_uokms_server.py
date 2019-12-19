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
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t


class vsce_uokms_server_t(Structure):
    pass


class VsceUokmsServer(object):
    """Class implements UOKMS for server-side."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.phe

    def vsce_uokms_server_new(self):
        vsce_uokms_server_new = self._lib.vsce_uokms_server_new
        vsce_uokms_server_new.argtypes = []
        vsce_uokms_server_new.restype = POINTER(vsce_uokms_server_t)
        return vsce_uokms_server_new()

    def vsce_uokms_server_delete(self, ctx):
        vsce_uokms_server_delete = self._lib.vsce_uokms_server_delete
        vsce_uokms_server_delete.argtypes = [POINTER(vsce_uokms_server_t)]
        vsce_uokms_server_delete.restype = None
        return vsce_uokms_server_delete(ctx)

    def vsce_uokms_server_use_random(self, ctx, random):
        """Random used for key generation, proofs, etc."""
        vsce_uokms_server_use_random = self._lib.vsce_uokms_server_use_random
        vsce_uokms_server_use_random.argtypes = [POINTER(vsce_uokms_server_t), POINTER(vscf_impl_t)]
        vsce_uokms_server_use_random.restype = None
        return vsce_uokms_server_use_random(ctx, random)

    def vsce_uokms_server_use_operation_random(self, ctx, operation_random):
        """Random used for crypto operations to make them const-time"""
        vsce_uokms_server_use_operation_random = self._lib.vsce_uokms_server_use_operation_random
        vsce_uokms_server_use_operation_random.argtypes = [POINTER(vsce_uokms_server_t), POINTER(vscf_impl_t)]
        vsce_uokms_server_use_operation_random.restype = None
        return vsce_uokms_server_use_operation_random(ctx, operation_random)

    def vsce_uokms_server_setup_defaults(self, ctx):
        """Setups dependencies with default values."""
        vsce_uokms_server_setup_defaults = self._lib.vsce_uokms_server_setup_defaults
        vsce_uokms_server_setup_defaults.argtypes = [POINTER(vsce_uokms_server_t)]
        vsce_uokms_server_setup_defaults.restype = c_int
        return vsce_uokms_server_setup_defaults(ctx)

    def vsce_uokms_server_generate_server_key_pair(self, ctx, server_private_key, server_public_key):
        """Generates new NIST P-256 server key pair for some client"""
        vsce_uokms_server_generate_server_key_pair = self._lib.vsce_uokms_server_generate_server_key_pair
        vsce_uokms_server_generate_server_key_pair.argtypes = [POINTER(vsce_uokms_server_t), POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsce_uokms_server_generate_server_key_pair.restype = c_int
        return vsce_uokms_server_generate_server_key_pair(ctx, server_private_key, server_public_key)

    def vsce_uokms_server_decrypt_response_len(self, ctx):
        """Buffer size needed to fit DecryptResponse"""
        vsce_uokms_server_decrypt_response_len = self._lib.vsce_uokms_server_decrypt_response_len
        vsce_uokms_server_decrypt_response_len.argtypes = [POINTER(vsce_uokms_server_t)]
        vsce_uokms_server_decrypt_response_len.restype = c_size_t
        return vsce_uokms_server_decrypt_response_len(ctx)

    def vsce_uokms_server_process_decrypt_request(self, ctx, server_private_key, decrypt_request, decrypt_response):
        """Processed client's decrypt request"""
        vsce_uokms_server_process_decrypt_request = self._lib.vsce_uokms_server_process_decrypt_request
        vsce_uokms_server_process_decrypt_request.argtypes = [POINTER(vsce_uokms_server_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_uokms_server_process_decrypt_request.restype = c_int
        return vsce_uokms_server_process_decrypt_request(ctx, server_private_key, decrypt_request, decrypt_response)

    def vsce_uokms_server_rotate_keys(self, ctx, server_private_key, new_server_private_key, new_server_public_key, update_token):
        """Updates server's private and public keys and issues an update token for use on client's side"""
        vsce_uokms_server_rotate_keys = self._lib.vsce_uokms_server_rotate_keys
        vsce_uokms_server_rotate_keys.argtypes = [POINTER(vsce_uokms_server_t), vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsce_uokms_server_rotate_keys.restype = c_int
        return vsce_uokms_server_rotate_keys(ctx, server_private_key, new_server_private_key, new_server_public_key, update_token)

    def vsce_uokms_server_shallow_copy(self, ctx):
        vsce_uokms_server_shallow_copy = self._lib.vsce_uokms_server_shallow_copy
        vsce_uokms_server_shallow_copy.argtypes = [POINTER(vsce_uokms_server_t)]
        vsce_uokms_server_shallow_copy.restype = POINTER(vsce_uokms_server_t)
        return vsce_uokms_server_shallow_copy(ctx)
