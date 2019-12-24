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


class vsce_phe_server_t(Structure):
    pass


class VscePheServer(object):
    """Class for server-side PHE crypto operations.
    This class is thread-safe in case if VSCE_MULTI_THREADING defined."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.phe

    def vsce_phe_server_new(self):
        vsce_phe_server_new = self._lib.vsce_phe_server_new
        vsce_phe_server_new.argtypes = []
        vsce_phe_server_new.restype = POINTER(vsce_phe_server_t)
        return vsce_phe_server_new()

    def vsce_phe_server_delete(self, ctx):
        vsce_phe_server_delete = self._lib.vsce_phe_server_delete
        vsce_phe_server_delete.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_delete.restype = None
        return vsce_phe_server_delete(ctx)

    def vsce_phe_server_use_random(self, ctx, random):
        """Random used for key generation, proofs, etc."""
        vsce_phe_server_use_random = self._lib.vsce_phe_server_use_random
        vsce_phe_server_use_random.argtypes = [POINTER(vsce_phe_server_t), POINTER(vscf_impl_t)]
        vsce_phe_server_use_random.restype = None
        return vsce_phe_server_use_random(ctx, random)

    def vsce_phe_server_use_operation_random(self, ctx, operation_random):
        """Random used for crypto operations to make them const-time"""
        vsce_phe_server_use_operation_random = self._lib.vsce_phe_server_use_operation_random
        vsce_phe_server_use_operation_random.argtypes = [POINTER(vsce_phe_server_t), POINTER(vscf_impl_t)]
        vsce_phe_server_use_operation_random.restype = None
        return vsce_phe_server_use_operation_random(ctx, operation_random)

    def vsce_phe_server_setup_defaults(self, ctx):
        """Setups dependencies with default values."""
        vsce_phe_server_setup_defaults = self._lib.vsce_phe_server_setup_defaults
        vsce_phe_server_setup_defaults.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_setup_defaults.restype = c_int
        return vsce_phe_server_setup_defaults(ctx)

    def vsce_phe_server_generate_server_key_pair(self, ctx, server_private_key, server_public_key):
        """Generates new NIST P-256 server key pair for some client"""
        vsce_phe_server_generate_server_key_pair = self._lib.vsce_phe_server_generate_server_key_pair
        vsce_phe_server_generate_server_key_pair.argtypes = [POINTER(vsce_phe_server_t), POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsce_phe_server_generate_server_key_pair.restype = c_int
        return vsce_phe_server_generate_server_key_pair(ctx, server_private_key, server_public_key)

    def vsce_phe_server_enrollment_response_len(self, ctx):
        """Buffer size needed to fit EnrollmentResponse"""
        vsce_phe_server_enrollment_response_len = self._lib.vsce_phe_server_enrollment_response_len
        vsce_phe_server_enrollment_response_len.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_enrollment_response_len.restype = c_size_t
        return vsce_phe_server_enrollment_response_len(ctx)

    def vsce_phe_server_get_enrollment(self, ctx, server_private_key, server_public_key, enrollment_response):
        """Generates a new random enrollment and proof for a new user"""
        vsce_phe_server_get_enrollment = self._lib.vsce_phe_server_get_enrollment
        vsce_phe_server_get_enrollment.argtypes = [POINTER(vsce_phe_server_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_server_get_enrollment.restype = c_int
        return vsce_phe_server_get_enrollment(ctx, server_private_key, server_public_key, enrollment_response)

    def vsce_phe_server_verify_password_response_len(self, ctx):
        """Buffer size needed to fit VerifyPasswordResponse"""
        vsce_phe_server_verify_password_response_len = self._lib.vsce_phe_server_verify_password_response_len
        vsce_phe_server_verify_password_response_len.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_verify_password_response_len.restype = c_size_t
        return vsce_phe_server_verify_password_response_len(ctx)

    def vsce_phe_server_verify_password(self, ctx, server_private_key, server_public_key, verify_password_request, verify_password_response):
        """Verifies existing user's password and generates response with proof"""
        vsce_phe_server_verify_password = self._lib.vsce_phe_server_verify_password
        vsce_phe_server_verify_password.argtypes = [POINTER(vsce_phe_server_t), vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_server_verify_password.restype = c_int
        return vsce_phe_server_verify_password(ctx, server_private_key, server_public_key, verify_password_request, verify_password_response)

    def vsce_phe_server_update_token_len(self, ctx):
        """Buffer size needed to fit UpdateToken"""
        vsce_phe_server_update_token_len = self._lib.vsce_phe_server_update_token_len
        vsce_phe_server_update_token_len.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_update_token_len.restype = c_size_t
        return vsce_phe_server_update_token_len(ctx)

    def vsce_phe_server_rotate_keys(self, ctx, server_private_key, new_server_private_key, new_server_public_key, update_token):
        """Updates server's private and public keys and issues an update token for use on client's side"""
        vsce_phe_server_rotate_keys = self._lib.vsce_phe_server_rotate_keys
        vsce_phe_server_rotate_keys.argtypes = [POINTER(vsce_phe_server_t), vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsce_phe_server_rotate_keys.restype = c_int
        return vsce_phe_server_rotate_keys(ctx, server_private_key, new_server_private_key, new_server_public_key, update_token)

    def vsce_phe_server_shallow_copy(self, ctx):
        vsce_phe_server_shallow_copy = self._lib.vsce_phe_server_shallow_copy
        vsce_phe_server_shallow_copy.argtypes = [POINTER(vsce_phe_server_t)]
        vsce_phe_server_shallow_copy.restype = POINTER(vsce_phe_server_t)
        return vsce_phe_server_shallow_copy(ctx)
