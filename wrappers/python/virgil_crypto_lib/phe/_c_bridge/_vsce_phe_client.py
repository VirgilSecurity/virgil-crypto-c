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


class vsce_phe_client_t(Structure):
    pass


class VscePheClient(object):
    """Class for client-side PHE crypto operations.
    This class is thread-safe in case if VSCE_MULTI_THREADING defined."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.phe

    def vsce_phe_client_new(self):
        vsce_phe_client_new = self._lib.vsce_phe_client_new
        vsce_phe_client_new.argtypes = []
        vsce_phe_client_new.restype = POINTER(vsce_phe_client_t)
        return vsce_phe_client_new()

    def vsce_phe_client_delete(self, ctx):
        vsce_phe_client_delete = self._lib.vsce_phe_client_delete
        vsce_phe_client_delete.argtypes = [POINTER(vsce_phe_client_t)]
        vsce_phe_client_delete.restype = None
        return vsce_phe_client_delete(ctx)

    def vsce_phe_client_use_random(self, ctx, random):
        """Random used for key generation, proofs, etc."""
        vsce_phe_client_use_random = self._lib.vsce_phe_client_use_random
        vsce_phe_client_use_random.argtypes = [POINTER(vsce_phe_client_t), POINTER(vscf_impl_t)]
        vsce_phe_client_use_random.restype = None
        return vsce_phe_client_use_random(ctx, random)

    def vsce_phe_client_use_operation_random(self, ctx, operation_random):
        """Random used for crypto operations to make them const-time"""
        vsce_phe_client_use_operation_random = self._lib.vsce_phe_client_use_operation_random
        vsce_phe_client_use_operation_random.argtypes = [POINTER(vsce_phe_client_t), POINTER(vscf_impl_t)]
        vsce_phe_client_use_operation_random.restype = None
        return vsce_phe_client_use_operation_random(ctx, operation_random)

    def vsce_phe_client_setup_defaults(self, ctx):
        """Setups dependencies with default values."""
        vsce_phe_client_setup_defaults = self._lib.vsce_phe_client_setup_defaults
        vsce_phe_client_setup_defaults.argtypes = [POINTER(vsce_phe_client_t)]
        vsce_phe_client_setup_defaults.restype = c_int
        return vsce_phe_client_setup_defaults(ctx)

    def vsce_phe_client_set_keys(self, ctx, client_private_key, server_public_key):
        """Sets client private and server public key
        Call this method before any other methods except `update enrollment record` and `generate client private key`
        This function should be called only once"""
        vsce_phe_client_set_keys = self._lib.vsce_phe_client_set_keys
        vsce_phe_client_set_keys.argtypes = [POINTER(vsce_phe_client_t), vsc_data_t, vsc_data_t]
        vsce_phe_client_set_keys.restype = c_int
        return vsce_phe_client_set_keys(ctx, client_private_key, server_public_key)

    def vsce_phe_client_generate_client_private_key(self, ctx, client_private_key):
        """Generates client private key"""
        vsce_phe_client_generate_client_private_key = self._lib.vsce_phe_client_generate_client_private_key
        vsce_phe_client_generate_client_private_key.argtypes = [POINTER(vsce_phe_client_t), POINTER(vsc_buffer_t)]
        vsce_phe_client_generate_client_private_key.restype = c_int
        return vsce_phe_client_generate_client_private_key(ctx, client_private_key)

    def vsce_phe_client_enrollment_record_len(self, ctx):
        """Buffer size needed to fit EnrollmentRecord"""
        vsce_phe_client_enrollment_record_len = self._lib.vsce_phe_client_enrollment_record_len
        vsce_phe_client_enrollment_record_len.argtypes = [POINTER(vsce_phe_client_t)]
        vsce_phe_client_enrollment_record_len.restype = c_size_t
        return vsce_phe_client_enrollment_record_len(ctx)

    def vsce_phe_client_enroll_account(self, ctx, enrollment_response, password, enrollment_record, account_key):
        """Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
        a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
        Also generates a random seed which then can be used to generate symmetric or private key to protect user's data"""
        vsce_phe_client_enroll_account = self._lib.vsce_phe_client_enroll_account
        vsce_phe_client_enroll_account.argtypes = [POINTER(vsce_phe_client_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsce_phe_client_enroll_account.restype = c_int
        return vsce_phe_client_enroll_account(ctx, enrollment_response, password, enrollment_record, account_key)

    def vsce_phe_client_verify_password_request_len(self, ctx):
        """Buffer size needed to fit VerifyPasswordRequest"""
        vsce_phe_client_verify_password_request_len = self._lib.vsce_phe_client_verify_password_request_len
        vsce_phe_client_verify_password_request_len.argtypes = [POINTER(vsce_phe_client_t)]
        vsce_phe_client_verify_password_request_len.restype = c_size_t
        return vsce_phe_client_verify_password_request_len(ctx)

    def vsce_phe_client_create_verify_password_request(self, ctx, password, enrollment_record, verify_password_request):
        """Creates a request for further password verification at the PHE server side."""
        vsce_phe_client_create_verify_password_request = self._lib.vsce_phe_client_create_verify_password_request
        vsce_phe_client_create_verify_password_request.argtypes = [POINTER(vsce_phe_client_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_client_create_verify_password_request.restype = c_int
        return vsce_phe_client_create_verify_password_request(ctx, password, enrollment_record, verify_password_request)

    def vsce_phe_client_check_response_and_decrypt(self, ctx, password, enrollment_record, verify_password_response, account_key):
        """Verifies PHE server's answer
        If login succeeded, extracts account key
        If login failed account key will be empty"""
        vsce_phe_client_check_response_and_decrypt = self._lib.vsce_phe_client_check_response_and_decrypt
        vsce_phe_client_check_response_and_decrypt.argtypes = [POINTER(vsce_phe_client_t), vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_client_check_response_and_decrypt.restype = c_int
        return vsce_phe_client_check_response_and_decrypt(ctx, password, enrollment_record, verify_password_response, account_key)

    def vsce_phe_client_rotate_keys(self, ctx, update_token, new_client_private_key, new_server_public_key):
        """Updates client's private key and server's public key using server's update token
        Use output values to instantiate new client instance with new keys"""
        vsce_phe_client_rotate_keys = self._lib.vsce_phe_client_rotate_keys
        vsce_phe_client_rotate_keys.argtypes = [POINTER(vsce_phe_client_t), vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vsce_phe_client_rotate_keys.restype = c_int
        return vsce_phe_client_rotate_keys(ctx, update_token, new_client_private_key, new_server_public_key)

    def vsce_phe_client_update_enrollment_record(self, ctx, enrollment_record, update_token, new_enrollment_record):
        """Updates EnrollmentRecord using server's update token"""
        vsce_phe_client_update_enrollment_record = self._lib.vsce_phe_client_update_enrollment_record
        vsce_phe_client_update_enrollment_record.argtypes = [POINTER(vsce_phe_client_t), vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vsce_phe_client_update_enrollment_record.restype = c_int
        return vsce_phe_client_update_enrollment_record(ctx, enrollment_record, update_token, new_enrollment_record)

    def vsce_phe_client_shallow_copy(self, ctx):
        vsce_phe_client_shallow_copy = self._lib.vsce_phe_client_shallow_copy
        vsce_phe_client_shallow_copy.argtypes = [POINTER(vsce_phe_client_t)]
        vsce_phe_client_shallow_copy.restype = POINTER(vsce_phe_client_t)
        return vsce_phe_client_shallow_copy(ctx)
