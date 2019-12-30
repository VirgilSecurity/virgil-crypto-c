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
from ._c_bridge import VscePheClient
from ._c_bridge import VsceStatus
from virgil_crypto_lib.common._c_bridge import Data
from .common import Common
from virgil_crypto_lib.common._c_bridge import Buffer


class Client(object):
    """Class for client-side PHE crypto operations.
    This class is thread-safe in case if VSCE_MULTI_THREADING defined."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vsce_phe_client = VscePheClient()
        self.ctx = self._lib_vsce_phe_client.vsce_phe_client_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vsce_phe_client.vsce_phe_client_delete(self.ctx)

    def set_random(self, random):
        """Random used for key generation, proofs, etc."""
        self._lib_vsce_phe_client.vsce_phe_client_use_random(self.ctx, random.c_impl)

    def set_operation_random(self, operation_random):
        """Random used for crypto operations to make them const-time"""
        self._lib_vsce_phe_client.vsce_phe_client_use_operation_random(self.ctx, operation_random.c_impl)

    def setup_defaults(self):
        """Setups dependencies with default values."""
        status = self._lib_vsce_phe_client.vsce_phe_client_setup_defaults(self.ctx)
        VsceStatus.handle_status(status)

    def set_keys(self, client_private_key, server_public_key):
        """Sets client private and server public key
        Call this method before any other methods except `update enrollment record` and `generate client private key`
        This function should be called only once"""
        d_client_private_key = Data(client_private_key)
        d_server_public_key = Data(server_public_key)
        status = self._lib_vsce_phe_client.vsce_phe_client_set_keys(self.ctx, d_client_private_key.data, d_server_public_key.data)
        VsceStatus.handle_status(status)

    def generate_client_private_key(self):
        """Generates client private key"""
        client_private_key = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        status = self._lib_vsce_phe_client.vsce_phe_client_generate_client_private_key(self.ctx, client_private_key.c_buffer)
        VsceStatus.handle_status(status)
        return client_private_key.get_bytes()

    def enrollment_record_len(self):
        """Buffer size needed to fit EnrollmentRecord"""
        result = self._lib_vsce_phe_client.vsce_phe_client_enrollment_record_len(self.ctx)
        return result

    def enroll_account(self, enrollment_response, password):
        """Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
        a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
        Also generates a random seed which then can be used to generate symmetric or private key to protect user's data"""
        d_enrollment_response = Data(enrollment_response)
        d_password = Data(password)
        enrollment_record = Buffer(self.enrollment_record_len())
        account_key = Buffer(Common.PHE_ACCOUNT_KEY_LENGTH)
        status = self._lib_vsce_phe_client.vsce_phe_client_enroll_account(self.ctx, d_enrollment_response.data, d_password.data, enrollment_record.c_buffer, account_key.c_buffer)
        VsceStatus.handle_status(status)
        return enrollment_record.get_bytes(), account_key.get_bytes()

    def verify_password_request_len(self):
        """Buffer size needed to fit VerifyPasswordRequest"""
        result = self._lib_vsce_phe_client.vsce_phe_client_verify_password_request_len(self.ctx)
        return result

    def create_verify_password_request(self, password, enrollment_record):
        """Creates a request for further password verification at the PHE server side."""
        d_password = Data(password)
        d_enrollment_record = Data(enrollment_record)
        verify_password_request = Buffer(self.verify_password_request_len())
        status = self._lib_vsce_phe_client.vsce_phe_client_create_verify_password_request(self.ctx, d_password.data, d_enrollment_record.data, verify_password_request.c_buffer)
        VsceStatus.handle_status(status)
        return verify_password_request.get_bytes()

    def check_response_and_decrypt(self, password, enrollment_record, verify_password_response):
        """Verifies PHE server's answer
        If login succeeded, extracts account key
        If login failed account key will be empty"""
        d_password = Data(password)
        d_enrollment_record = Data(enrollment_record)
        d_verify_password_response = Data(verify_password_response)
        account_key = Buffer(Common.PHE_ACCOUNT_KEY_LENGTH)
        status = self._lib_vsce_phe_client.vsce_phe_client_check_response_and_decrypt(self.ctx, d_password.data, d_enrollment_record.data, d_verify_password_response.data, account_key.c_buffer)
        VsceStatus.handle_status(status)
        return account_key.get_bytes()

    def rotate_keys(self, update_token):
        """Updates client's private key and server's public key using server's update token
        Use output values to instantiate new client instance with new keys"""
        d_update_token = Data(update_token)
        new_client_private_key = Buffer(Common.PHE_PRIVATE_KEY_LENGTH)
        new_server_public_key = Buffer(Common.PHE_PUBLIC_KEY_LENGTH)
        status = self._lib_vsce_phe_client.vsce_phe_client_rotate_keys(self.ctx, d_update_token.data, new_client_private_key.c_buffer, new_server_public_key.c_buffer)
        VsceStatus.handle_status(status)
        return new_client_private_key.get_bytes(), new_server_public_key.get_bytes()

    def update_enrollment_record(self, enrollment_record, update_token):
        """Updates EnrollmentRecord using server's update token"""
        d_enrollment_record = Data(enrollment_record)
        d_update_token = Data(update_token)
        new_enrollment_record = Buffer(self.enrollment_record_len())
        status = self._lib_vsce_phe_client.vsce_phe_client_update_enrollment_record(self.ctx, d_enrollment_record.data, d_update_token.data, new_enrollment_record.c_buffer)
        VsceStatus.handle_status(status)
        return new_enrollment_record.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_phe_client = VscePheClient()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vsce_phe_client = VscePheClient()
        inst.ctx = inst._lib_vsce_phe_client.vsce_phe_client_shallow_copy(c_ctx)
        return inst
