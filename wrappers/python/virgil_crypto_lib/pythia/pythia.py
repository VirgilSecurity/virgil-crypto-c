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
from ._c_bridge import VscpPythia
from ._c_bridge import VscpStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge._vscp_error import vscp_error_t


class Pythia(object):
    """Provide Pythia implementation based on the Virgil Security."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscp_pythia = VscpPythia()

    def configure(self):
        """Performs global initialization of the pythia library.
        Must be called once for entire application at startup."""
        status = self._lib_vscp_pythia.vscp_pythia_configure()
        VscpStatus.handle_status(status)

    def cleanup(self):
        """Performs global cleanup of the pythia library.
        Must be called once for entire application before exit."""
        self._lib_vscp_pythia.vscp_pythia_cleanup()

    def blinded_password_buf_len(self):
        """Return length of the buffer needed to hold 'blinded password'."""
        result = self._lib_vscp_pythia.vscp_pythia_blinded_password_buf_len()
        return result

    def deblinded_password_buf_len(self):
        """Return length of the buffer needed to hold 'deblinded password'."""
        result = self._lib_vscp_pythia.vscp_pythia_deblinded_password_buf_len()
        return result

    def blinding_secret_buf_len(self):
        """Return length of the buffer needed to hold 'blinding secret'."""
        result = self._lib_vscp_pythia.vscp_pythia_blinding_secret_buf_len()
        return result

    def transformation_private_key_buf_len(self):
        """Return length of the buffer needed to hold 'transformation private key'."""
        result = self._lib_vscp_pythia.vscp_pythia_transformation_private_key_buf_len()
        return result

    def transformation_public_key_buf_len(self):
        """Return length of the buffer needed to hold 'transformation public key'."""
        result = self._lib_vscp_pythia.vscp_pythia_transformation_public_key_buf_len()
        return result

    def transformed_password_buf_len(self):
        """Return length of the buffer needed to hold 'transformed password'."""
        result = self._lib_vscp_pythia.vscp_pythia_transformed_password_buf_len()
        return result

    def transformed_tweak_buf_len(self):
        """Return length of the buffer needed to hold 'transformed tweak'."""
        result = self._lib_vscp_pythia.vscp_pythia_transformed_tweak_buf_len()
        return result

    def proof_value_buf_len(self):
        """Return length of the buffer needed to hold 'proof value'."""
        result = self._lib_vscp_pythia.vscp_pythia_proof_value_buf_len()
        return result

    def password_update_token_buf_len(self):
        """Return length of the buffer needed to hold 'password update token'."""
        result = self._lib_vscp_pythia.vscp_pythia_password_update_token_buf_len()
        return result

    def blind(self, password):
        """Blinds password. Turns password into a pseudo-random string.
        This step is necessary to prevent 3rd-parties from knowledge of end user's password."""
        d_password = Data(password)
        blinded_password = Buffer(self.blinded_password_buf_len())
        blinding_secret = Buffer(self.blinding_secret_buf_len())
        status = self._lib_vscp_pythia.vscp_pythia_blind(d_password.data, blinded_password.c_buffer, blinding_secret.c_buffer)
        VscpStatus.handle_status(status)
        return blinded_password.get_bytes(), blinding_secret.get_bytes()

    def deblind(self, transformed_password, blinding_secret):
        """Deblinds 'transformed password' value with previously returned 'blinding secret' from blind()."""
        d_transformed_password = Data(transformed_password)
        d_blinding_secret = Data(blinding_secret)
        deblinded_password = Buffer(self.deblinded_password_buf_len())
        status = self._lib_vscp_pythia.vscp_pythia_deblind(d_transformed_password.data, d_blinding_secret.data, deblinded_password.c_buffer)
        VscpStatus.handle_status(status)
        return deblinded_password.get_bytes()

    def compute_transformation_key_pair(self, transformation_key_id, pythia_secret, pythia_scope_secret):
        """Computes transformation private and public key."""
        d_transformation_key_id = Data(transformation_key_id)
        d_pythia_secret = Data(pythia_secret)
        d_pythia_scope_secret = Data(pythia_scope_secret)
        transformation_private_key = Buffer(self.transformation_private_key_buf_len())
        transformation_public_key = Buffer(self.transformation_public_key_buf_len())
        status = self._lib_vscp_pythia.vscp_pythia_compute_transformation_key_pair(d_transformation_key_id.data, d_pythia_secret.data, d_pythia_scope_secret.data, transformation_private_key.c_buffer, transformation_public_key.c_buffer)
        VscpStatus.handle_status(status)
        return transformation_private_key.get_bytes(), transformation_public_key.get_bytes()

    def transform(self, blinded_password, tweak, transformation_private_key):
        """Transforms blinded password using transformation private key."""
        d_blinded_password = Data(blinded_password)
        d_tweak = Data(tweak)
        d_transformation_private_key = Data(transformation_private_key)
        transformed_password = Buffer(self.transformed_password_buf_len())
        transformed_tweak = Buffer(self.transformed_tweak_buf_len())
        status = self._lib_vscp_pythia.vscp_pythia_transform(d_blinded_password.data, d_tweak.data, d_transformation_private_key.data, transformed_password.c_buffer, transformed_tweak.c_buffer)
        VscpStatus.handle_status(status)
        return transformed_password.get_bytes(), transformed_tweak.get_bytes()

    def prove(self, transformed_password, blinded_password, transformed_tweak, transformation_private_key, transformation_public_key):
        """Generates proof that server possesses secret values that were used to transform password."""
        d_transformed_password = Data(transformed_password)
        d_blinded_password = Data(blinded_password)
        d_transformed_tweak = Data(transformed_tweak)
        d_transformation_private_key = Data(transformation_private_key)
        d_transformation_public_key = Data(transformation_public_key)
        proof_value_c = Buffer(self.proof_value_buf_len())
        proof_value_u = Buffer(self.proof_value_buf_len())
        status = self._lib_vscp_pythia.vscp_pythia_prove(d_transformed_password.data, d_blinded_password.data, d_transformed_tweak.data, d_transformation_private_key.data, d_transformation_public_key.data, proof_value_c.c_buffer, proof_value_u.c_buffer)
        VscpStatus.handle_status(status)
        return proof_value_c.get_bytes(), proof_value_u.get_bytes()

    def verify(self, transformed_password, blinded_password, tweak, transformation_public_key, proof_value_c, proof_value_u):
        """This operation allows client to verify that the output of transform() is correct,
        assuming that client has previously stored transformation public key."""
        d_transformed_password = Data(transformed_password)
        d_blinded_password = Data(blinded_password)
        d_tweak = Data(tweak)
        d_transformation_public_key = Data(transformation_public_key)
        d_proof_value_c = Data(proof_value_c)
        d_proof_value_u = Data(proof_value_u)
        error = vscp_error_t()
        result = self._lib_vscp_pythia.vscp_pythia_verify(d_transformed_password.data, d_blinded_password.data, d_tweak.data, d_transformation_public_key.data, d_proof_value_c.data, d_proof_value_u.data, error)
        VscpStatus.handle_status(error.status)
        return result

    def get_password_update_token(self, previous_transformation_private_key, new_transformation_private_key):
        """Rotates old transformation key to new transformation key and generates 'password update token',
        that can update 'deblinded password'(s).

        This action should increment version of the 'pythia scope secret'."""
        d_previous_transformation_private_key = Data(previous_transformation_private_key)
        d_new_transformation_private_key = Data(new_transformation_private_key)
        password_update_token = Buffer(self.password_update_token_buf_len())
        status = self._lib_vscp_pythia.vscp_pythia_get_password_update_token(d_previous_transformation_private_key.data, d_new_transformation_private_key.data, password_update_token.c_buffer)
        VscpStatus.handle_status(status)
        return password_update_token.get_bytes()

    def update_deblinded_with_token(self, deblinded_password, password_update_token):
        """Updates previously stored 'deblinded password' with 'password update token'.
        After this call, 'transform()' called with new arguments will return corresponding values."""
        d_deblinded_password = Data(deblinded_password)
        d_password_update_token = Data(password_update_token)
        updated_deblinded_password = Buffer(self.deblinded_password_buf_len())
        status = self._lib_vscp_pythia.vscp_pythia_update_deblinded_with_token(d_deblinded_password.data, d_password_update_token.data, updated_deblinded_password.c_buffer)
        VscpStatus.handle_status(status)
        return updated_deblinded_password.get_bytes()
