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
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from ._vscp_error import vscp_error_t


class VscpPythia(object):
    """Provide Pythia implementation based on the Virgil Security."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.pythia

    def vscp_pythia_configure(self):
        """Performs global initialization of the pythia library.
        Must be called once for entire application at startup."""
        vscp_pythia_configure = self._lib.vscp_pythia_configure
        vscp_pythia_configure.argtypes = []
        vscp_pythia_configure.restype = c_int
        return vscp_pythia_configure()

    def vscp_pythia_cleanup(self):
        """Performs global cleanup of the pythia library.
        Must be called once for entire application before exit."""
        vscp_pythia_cleanup = self._lib.vscp_pythia_cleanup
        vscp_pythia_cleanup.argtypes = []
        vscp_pythia_cleanup.restype = None
        return vscp_pythia_cleanup()

    def vscp_pythia_blinded_password_buf_len(self):
        """Return length of the buffer needed to hold 'blinded password'."""
        vscp_pythia_blinded_password_buf_len = self._lib.vscp_pythia_blinded_password_buf_len
        vscp_pythia_blinded_password_buf_len.argtypes = []
        vscp_pythia_blinded_password_buf_len.restype = c_size_t
        return vscp_pythia_blinded_password_buf_len()

    def vscp_pythia_deblinded_password_buf_len(self):
        """Return length of the buffer needed to hold 'deblinded password'."""
        vscp_pythia_deblinded_password_buf_len = self._lib.vscp_pythia_deblinded_password_buf_len
        vscp_pythia_deblinded_password_buf_len.argtypes = []
        vscp_pythia_deblinded_password_buf_len.restype = c_size_t
        return vscp_pythia_deblinded_password_buf_len()

    def vscp_pythia_blinding_secret_buf_len(self):
        """Return length of the buffer needed to hold 'blinding secret'."""
        vscp_pythia_blinding_secret_buf_len = self._lib.vscp_pythia_blinding_secret_buf_len
        vscp_pythia_blinding_secret_buf_len.argtypes = []
        vscp_pythia_blinding_secret_buf_len.restype = c_size_t
        return vscp_pythia_blinding_secret_buf_len()

    def vscp_pythia_transformation_private_key_buf_len(self):
        """Return length of the buffer needed to hold 'transformation private key'."""
        vscp_pythia_transformation_private_key_buf_len = self._lib.vscp_pythia_transformation_private_key_buf_len
        vscp_pythia_transformation_private_key_buf_len.argtypes = []
        vscp_pythia_transformation_private_key_buf_len.restype = c_size_t
        return vscp_pythia_transformation_private_key_buf_len()

    def vscp_pythia_transformation_public_key_buf_len(self):
        """Return length of the buffer needed to hold 'transformation public key'."""
        vscp_pythia_transformation_public_key_buf_len = self._lib.vscp_pythia_transformation_public_key_buf_len
        vscp_pythia_transformation_public_key_buf_len.argtypes = []
        vscp_pythia_transformation_public_key_buf_len.restype = c_size_t
        return vscp_pythia_transformation_public_key_buf_len()

    def vscp_pythia_transformed_password_buf_len(self):
        """Return length of the buffer needed to hold 'transformed password'."""
        vscp_pythia_transformed_password_buf_len = self._lib.vscp_pythia_transformed_password_buf_len
        vscp_pythia_transformed_password_buf_len.argtypes = []
        vscp_pythia_transformed_password_buf_len.restype = c_size_t
        return vscp_pythia_transformed_password_buf_len()

    def vscp_pythia_transformed_tweak_buf_len(self):
        """Return length of the buffer needed to hold 'transformed tweak'."""
        vscp_pythia_transformed_tweak_buf_len = self._lib.vscp_pythia_transformed_tweak_buf_len
        vscp_pythia_transformed_tweak_buf_len.argtypes = []
        vscp_pythia_transformed_tweak_buf_len.restype = c_size_t
        return vscp_pythia_transformed_tweak_buf_len()

    def vscp_pythia_proof_value_buf_len(self):
        """Return length of the buffer needed to hold 'proof value'."""
        vscp_pythia_proof_value_buf_len = self._lib.vscp_pythia_proof_value_buf_len
        vscp_pythia_proof_value_buf_len.argtypes = []
        vscp_pythia_proof_value_buf_len.restype = c_size_t
        return vscp_pythia_proof_value_buf_len()

    def vscp_pythia_password_update_token_buf_len(self):
        """Return length of the buffer needed to hold 'password update token'."""
        vscp_pythia_password_update_token_buf_len = self._lib.vscp_pythia_password_update_token_buf_len
        vscp_pythia_password_update_token_buf_len.argtypes = []
        vscp_pythia_password_update_token_buf_len.restype = c_size_t
        return vscp_pythia_password_update_token_buf_len()

    def vscp_pythia_blind(self, password, blinded_password, blinding_secret):
        """Blinds password. Turns password into a pseudo-random string.
        This step is necessary to prevent 3rd-parties from knowledge of end user's password."""
        vscp_pythia_blind = self._lib.vscp_pythia_blind
        vscp_pythia_blind.argtypes = [vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vscp_pythia_blind.restype = c_int
        return vscp_pythia_blind(password, blinded_password, blinding_secret)

    def vscp_pythia_deblind(self, transformed_password, blinding_secret, deblinded_password):
        """Deblinds 'transformed password' value with previously returned 'blinding secret' from blind()."""
        vscp_pythia_deblind = self._lib.vscp_pythia_deblind
        vscp_pythia_deblind.argtypes = [vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vscp_pythia_deblind.restype = c_int
        return vscp_pythia_deblind(transformed_password, blinding_secret, deblinded_password)

    def vscp_pythia_compute_transformation_key_pair(self, transformation_key_id, pythia_secret, pythia_scope_secret, transformation_private_key, transformation_public_key):
        """Computes transformation private and public key."""
        vscp_pythia_compute_transformation_key_pair = self._lib.vscp_pythia_compute_transformation_key_pair
        vscp_pythia_compute_transformation_key_pair.argtypes = [vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vscp_pythia_compute_transformation_key_pair.restype = c_int
        return vscp_pythia_compute_transformation_key_pair(transformation_key_id, pythia_secret, pythia_scope_secret, transformation_private_key, transformation_public_key)

    def vscp_pythia_transform(self, blinded_password, tweak, transformation_private_key, transformed_password, transformed_tweak):
        """Transforms blinded password using transformation private key."""
        vscp_pythia_transform = self._lib.vscp_pythia_transform
        vscp_pythia_transform.argtypes = [vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vscp_pythia_transform.restype = c_int
        return vscp_pythia_transform(blinded_password, tweak, transformation_private_key, transformed_password, transformed_tweak)

    def vscp_pythia_prove(self, transformed_password, blinded_password, transformed_tweak, transformation_private_key, transformation_public_key, proof_value_c, proof_value_u):
        """Generates proof that server possesses secret values that were used to transform password."""
        vscp_pythia_prove = self._lib.vscp_pythia_prove
        vscp_pythia_prove.argtypes = [vsc_data_t, vsc_data_t, vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]
        vscp_pythia_prove.restype = c_int
        return vscp_pythia_prove(transformed_password, blinded_password, transformed_tweak, transformation_private_key, transformation_public_key, proof_value_c, proof_value_u)

    def vscp_pythia_verify(self, transformed_password, blinded_password, tweak, transformation_public_key, proof_value_c, proof_value_u, error):
        """This operation allows client to verify that the output of transform() is correct,
        assuming that client has previously stored transformation public key."""
        vscp_pythia_verify = self._lib.vscp_pythia_verify
        vscp_pythia_verify.argtypes = [vsc_data_t, vsc_data_t, vsc_data_t, vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vscp_error_t)]
        vscp_pythia_verify.restype = c_bool
        return vscp_pythia_verify(transformed_password, blinded_password, tweak, transformation_public_key, proof_value_c, proof_value_u, error)

    def vscp_pythia_get_password_update_token(self, previous_transformation_private_key, new_transformation_private_key, password_update_token):
        """Rotates old transformation key to new transformation key and generates 'password update token',
        that can update 'deblinded password'(s).

        This action should increment version of the 'pythia scope secret'."""
        vscp_pythia_get_password_update_token = self._lib.vscp_pythia_get_password_update_token
        vscp_pythia_get_password_update_token.argtypes = [vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vscp_pythia_get_password_update_token.restype = c_int
        return vscp_pythia_get_password_update_token(previous_transformation_private_key, new_transformation_private_key, password_update_token)

    def vscp_pythia_update_deblinded_with_token(self, deblinded_password, password_update_token, updated_deblinded_password):
        """Updates previously stored 'deblinded password' with 'password update token'.
        After this call, 'transform()' called with new arguments will return corresponding values."""
        vscp_pythia_update_deblinded_with_token = self._lib.vscp_pythia_update_deblinded_with_token
        vscp_pythia_update_deblinded_with_token.argtypes = [vsc_data_t, vsc_data_t, POINTER(vsc_buffer_t)]
        vscp_pythia_update_deblinded_with_token.restype = c_int
        return vscp_pythia_update_deblinded_with_token(deblinded_password, password_update_token, updated_deblinded_password)
