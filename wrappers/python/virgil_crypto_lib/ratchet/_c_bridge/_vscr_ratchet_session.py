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
from ._vscr_ratchet_message import vscr_ratchet_message_t
from ._vscr_error import vscr_error_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscr_ratchet_session_t(Structure):
    pass


class VscrRatchetSession(object):
    """Class for ratchet session between 2 participants"""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.ratchet

    def vscr_ratchet_session_new(self):
        vscr_ratchet_session_new = self._lib.vscr_ratchet_session_new
        vscr_ratchet_session_new.argtypes = []
        vscr_ratchet_session_new.restype = POINTER(vscr_ratchet_session_t)
        return vscr_ratchet_session_new()

    def vscr_ratchet_session_delete(self, ctx):
        vscr_ratchet_session_delete = self._lib.vscr_ratchet_session_delete
        vscr_ratchet_session_delete.argtypes = [POINTER(vscr_ratchet_session_t)]
        vscr_ratchet_session_delete.restype = None
        return vscr_ratchet_session_delete(ctx)

    def vscr_ratchet_session_use_rng(self, ctx, rng):
        """Random used to generate keys"""
        vscr_ratchet_session_use_rng = self._lib.vscr_ratchet_session_use_rng
        vscr_ratchet_session_use_rng.argtypes = [POINTER(vscr_ratchet_session_t), POINTER(vscf_impl_t)]
        vscr_ratchet_session_use_rng.restype = None
        return vscr_ratchet_session_use_rng(ctx, rng)

    def vscr_ratchet_session_setup_defaults(self, ctx):
        """Setups default dependencies:
            - RNG: CTR DRBG"""
        vscr_ratchet_session_setup_defaults = self._lib.vscr_ratchet_session_setup_defaults
        vscr_ratchet_session_setup_defaults.argtypes = [POINTER(vscr_ratchet_session_t)]
        vscr_ratchet_session_setup_defaults.restype = c_int
        return vscr_ratchet_session_setup_defaults(ctx)

    def vscr_ratchet_session_initiate(self, ctx, sender_identity_private_key, receiver_identity_public_key, receiver_long_term_public_key, receiver_one_time_public_key):
        """Initiates session"""
        vscr_ratchet_session_initiate = self._lib.vscr_ratchet_session_initiate
        vscr_ratchet_session_initiate.argtypes = [POINTER(vscr_ratchet_session_t), vsc_data_t, vsc_data_t, vsc_data_t, vsc_data_t]
        vscr_ratchet_session_initiate.restype = c_int
        return vscr_ratchet_session_initiate(ctx, sender_identity_private_key, receiver_identity_public_key, receiver_long_term_public_key, receiver_one_time_public_key)

    def vscr_ratchet_session_respond(self, ctx, sender_identity_public_key, receiver_identity_private_key, receiver_long_term_private_key, receiver_one_time_private_key, message):
        """Responds to session initiation"""
        vscr_ratchet_session_respond = self._lib.vscr_ratchet_session_respond
        vscr_ratchet_session_respond.argtypes = [POINTER(vscr_ratchet_session_t), vsc_data_t, vsc_data_t, vsc_data_t, vsc_data_t, POINTER(vscr_ratchet_message_t)]
        vscr_ratchet_session_respond.restype = c_int
        return vscr_ratchet_session_respond(ctx, sender_identity_public_key, receiver_identity_private_key, receiver_long_term_private_key, receiver_one_time_private_key, message)

    def vscr_ratchet_session_is_initiator(self, ctx):
        """Returns flag that indicates is this session was initiated or responded"""
        vscr_ratchet_session_is_initiator = self._lib.vscr_ratchet_session_is_initiator
        vscr_ratchet_session_is_initiator.argtypes = [POINTER(vscr_ratchet_session_t)]
        vscr_ratchet_session_is_initiator.restype = c_bool
        return vscr_ratchet_session_is_initiator(ctx)

    def vscr_ratchet_session_received_first_response(self, ctx):
        """Returns true if at least 1 response was successfully decrypted, false - otherwise"""
        vscr_ratchet_session_received_first_response = self._lib.vscr_ratchet_session_received_first_response
        vscr_ratchet_session_received_first_response.argtypes = [POINTER(vscr_ratchet_session_t)]
        vscr_ratchet_session_received_first_response.restype = c_bool
        return vscr_ratchet_session_received_first_response(ctx)

    def vscr_ratchet_session_receiver_has_one_time_public_key(self, ctx):
        """Returns true if receiver had one time public key"""
        vscr_ratchet_session_receiver_has_one_time_public_key = self._lib.vscr_ratchet_session_receiver_has_one_time_public_key
        vscr_ratchet_session_receiver_has_one_time_public_key.argtypes = [POINTER(vscr_ratchet_session_t)]
        vscr_ratchet_session_receiver_has_one_time_public_key.restype = c_bool
        return vscr_ratchet_session_receiver_has_one_time_public_key(ctx)

    def vscr_ratchet_session_encrypt(self, ctx, plain_text, error):
        """Encrypts data"""
        vscr_ratchet_session_encrypt = self._lib.vscr_ratchet_session_encrypt
        vscr_ratchet_session_encrypt.argtypes = [POINTER(vscr_ratchet_session_t), vsc_data_t, POINTER(vscr_error_t)]
        vscr_ratchet_session_encrypt.restype = POINTER(vscr_ratchet_message_t)
        return vscr_ratchet_session_encrypt(ctx, plain_text, error)

    def vscr_ratchet_session_decrypt_len(self, ctx, message):
        """Calculates size of buffer sufficient to store decrypted message"""
        vscr_ratchet_session_decrypt_len = self._lib.vscr_ratchet_session_decrypt_len
        vscr_ratchet_session_decrypt_len.argtypes = [POINTER(vscr_ratchet_session_t), POINTER(vscr_ratchet_message_t)]
        vscr_ratchet_session_decrypt_len.restype = c_size_t
        return vscr_ratchet_session_decrypt_len(ctx, message)

    def vscr_ratchet_session_decrypt(self, ctx, message, plain_text):
        """Decrypts message"""
        vscr_ratchet_session_decrypt = self._lib.vscr_ratchet_session_decrypt
        vscr_ratchet_session_decrypt.argtypes = [POINTER(vscr_ratchet_session_t), POINTER(vscr_ratchet_message_t), POINTER(vsc_buffer_t)]
        vscr_ratchet_session_decrypt.restype = c_int
        return vscr_ratchet_session_decrypt(ctx, message, plain_text)

    def vscr_ratchet_session_serialize(self, ctx):
        """Serializes session to buffer"""
        vscr_ratchet_session_serialize = self._lib.vscr_ratchet_session_serialize
        vscr_ratchet_session_serialize.argtypes = [POINTER(vscr_ratchet_session_t)]
        vscr_ratchet_session_serialize.restype = POINTER(vsc_buffer_t)
        return vscr_ratchet_session_serialize(ctx)

    def vscr_ratchet_session_deserialize(self, input, error):
        """Deserializes session from buffer.
        NOTE: Deserialized session needs dependencies to be set. Check setup defaults"""
        vscr_ratchet_session_deserialize = self._lib.vscr_ratchet_session_deserialize
        vscr_ratchet_session_deserialize.argtypes = [vsc_data_t, POINTER(vscr_error_t)]
        vscr_ratchet_session_deserialize.restype = POINTER(vscr_ratchet_session_t)
        return vscr_ratchet_session_deserialize(input, error)

    def vscr_ratchet_session_shallow_copy(self, ctx):
        vscr_ratchet_session_shallow_copy = self._lib.vscr_ratchet_session_shallow_copy
        vscr_ratchet_session_shallow_copy.argtypes = [POINTER(vscr_ratchet_session_t)]
        vscr_ratchet_session_shallow_copy.restype = POINTER(vscr_ratchet_session_t)
        return vscr_ratchet_session_shallow_copy(ctx)
