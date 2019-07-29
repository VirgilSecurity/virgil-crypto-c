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
from ._c_bridge import VscrRatchetSession
from ._c_bridge import VscrStatus
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge._vscr_error import vscr_error_t
from .message import Message
from virgil_crypto_lib.common._c_bridge import Buffer
from .session import Session


class Session(object):
    """Class for ratchet session between 2 participants"""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscr_ratchet_session = VscrRatchetSession()
        self.ctx = self._lib_vscr_ratchet_session.vscr_ratchet_session_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscr_ratchet_session.vscr_ratchet_session_delete(self.ctx)

    def set_rng(self, rng):
        """Random used to generate keys"""
        self._lib_vscr_ratchet_session.vscr_ratchet_session_use_rng(self.ctx, rng.c_impl)

    def setup_defaults(self):
        """Setups default dependencies:
            - RNG: CTR DRBG"""
        status = self._lib_vscr_ratchet_session.vscr_ratchet_session_setup_defaults(self.ctx)
        VscrStatus.handle_status(status)

    def initiate(self, sender_identity_private_key, receiver_identity_public_key, receiver_long_term_public_key, receiver_one_time_public_key):
        """Initiates session"""
        d_sender_identity_private_key = Data(sender_identity_private_key)
        d_receiver_identity_public_key = Data(receiver_identity_public_key)
        d_receiver_long_term_public_key = Data(receiver_long_term_public_key)
        d_receiver_one_time_public_key = Data(receiver_one_time_public_key)
        status = self._lib_vscr_ratchet_session.vscr_ratchet_session_initiate(self.ctx, d_sender_identity_private_key.data, d_receiver_identity_public_key.data, d_receiver_long_term_public_key.data, d_receiver_one_time_public_key.data)
        VscrStatus.handle_status(status)

    def respond(self, sender_identity_public_key, receiver_identity_private_key, receiver_long_term_private_key, receiver_one_time_private_key, message):
        """Responds to session initiation"""
        d_sender_identity_public_key = Data(sender_identity_public_key)
        d_receiver_identity_private_key = Data(receiver_identity_private_key)
        d_receiver_long_term_private_key = Data(receiver_long_term_private_key)
        d_receiver_one_time_private_key = Data(receiver_one_time_private_key)
        status = self._lib_vscr_ratchet_session.vscr_ratchet_session_respond(self.ctx, d_sender_identity_public_key.data, d_receiver_identity_private_key.data, d_receiver_long_term_private_key.data, d_receiver_one_time_private_key.data, message.ctx)
        VscrStatus.handle_status(status)

    def is_initiator(self):
        """Returns flag that indicates is this session was initiated or responded"""
        result = self._lib_vscr_ratchet_session.vscr_ratchet_session_is_initiator(self.ctx)
        return result

    def received_first_response(self):
        """Returns true if at least 1 response was successfully decrypted, false - otherwise"""
        result = self._lib_vscr_ratchet_session.vscr_ratchet_session_received_first_response(self.ctx)
        return result

    def receiver_has_one_time_public_key(self):
        """Returns true if receiver had one time public key"""
        result = self._lib_vscr_ratchet_session.vscr_ratchet_session_receiver_has_one_time_public_key(self.ctx)
        return result

    def encrypt(self, plain_text):
        """Encrypts data"""
        d_plain_text = Data(plain_text)
        error = vscr_error_t()
        result = self._lib_vscr_ratchet_session.vscr_ratchet_session_encrypt(self.ctx, d_plain_text.data, error)
        VscrStatus.handle_status(error.status)
        instance = Message.take_c_ctx(result)
        return instance

    def decrypt_len(self, message):
        """Calculates size of buffer sufficient to store decrypted message"""
        result = self._lib_vscr_ratchet_session.vscr_ratchet_session_decrypt_len(self.ctx, message.ctx)
        return result

    def decrypt(self, message):
        """Decrypts message"""
        plain_text = Buffer(self.decrypt_len(message=message))
        status = self._lib_vscr_ratchet_session.vscr_ratchet_session_decrypt(self.ctx, message.ctx, plain_text.c_buffer)
        VscrStatus.handle_status(status)
        return plain_text.get_bytes()

    def serialize(self):
        """Serializes session to buffer"""
        result = self._lib_vscr_ratchet_session.vscr_ratchet_session_serialize(self.ctx)
        instance = Buffer.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def deserialize(self, input):
        """Deserializes session from buffer.
        NOTE: Deserialized session needs dependencies to be set. Check setup defaults"""
        d_input = Data(input)
        error = vscr_error_t()
        result = self._lib_vscr_ratchet_session.vscr_ratchet_session_deserialize(d_input.data, error)
        VscrStatus.handle_status(error.status)
        instance = Session.take_c_ctx(result)
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_session = VscrRatchetSession()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_session = VscrRatchetSession()
        inst.ctx = inst._lib_vscr_ratchet_session.vscr_ratchet_session_shallow_copy(c_ctx)
        return inst
