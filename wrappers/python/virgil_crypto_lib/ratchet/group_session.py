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
from ._c_bridge import VscrRatchetGroupSession
from ._c_bridge import VscrStatus
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge._vscr_error import vscr_error_t
from .group_message import GroupMessage
from virgil_crypto_lib.common._c_bridge import Buffer
from .group_session import GroupSession
from .group_ticket import GroupTicket


class GroupSession(object):
    """Ratchet group session."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscr_ratchet_group_session = VscrRatchetGroupSession()
        self.ctx = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_delete(self.ctx)

    def set_rng(self, rng):
        """Random"""
        self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_use_rng(self.ctx, rng.c_impl)

    def is_initialized(self):
        """Shows whether session was initialized."""
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_is_initialized(self.ctx)
        return result

    def is_private_key_set(self):
        """Shows whether identity private key was set."""
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_is_private_key_set(self.ctx)
        return result

    def is_my_id_set(self):
        """Shows whether my id was set."""
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_is_my_id_set(self.ctx)
        return result

    def get_current_epoch(self):
        """Returns current epoch."""
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_get_current_epoch(self.ctx)
        return result

    def setup_defaults(self):
        """Setups default dependencies:
        - RNG: CTR DRBG"""
        status = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_setup_defaults(self.ctx)
        VscrStatus.handle_status(status)

    def set_private_key(self, my_private_key):
        """Sets identity private key."""
        d_my_private_key = Data(my_private_key)
        status = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_set_private_key(self.ctx, d_my_private_key.data)
        VscrStatus.handle_status(status)

    def set_my_id(self, my_id):
        """Sets my id. Should be 32 byte"""
        d_my_id = Data(my_id)
        self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_set_my_id(self.ctx, d_my_id.data)

    def get_my_id(self):
        """Returns my id."""
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_get_my_id(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def get_session_id(self):
        """Returns session id."""
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_get_session_id(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def get_participants_count(self):
        """Returns number of participants."""
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_get_participants_count(self.ctx)
        return result

    def setup_session_state(self, message, participants):
        """Sets up session.
        Use this method when you have newer epoch message and know all participants info.
        NOTE: Identity private key and my id should be set separately."""
        status = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_setup_session_state(self.ctx, message.ctx, participants.ctx)
        VscrStatus.handle_status(status)

    def update_session_state(self, message, add_participants, remove_participants):
        """Sets up session.
        Use this method when you have message with next epoch, and you know how participants set was changed.
        NOTE: Identity private key and my id should be set separately."""
        status = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_update_session_state(self.ctx, message.ctx, add_participants.ctx, remove_participants.ctx)
        VscrStatus.handle_status(status)

    def encrypt(self, plain_text):
        """Encrypts data"""
        d_plain_text = Data(plain_text)
        error = vscr_error_t()
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_encrypt(self.ctx, d_plain_text.data, error)
        VscrStatus.handle_status(error.status)
        instance = GroupMessage.take_c_ctx(result)
        return instance

    def decrypt_len(self, message):
        """Calculates size of buffer sufficient to store decrypted message"""
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_decrypt_len(self.ctx, message.ctx)
        return result

    def decrypt(self, message):
        """Decrypts message"""
        plain_text = Buffer(self.decrypt_len(message=message))
        status = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_decrypt(self.ctx, message.ctx, plain_text.c_buffer)
        VscrStatus.handle_status(status)
        return plain_text.get_bytes()

    def serialize(self):
        """Serializes session to buffer
        NOTE: Session changes its state every encrypt/decrypt operations. Be sure to save it."""
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_serialize(self.ctx)
        instance = Buffer.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def deserialize(self, input):
        """Deserializes session from buffer.
        NOTE: Deserialized session needs dependencies to be set.
        You should set separately:
            - rng
            - my private key"""
        d_input = Data(input)
        error = vscr_error_t()
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_deserialize(d_input.data, error)
        VscrStatus.handle_status(error.status)
        instance = GroupSession.take_c_ctx(result)
        return instance

    def create_group_ticket(self):
        """Creates ticket with new key for adding or removing participants."""
        error = vscr_error_t()
        result = self._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_create_group_ticket(self.ctx, error)
        VscrStatus.handle_status(error.status)
        instance = GroupTicket.take_c_ctx(result)
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_session = VscrRatchetGroupSession()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscr_ratchet_group_session = VscrRatchetGroupSession()
        inst.ctx = inst._lib_vscr_ratchet_group_session.vscr_ratchet_group_session_shallow_copy(c_ctx)
        return inst
