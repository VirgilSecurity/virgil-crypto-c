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
from ._c_bridge import VscfGroupSession
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge._vscf_error import vscf_error_t
from .group_session_message import GroupSessionMessage
from virgil_crypto_lib.common._c_bridge import Buffer
from .group_session_ticket import GroupSessionTicket


class GroupSession(object):
    """Group chat encryption session."""

    # Sender id len
    SENDER_ID_LEN = 32
    # Max plain text len
    MAX_PLAIN_TEXT_LEN = 30000
    # Max epochs count
    MAX_EPOCHS_COUNT = 50
    # Salt size
    SALT_SIZE = 32

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_group_session = VscfGroupSession()
        self.ctx = self._lib_vscf_group_session.vscf_group_session_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_group_session.vscf_group_session_delete(self.ctx)

    def set_rng(self, rng):
        """Random"""
        self._lib_vscf_group_session.vscf_group_session_use_rng(self.ctx, rng.c_impl)

    def get_current_epoch(self):
        """Returns current epoch."""
        result = self._lib_vscf_group_session.vscf_group_session_get_current_epoch(self.ctx)
        return result

    def setup_defaults(self):
        """Setups default dependencies:
        - RNG: CTR DRBG"""
        status = self._lib_vscf_group_session.vscf_group_session_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def get_session_id(self):
        """Returns session id."""
        result = self._lib_vscf_group_session.vscf_group_session_get_session_id(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def add_epoch(self, message):
        """Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
        Epoch message should be encrypted and signed by trusted group chat member (admin)."""
        status = self._lib_vscf_group_session.vscf_group_session_add_epoch(self.ctx, message.ctx)
        VscfStatus.handle_status(status)

    def encrypt(self, plain_text, private_key):
        """Encrypts data"""
        d_plain_text = Data(plain_text)
        error = vscf_error_t()
        result = self._lib_vscf_group_session.vscf_group_session_encrypt(self.ctx, d_plain_text.data, private_key.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = GroupSessionMessage.take_c_ctx(result)
        return instance

    def decrypt_len(self, message):
        """Calculates size of buffer sufficient to store decrypted message"""
        result = self._lib_vscf_group_session.vscf_group_session_decrypt_len(self.ctx, message.ctx)
        return result

    def decrypt(self, message, public_key):
        """Decrypts message"""
        plain_text = Buffer(self.decrypt_len(message=message))
        status = self._lib_vscf_group_session.vscf_group_session_decrypt(self.ctx, message.ctx, public_key.c_impl, plain_text.c_buffer)
        VscfStatus.handle_status(status)
        return plain_text.get_bytes()

    def create_group_ticket(self):
        """Creates ticket with new key for removing participants or proactive to rotate encryption key."""
        error = vscf_error_t()
        result = self._lib_vscf_group_session.vscf_group_session_create_group_ticket(self.ctx, error)
        VscfStatus.handle_status(error.status)
        instance = GroupSessionTicket.take_c_ctx(result)
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_group_session = VscfGroupSession()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_group_session = VscfGroupSession()
        inst.ctx = inst._lib_vscf_group_session.vscf_group_session_shallow_copy(c_ctx)
        return inst
