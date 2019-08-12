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
from ._vscr_ratchet_group_message import vscr_ratchet_group_message_t
from ._vscr_ratchet_group_participants_info import vscr_ratchet_group_participants_info_t
from ._vscr_ratchet_group_participants_ids import vscr_ratchet_group_participants_ids_t
from ._vscr_error import vscr_error_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from ._vscr_ratchet_group_ticket import vscr_ratchet_group_ticket_t


class vscr_ratchet_group_session_t(Structure):
    pass


class VscrRatchetGroupSession(object):
    """Ratchet group session."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.ratchet

    def vscr_ratchet_group_session_new(self):
        vscr_ratchet_group_session_new = self._lib.vscr_ratchet_group_session_new
        vscr_ratchet_group_session_new.argtypes = []
        vscr_ratchet_group_session_new.restype = POINTER(vscr_ratchet_group_session_t)
        return vscr_ratchet_group_session_new()

    def vscr_ratchet_group_session_delete(self, ctx):
        vscr_ratchet_group_session_delete = self._lib.vscr_ratchet_group_session_delete
        vscr_ratchet_group_session_delete.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_delete.restype = None
        return vscr_ratchet_group_session_delete(ctx)

    def vscr_ratchet_group_session_use_rng(self, ctx, rng):
        """Random"""
        vscr_ratchet_group_session_use_rng = self._lib.vscr_ratchet_group_session_use_rng
        vscr_ratchet_group_session_use_rng.argtypes = [POINTER(vscr_ratchet_group_session_t), POINTER(vscf_impl_t)]
        vscr_ratchet_group_session_use_rng.restype = None
        return vscr_ratchet_group_session_use_rng(ctx, rng)

    def vscr_ratchet_group_session_is_initialized(self, ctx):
        """Shows whether session was initialized."""
        vscr_ratchet_group_session_is_initialized = self._lib.vscr_ratchet_group_session_is_initialized
        vscr_ratchet_group_session_is_initialized.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_is_initialized.restype = c_bool
        return vscr_ratchet_group_session_is_initialized(ctx)

    def vscr_ratchet_group_session_is_private_key_set(self, ctx):
        """Shows whether identity private key was set."""
        vscr_ratchet_group_session_is_private_key_set = self._lib.vscr_ratchet_group_session_is_private_key_set
        vscr_ratchet_group_session_is_private_key_set.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_is_private_key_set.restype = c_bool
        return vscr_ratchet_group_session_is_private_key_set(ctx)

    def vscr_ratchet_group_session_is_my_id_set(self, ctx):
        """Shows whether my id was set."""
        vscr_ratchet_group_session_is_my_id_set = self._lib.vscr_ratchet_group_session_is_my_id_set
        vscr_ratchet_group_session_is_my_id_set.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_is_my_id_set.restype = c_bool
        return vscr_ratchet_group_session_is_my_id_set(ctx)

    def vscr_ratchet_group_session_get_current_epoch(self, ctx):
        """Returns current epoch."""
        vscr_ratchet_group_session_get_current_epoch = self._lib.vscr_ratchet_group_session_get_current_epoch
        vscr_ratchet_group_session_get_current_epoch.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_get_current_epoch.restype = c_uint
        return vscr_ratchet_group_session_get_current_epoch(ctx)

    def vscr_ratchet_group_session_setup_defaults(self, ctx):
        """Setups default dependencies:
        - RNG: CTR DRBG"""
        vscr_ratchet_group_session_setup_defaults = self._lib.vscr_ratchet_group_session_setup_defaults
        vscr_ratchet_group_session_setup_defaults.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_setup_defaults.restype = c_int
        return vscr_ratchet_group_session_setup_defaults(ctx)

    def vscr_ratchet_group_session_set_private_key(self, ctx, my_private_key):
        """Sets identity private key."""
        vscr_ratchet_group_session_set_private_key = self._lib.vscr_ratchet_group_session_set_private_key
        vscr_ratchet_group_session_set_private_key.argtypes = [POINTER(vscr_ratchet_group_session_t), vsc_data_t]
        vscr_ratchet_group_session_set_private_key.restype = c_int
        return vscr_ratchet_group_session_set_private_key(ctx, my_private_key)

    def vscr_ratchet_group_session_set_my_id(self, ctx, my_id):
        """Sets my id. Should be 32 byte"""
        vscr_ratchet_group_session_set_my_id = self._lib.vscr_ratchet_group_session_set_my_id
        vscr_ratchet_group_session_set_my_id.argtypes = [POINTER(vscr_ratchet_group_session_t), vsc_data_t]
        vscr_ratchet_group_session_set_my_id.restype = None
        return vscr_ratchet_group_session_set_my_id(ctx, my_id)

    def vscr_ratchet_group_session_get_my_id(self, ctx):
        """Returns my id."""
        vscr_ratchet_group_session_get_my_id = self._lib.vscr_ratchet_group_session_get_my_id
        vscr_ratchet_group_session_get_my_id.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_get_my_id.restype = vsc_data_t
        return vscr_ratchet_group_session_get_my_id(ctx)

    def vscr_ratchet_group_session_get_session_id(self, ctx):
        """Returns session id."""
        vscr_ratchet_group_session_get_session_id = self._lib.vscr_ratchet_group_session_get_session_id
        vscr_ratchet_group_session_get_session_id.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_get_session_id.restype = vsc_data_t
        return vscr_ratchet_group_session_get_session_id(ctx)

    def vscr_ratchet_group_session_get_participants_count(self, ctx):
        """Returns number of participants."""
        vscr_ratchet_group_session_get_participants_count = self._lib.vscr_ratchet_group_session_get_participants_count
        vscr_ratchet_group_session_get_participants_count.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_get_participants_count.restype = c_uint
        return vscr_ratchet_group_session_get_participants_count(ctx)

    def vscr_ratchet_group_session_setup_session_state(self, ctx, message, participants):
        """Sets up session.
        Use this method when you have newer epoch message and know all participants info.
        NOTE: Identity private key and my id should be set separately."""
        vscr_ratchet_group_session_setup_session_state = self._lib.vscr_ratchet_group_session_setup_session_state
        vscr_ratchet_group_session_setup_session_state.argtypes = [POINTER(vscr_ratchet_group_session_t), POINTER(vscr_ratchet_group_message_t), POINTER(vscr_ratchet_group_participants_info_t)]
        vscr_ratchet_group_session_setup_session_state.restype = c_int
        return vscr_ratchet_group_session_setup_session_state(ctx, message, participants)

    def vscr_ratchet_group_session_update_session_state(self, ctx, message, add_participants, remove_participants):
        """Sets up session.
        Use this method when you have message with next epoch, and you know how participants set was changed.
        NOTE: Identity private key and my id should be set separately."""
        vscr_ratchet_group_session_update_session_state = self._lib.vscr_ratchet_group_session_update_session_state
        vscr_ratchet_group_session_update_session_state.argtypes = [POINTER(vscr_ratchet_group_session_t), POINTER(vscr_ratchet_group_message_t), POINTER(vscr_ratchet_group_participants_info_t), POINTER(vscr_ratchet_group_participants_ids_t)]
        vscr_ratchet_group_session_update_session_state.restype = c_int
        return vscr_ratchet_group_session_update_session_state(ctx, message, add_participants, remove_participants)

    def vscr_ratchet_group_session_encrypt(self, ctx, plain_text, error):
        """Encrypts data"""
        vscr_ratchet_group_session_encrypt = self._lib.vscr_ratchet_group_session_encrypt
        vscr_ratchet_group_session_encrypt.argtypes = [POINTER(vscr_ratchet_group_session_t), vsc_data_t, POINTER(vscr_error_t)]
        vscr_ratchet_group_session_encrypt.restype = POINTER(vscr_ratchet_group_message_t)
        return vscr_ratchet_group_session_encrypt(ctx, plain_text, error)

    def vscr_ratchet_group_session_decrypt_len(self, ctx, message):
        """Calculates size of buffer sufficient to store decrypted message"""
        vscr_ratchet_group_session_decrypt_len = self._lib.vscr_ratchet_group_session_decrypt_len
        vscr_ratchet_group_session_decrypt_len.argtypes = [POINTER(vscr_ratchet_group_session_t), POINTER(vscr_ratchet_group_message_t)]
        vscr_ratchet_group_session_decrypt_len.restype = c_size_t
        return vscr_ratchet_group_session_decrypt_len(ctx, message)

    def vscr_ratchet_group_session_decrypt(self, ctx, message, sender_id, plain_text):
        """Decrypts message"""
        vscr_ratchet_group_session_decrypt = self._lib.vscr_ratchet_group_session_decrypt
        vscr_ratchet_group_session_decrypt.argtypes = [POINTER(vscr_ratchet_group_session_t), POINTER(vscr_ratchet_group_message_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscr_ratchet_group_session_decrypt.restype = c_int
        return vscr_ratchet_group_session_decrypt(ctx, message, sender_id, plain_text)

    def vscr_ratchet_group_session_serialize(self, ctx):
        """Serializes session to buffer
        NOTE: Session changes its state every encrypt/decrypt operations. Be sure to save it."""
        vscr_ratchet_group_session_serialize = self._lib.vscr_ratchet_group_session_serialize
        vscr_ratchet_group_session_serialize.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_serialize.restype = POINTER(vsc_buffer_t)
        return vscr_ratchet_group_session_serialize(ctx)

    def vscr_ratchet_group_session_deserialize(self, input, error):
        """Deserializes session from buffer.
        NOTE: Deserialized session needs dependencies to be set.
        You should set separately:
            - rng
            - my private key"""
        vscr_ratchet_group_session_deserialize = self._lib.vscr_ratchet_group_session_deserialize
        vscr_ratchet_group_session_deserialize.argtypes = [vsc_data_t, POINTER(vscr_error_t)]
        vscr_ratchet_group_session_deserialize.restype = POINTER(vscr_ratchet_group_session_t)
        return vscr_ratchet_group_session_deserialize(input, error)

    def vscr_ratchet_group_session_create_group_ticket(self, ctx, error):
        """Creates ticket with new key for adding or removing participants."""
        vscr_ratchet_group_session_create_group_ticket = self._lib.vscr_ratchet_group_session_create_group_ticket
        vscr_ratchet_group_session_create_group_ticket.argtypes = [POINTER(vscr_ratchet_group_session_t), POINTER(vscr_error_t)]
        vscr_ratchet_group_session_create_group_ticket.restype = POINTER(vscr_ratchet_group_ticket_t)
        return vscr_ratchet_group_session_create_group_ticket(ctx, error)

    def vscr_ratchet_group_session_shallow_copy(self, ctx):
        vscr_ratchet_group_session_shallow_copy = self._lib.vscr_ratchet_group_session_shallow_copy
        vscr_ratchet_group_session_shallow_copy.argtypes = [POINTER(vscr_ratchet_group_session_t)]
        vscr_ratchet_group_session_shallow_copy.restype = POINTER(vscr_ratchet_group_session_t)
        return vscr_ratchet_group_session_shallow_copy(ctx)
