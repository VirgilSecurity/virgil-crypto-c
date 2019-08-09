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
from ._vscf_impl import vscf_impl_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_group_session_message import vscf_group_session_message_t
from ._vscf_error import vscf_error_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from ._vscf_group_session_ticket import vscf_group_session_ticket_t


class vscf_group_session_t(Structure):
    pass


class VscfGroupSession(object):
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
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_group_session_new(self):
        vscf_group_session_new = self._lib.vscf_group_session_new
        vscf_group_session_new.argtypes = []
        vscf_group_session_new.restype = POINTER(vscf_group_session_t)
        return vscf_group_session_new()

    def vscf_group_session_delete(self, ctx):
        vscf_group_session_delete = self._lib.vscf_group_session_delete
        vscf_group_session_delete.argtypes = [POINTER(vscf_group_session_t)]
        vscf_group_session_delete.restype = None
        return vscf_group_session_delete(ctx)

    def vscf_group_session_use_rng(self, ctx, rng):
        """Random"""
        vscf_group_session_use_rng = self._lib.vscf_group_session_use_rng
        vscf_group_session_use_rng.argtypes = [POINTER(vscf_group_session_t), POINTER(vscf_impl_t)]
        vscf_group_session_use_rng.restype = None
        return vscf_group_session_use_rng(ctx, rng)

    def vscf_group_session_get_current_epoch(self, ctx):
        """Returns current epoch."""
        vscf_group_session_get_current_epoch = self._lib.vscf_group_session_get_current_epoch
        vscf_group_session_get_current_epoch.argtypes = [POINTER(vscf_group_session_t)]
        vscf_group_session_get_current_epoch.restype = c_uint
        return vscf_group_session_get_current_epoch(ctx)

    def vscf_group_session_setup_defaults(self, ctx):
        """Setups default dependencies:
        - RNG: CTR DRBG"""
        vscf_group_session_setup_defaults = self._lib.vscf_group_session_setup_defaults
        vscf_group_session_setup_defaults.argtypes = [POINTER(vscf_group_session_t)]
        vscf_group_session_setup_defaults.restype = c_int
        return vscf_group_session_setup_defaults(ctx)

    def vscf_group_session_get_session_id(self, ctx):
        """Returns session id."""
        vscf_group_session_get_session_id = self._lib.vscf_group_session_get_session_id
        vscf_group_session_get_session_id.argtypes = [POINTER(vscf_group_session_t)]
        vscf_group_session_get_session_id.restype = vsc_data_t
        return vscf_group_session_get_session_id(ctx)

    def vscf_group_session_add_epoch(self, ctx, message):
        """Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
        Epoch message should be encrypted and signed by trusted group chat member (admin)."""
        vscf_group_session_add_epoch = self._lib.vscf_group_session_add_epoch
        vscf_group_session_add_epoch.argtypes = [POINTER(vscf_group_session_t), POINTER(vscf_group_session_message_t)]
        vscf_group_session_add_epoch.restype = c_int
        return vscf_group_session_add_epoch(ctx, message)

    def vscf_group_session_encrypt(self, ctx, plain_text, private_key, sender_id, error):
        """Encrypts data"""
        vscf_group_session_encrypt = self._lib.vscf_group_session_encrypt
        vscf_group_session_encrypt.argtypes = [POINTER(vscf_group_session_t), vsc_data_t, POINTER(vscf_impl_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_group_session_encrypt.restype = POINTER(vscf_group_session_message_t)
        return vscf_group_session_encrypt(ctx, plain_text, private_key, sender_id, error)

    def vscf_group_session_decrypt_len(self, ctx, message):
        """Calculates size of buffer sufficient to store decrypted message"""
        vscf_group_session_decrypt_len = self._lib.vscf_group_session_decrypt_len
        vscf_group_session_decrypt_len.argtypes = [POINTER(vscf_group_session_t), POINTER(vscf_group_session_message_t)]
        vscf_group_session_decrypt_len.restype = c_size_t
        return vscf_group_session_decrypt_len(ctx, message)

    def vscf_group_session_decrypt(self, ctx, message, public_key, sender_id, plain_text):
        """Decrypts message"""
        vscf_group_session_decrypt = self._lib.vscf_group_session_decrypt
        vscf_group_session_decrypt.argtypes = [POINTER(vscf_group_session_t), POINTER(vscf_group_session_message_t), POINTER(vscf_impl_t), vsc_data_t, POINTER(vsc_buffer_t)]
        vscf_group_session_decrypt.restype = c_int
        return vscf_group_session_decrypt(ctx, message, public_key, sender_id, plain_text)

    def vscf_group_session_create_group_ticket(self, ctx, error):
        """Creates ticket with new key for removing participants or proactive to rotate encryption key."""
        vscf_group_session_create_group_ticket = self._lib.vscf_group_session_create_group_ticket
        vscf_group_session_create_group_ticket.argtypes = [POINTER(vscf_group_session_t), POINTER(vscf_error_t)]
        vscf_group_session_create_group_ticket.restype = POINTER(vscf_group_session_ticket_t)
        return vscf_group_session_create_group_ticket(ctx, error)

    def vscf_group_session_shallow_copy(self, ctx):
        vscf_group_session_shallow_copy = self._lib.vscf_group_session_shallow_copy
        vscf_group_session_shallow_copy.argtypes = [POINTER(vscf_group_session_t)]
        vscf_group_session_shallow_copy.restype = POINTER(vscf_group_session_t)
        return vscf_group_session_shallow_copy(ctx)
