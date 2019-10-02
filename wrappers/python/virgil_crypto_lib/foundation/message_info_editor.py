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
from ._c_bridge import VscfMessageInfoEditor
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer


class MessageInfoEditor(object):
    """Add and/or remove recipients and it's parameters within message info.

    Usage:
      1. Unpack binary message info that was obtained from RecipientCipher.
      2. Add and/or remove key recipients.
      3. Pack MessagInfo to the binary data."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_message_info_editor = VscfMessageInfoEditor()
        self.ctx = self._lib_vscf_message_info_editor.vscf_message_info_editor_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_message_info_editor.vscf_message_info_editor_delete(self.ctx)

    def set_random(self, random):
        self._lib_vscf_message_info_editor.vscf_message_info_editor_use_random(self.ctx, random.c_impl)

    def setup_defaults(self):
        """Set dependencies to it's defaults."""
        status = self._lib_vscf_message_info_editor.vscf_message_info_editor_setup_defaults(self.ctx)
        VscfStatus.handle_status(status)

    def unpack(self, message_info_data):
        """Unpack serialized message info.

        Note that recipients can only be removed but not added.
        Note, use "unlock" method to be able to add new recipients as well."""
        d_message_info_data = Data(message_info_data)
        status = self._lib_vscf_message_info_editor.vscf_message_info_editor_unpack(self.ctx, d_message_info_data.data)
        VscfStatus.handle_status(status)

    def unlock(self, owner_recipient_id, owner_private_key):
        """Decrypt encryption key this allows adding new recipients."""
        d_owner_recipient_id = Data(owner_recipient_id)
        status = self._lib_vscf_message_info_editor.vscf_message_info_editor_unlock(self.ctx, d_owner_recipient_id.data, owner_private_key.c_impl)
        VscfStatus.handle_status(status)

    def add_key_recipient(self, recipient_id, public_key):
        """Add recipient defined with id and public key."""
        d_recipient_id = Data(recipient_id)
        status = self._lib_vscf_message_info_editor.vscf_message_info_editor_add_key_recipient(self.ctx, d_recipient_id.data, public_key.c_impl)
        VscfStatus.handle_status(status)

    def remove_key_recipient(self, recipient_id):
        """Remove recipient with a given id.
        Return false if recipient with given id was not found."""
        d_recipient_id = Data(recipient_id)
        result = self._lib_vscf_message_info_editor.vscf_message_info_editor_remove_key_recipient(self.ctx, d_recipient_id.data)
        return result

    def remove_all(self):
        """Remove all existent recipients."""
        self._lib_vscf_message_info_editor.vscf_message_info_editor_remove_all(self.ctx)

    def packed_len(self):
        """Return length of serialized message info.
        Actual length can be obtained right after applying changes."""
        result = self._lib_vscf_message_info_editor.vscf_message_info_editor_packed_len(self.ctx)
        return result

    def pack(self):
        """Return serialized message info.
        Precondition: this method can be called after "apply"."""
        message_info = Buffer(self.packed_len())
        self._lib_vscf_message_info_editor.vscf_message_info_editor_pack(self.ctx, message_info.c_buffer)
        return message_info.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_editor = VscfMessageInfoEditor()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_editor = VscfMessageInfoEditor()
        inst.ctx = inst._lib_vscf_message_info_editor.vscf_message_info_editor_shallow_copy(c_ctx)
        return inst
