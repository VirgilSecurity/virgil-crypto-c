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
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t


class vscf_message_info_editor_t(Structure):
    pass


class VscfMessageInfoEditor(object):
    """Add and/or remove recipients and it's parameters within message info.

    Usage:
      1. Unpack binary message info that was obtained from RecipientCipher.
      2. Add and/or remove key recipients.
      3. Pack MessagInfo to the binary data."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_message_info_editor_new(self):
        vscf_message_info_editor_new = self._lib.vscf_message_info_editor_new
        vscf_message_info_editor_new.argtypes = []
        vscf_message_info_editor_new.restype = POINTER(vscf_message_info_editor_t)
        return vscf_message_info_editor_new()

    def vscf_message_info_editor_delete(self, ctx):
        vscf_message_info_editor_delete = self._lib.vscf_message_info_editor_delete
        vscf_message_info_editor_delete.argtypes = [POINTER(vscf_message_info_editor_t)]
        vscf_message_info_editor_delete.restype = None
        return vscf_message_info_editor_delete(ctx)

    def vscf_message_info_editor_use_random(self, ctx, random):
        vscf_message_info_editor_use_random = self._lib.vscf_message_info_editor_use_random
        vscf_message_info_editor_use_random.argtypes = [POINTER(vscf_message_info_editor_t), POINTER(vscf_impl_t)]
        vscf_message_info_editor_use_random.restype = None
        return vscf_message_info_editor_use_random(ctx, random)

    def vscf_message_info_editor_setup_defaults(self, ctx):
        """Set dependencies to it's defaults."""
        vscf_message_info_editor_setup_defaults = self._lib.vscf_message_info_editor_setup_defaults
        vscf_message_info_editor_setup_defaults.argtypes = [POINTER(vscf_message_info_editor_t)]
        vscf_message_info_editor_setup_defaults.restype = c_int
        return vscf_message_info_editor_setup_defaults(ctx)

    def vscf_message_info_editor_unpack(self, ctx, message_info_data):
        """Unpack serialized message info.

        Note that recipients can only be removed but not added.
        Note, use "unlock" method to be able to add new recipients as well."""
        vscf_message_info_editor_unpack = self._lib.vscf_message_info_editor_unpack
        vscf_message_info_editor_unpack.argtypes = [POINTER(vscf_message_info_editor_t), vsc_data_t]
        vscf_message_info_editor_unpack.restype = c_int
        return vscf_message_info_editor_unpack(ctx, message_info_data)

    def vscf_message_info_editor_unlock(self, ctx, owner_recipient_id, owner_private_key):
        """Decrypt encryption key this allows adding new recipients."""
        vscf_message_info_editor_unlock = self._lib.vscf_message_info_editor_unlock
        vscf_message_info_editor_unlock.argtypes = [POINTER(vscf_message_info_editor_t), vsc_data_t, POINTER(vscf_impl_t)]
        vscf_message_info_editor_unlock.restype = c_int
        return vscf_message_info_editor_unlock(ctx, owner_recipient_id, owner_private_key)

    def vscf_message_info_editor_add_key_recipient(self, ctx, recipient_id, public_key):
        """Add recipient defined with id and public key."""
        vscf_message_info_editor_add_key_recipient = self._lib.vscf_message_info_editor_add_key_recipient
        vscf_message_info_editor_add_key_recipient.argtypes = [POINTER(vscf_message_info_editor_t), vsc_data_t, POINTER(vscf_impl_t)]
        vscf_message_info_editor_add_key_recipient.restype = c_int
        return vscf_message_info_editor_add_key_recipient(ctx, recipient_id, public_key)

    def vscf_message_info_editor_remove_key_recipient(self, ctx, recipient_id):
        """Remove recipient with a given id.
        Return false if recipient with given id was not found."""
        vscf_message_info_editor_remove_key_recipient = self._lib.vscf_message_info_editor_remove_key_recipient
        vscf_message_info_editor_remove_key_recipient.argtypes = [POINTER(vscf_message_info_editor_t), vsc_data_t]
        vscf_message_info_editor_remove_key_recipient.restype = c_bool
        return vscf_message_info_editor_remove_key_recipient(ctx, recipient_id)

    def vscf_message_info_editor_remove_all(self, ctx):
        """Remove all existent recipients."""
        vscf_message_info_editor_remove_all = self._lib.vscf_message_info_editor_remove_all
        vscf_message_info_editor_remove_all.argtypes = [POINTER(vscf_message_info_editor_t)]
        vscf_message_info_editor_remove_all.restype = None
        return vscf_message_info_editor_remove_all(ctx)

    def vscf_message_info_editor_packed_len(self, ctx):
        """Return length of serialized message info.
        Actual length can be obtained right after applying changes."""
        vscf_message_info_editor_packed_len = self._lib.vscf_message_info_editor_packed_len
        vscf_message_info_editor_packed_len.argtypes = [POINTER(vscf_message_info_editor_t)]
        vscf_message_info_editor_packed_len.restype = c_size_t
        return vscf_message_info_editor_packed_len(ctx)

    def vscf_message_info_editor_pack(self, ctx, message_info):
        """Return serialized message info.
        Precondition: this method can be called after "apply"."""
        vscf_message_info_editor_pack = self._lib.vscf_message_info_editor_pack
        vscf_message_info_editor_pack.argtypes = [POINTER(vscf_message_info_editor_t), POINTER(vsc_buffer_t)]
        vscf_message_info_editor_pack.restype = None
        return vscf_message_info_editor_pack(ctx, message_info)

    def vscf_message_info_editor_shallow_copy(self, ctx):
        vscf_message_info_editor_shallow_copy = self._lib.vscf_message_info_editor_shallow_copy
        vscf_message_info_editor_shallow_copy.argtypes = [POINTER(vscf_message_info_editor_t)]
        vscf_message_info_editor_shallow_copy.restype = POINTER(vscf_message_info_editor_t)
        return vscf_message_info_editor_shallow_copy(ctx)
