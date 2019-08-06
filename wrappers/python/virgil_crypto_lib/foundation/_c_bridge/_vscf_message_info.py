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
from ._vscf_key_recipient_info import vscf_key_recipient_info_t
from ._vscf_password_recipient_info import vscf_password_recipient_info_t
from ._vscf_impl import vscf_impl_t
from ._vscf_key_recipient_info_list import vscf_key_recipient_info_list_t
from ._vscf_password_recipient_info_list import vscf_password_recipient_info_list_t
from ._vscf_message_info_custom_params import vscf_message_info_custom_params_t


class vscf_message_info_t(Structure):
    pass


class VscfMessageInfo(object):
    """Handle information about an encrypted message and algorithms
    that was used for encryption."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_message_info_new(self):
        vscf_message_info_new = self._lib.vscf_message_info_new
        vscf_message_info_new.argtypes = []
        vscf_message_info_new.restype = POINTER(vscf_message_info_t)
        return vscf_message_info_new()

    def vscf_message_info_delete(self, ctx):
        vscf_message_info_delete = self._lib.vscf_message_info_delete
        vscf_message_info_delete.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_delete.restype = None
        return vscf_message_info_delete(ctx)

    def vscf_message_info_add_key_recipient(self, ctx, key_recipient):
        """Add recipient that is defined by Public Key."""
        vscf_message_info_add_key_recipient = self._lib.vscf_message_info_add_key_recipient
        vscf_message_info_add_key_recipient.argtypes = [POINTER(vscf_message_info_t), POINTER(vscf_key_recipient_info_t)]
        vscf_message_info_add_key_recipient.restype = None
        return vscf_message_info_add_key_recipient(ctx, key_recipient)

    def vscf_message_info_add_password_recipient(self, ctx, password_recipient):
        """Add recipient that is defined by password."""
        vscf_message_info_add_password_recipient = self._lib.vscf_message_info_add_password_recipient
        vscf_message_info_add_password_recipient.argtypes = [POINTER(vscf_message_info_t), POINTER(vscf_password_recipient_info_t)]
        vscf_message_info_add_password_recipient.restype = None
        return vscf_message_info_add_password_recipient(ctx, password_recipient)

    def vscf_message_info_set_data_encryption_alg_info(self, ctx, data_encryption_alg_info):
        """Set information about algorithm that was used for data encryption."""
        vscf_message_info_set_data_encryption_alg_info = self._lib.vscf_message_info_set_data_encryption_alg_info
        vscf_message_info_set_data_encryption_alg_info.argtypes = [POINTER(vscf_message_info_t), POINTER(vscf_impl_t)]
        vscf_message_info_set_data_encryption_alg_info.restype = None
        return vscf_message_info_set_data_encryption_alg_info(ctx, data_encryption_alg_info)

    def vscf_message_info_data_encryption_alg_info(self, ctx):
        """Return information about algorithm that was used for the data encryption."""
        vscf_message_info_data_encryption_alg_info = self._lib.vscf_message_info_data_encryption_alg_info
        vscf_message_info_data_encryption_alg_info.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_data_encryption_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_message_info_data_encryption_alg_info(ctx)

    def vscf_message_info_key_recipient_info_list(self, ctx):
        """Return list with a "key recipient info" elements."""
        vscf_message_info_key_recipient_info_list = self._lib.vscf_message_info_key_recipient_info_list
        vscf_message_info_key_recipient_info_list.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_key_recipient_info_list.restype = POINTER(vscf_key_recipient_info_list_t)
        return vscf_message_info_key_recipient_info_list(ctx)

    def vscf_message_info_password_recipient_info_list(self, ctx):
        """Return list with a "password recipient info" elements."""
        vscf_message_info_password_recipient_info_list = self._lib.vscf_message_info_password_recipient_info_list
        vscf_message_info_password_recipient_info_list.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_password_recipient_info_list.restype = POINTER(vscf_password_recipient_info_list_t)
        return vscf_message_info_password_recipient_info_list(ctx)

    def vscf_message_info_set_custom_params(self, ctx, custom_params):
        """Setup custom params."""
        vscf_message_info_set_custom_params = self._lib.vscf_message_info_set_custom_params
        vscf_message_info_set_custom_params.argtypes = [POINTER(vscf_message_info_t), POINTER(vscf_message_info_custom_params_t)]
        vscf_message_info_set_custom_params.restype = None
        return vscf_message_info_set_custom_params(ctx, custom_params)

    def vscf_message_info_custom_params(self, ctx):
        """Provide access to the custom params object.
        The returned object can be used to add custom params or read it.
        If custom params object was not set then new empty object is created."""
        vscf_message_info_custom_params = self._lib.vscf_message_info_custom_params
        vscf_message_info_custom_params.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_custom_params.restype = POINTER(vscf_message_info_custom_params_t)
        return vscf_message_info_custom_params(ctx)

    def vscf_message_info_clear_recipients(self, ctx):
        """Remove all recipients."""
        vscf_message_info_clear_recipients = self._lib.vscf_message_info_clear_recipients
        vscf_message_info_clear_recipients.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_clear_recipients.restype = None
        return vscf_message_info_clear_recipients(ctx)

    def vscf_message_info_shallow_copy(self, ctx):
        vscf_message_info_shallow_copy = self._lib.vscf_message_info_shallow_copy
        vscf_message_info_shallow_copy.argtypes = [POINTER(vscf_message_info_t)]
        vscf_message_info_shallow_copy.restype = POINTER(vscf_message_info_t)
        return vscf_message_info_shallow_copy(ctx)
