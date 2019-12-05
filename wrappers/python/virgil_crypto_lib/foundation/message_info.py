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
from ._c_bridge import VscfMessageInfo
from ._c_bridge import VscfImplTag
from .key_recipient_info_list import KeyRecipientInfoList
from .password_recipient_info_list import PasswordRecipientInfoList
from .message_info_custom_params import MessageInfoCustomParams
from .footer_info import FooterInfo


class MessageInfo(object):
    """Handle information about an encrypted message and algorithms
    that was used for encryption."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_message_info = VscfMessageInfo()
        self.ctx = self._lib_vscf_message_info.vscf_message_info_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_message_info.vscf_message_info_delete(self.ctx)

    def data_encryption_alg_info(self):
        """Return information about algorithm that was used for the data encryption."""
        result = self._lib_vscf_message_info.vscf_message_info_data_encryption_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].use_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def key_recipient_info_list(self):
        """Return list with a "key recipient info" elements."""
        result = self._lib_vscf_message_info.vscf_message_info_key_recipient_info_list(self.ctx)
        instance = KeyRecipientInfoList.use_c_ctx(result)
        return instance

    def password_recipient_info_list(self):
        """Return list with a "password recipient info" elements."""
        result = self._lib_vscf_message_info.vscf_message_info_password_recipient_info_list(self.ctx)
        instance = PasswordRecipientInfoList.use_c_ctx(result)
        return instance

    def has_custom_params(self):
        """Return true if message info contains at least one custom param."""
        result = self._lib_vscf_message_info.vscf_message_info_has_custom_params(self.ctx)
        return result

    def custom_params(self):
        """Provide access to the custom params object.
        The returned object can be used to add custom params or read it.
        If custom params object was not set then new empty object is created."""
        result = self._lib_vscf_message_info.vscf_message_info_custom_params(self.ctx)
        instance = MessageInfoCustomParams.use_c_ctx(result)
        return instance

    def has_cipher_kdf_alg_info(self):
        """Return true if cipher kdf alg info exists."""
        result = self._lib_vscf_message_info.vscf_message_info_has_cipher_kdf_alg_info(self.ctx)
        return result

    def cipher_kdf_alg_info(self):
        """Return cipher kdf alg info."""
        result = self._lib_vscf_message_info.vscf_message_info_cipher_kdf_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].use_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def has_cipher_padding_alg_info(self):
        """Return true if cipher padding alg info exists."""
        result = self._lib_vscf_message_info.vscf_message_info_has_cipher_padding_alg_info(self.ctx)
        return result

    def cipher_padding_alg_info(self):
        """Return cipher padding alg info."""
        result = self._lib_vscf_message_info.vscf_message_info_cipher_padding_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].use_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def has_footer_info(self):
        """Return true if footer info exists."""
        result = self._lib_vscf_message_info.vscf_message_info_has_footer_info(self.ctx)
        return result

    def footer_info(self):
        """Return footer info."""
        result = self._lib_vscf_message_info.vscf_message_info_footer_info(self.ctx)
        instance = FooterInfo.use_c_ctx(result)
        return instance

    def clear(self):
        """Remove all infos."""
        self._lib_vscf_message_info.vscf_message_info_clear(self.ctx)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info = VscfMessageInfo()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info = VscfMessageInfo()
        inst.ctx = inst._lib_vscf_message_info.vscf_message_info_shallow_copy(c_ctx)
        return inst
