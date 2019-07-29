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
from ._c_bridge import VscfKeyRecipientInfo
from virgil_crypto_lib.common._c_bridge import Data
from ._c_bridge import VscfImplTag


class KeyRecipientInfo(object):
    """Handle information about recipient that is defined by a Public Key."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_key_recipient_info = VscfKeyRecipientInfo()
        self.ctx = self._lib_vscf_key_recipient_info.vscf_key_recipient_info_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_key_recipient_info.vscf_key_recipient_info_delete(self.ctx)

    @classmethod
    def with_data(cls, recipient_id, key_encryption_algorithm, encrypted_key):
        """Create object and define all properties."""
        d_recipient_id = Data(recipient_id)
        d_encrypted_key = Data(encrypted_key)
        inst = cls.__new__(cls)
        inst._lib_vscf_key_recipient_info = VscfKeyRecipientInfo()
        inst.ctx = inst._lib_vscf_key_recipient_info.vscf_key_recipient_info_new_with_data(d_recipient_id.data, key_encryption_algorithm.c_impl, d_encrypted_key.data)
        return inst

    def recipient_id(self):
        """Return recipient identifier."""
        result = self._lib_vscf_key_recipient_info.vscf_key_recipient_info_recipient_id(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def key_encryption_algorithm(self):
        """Return algorithm information that was used for encryption
        a data encryption key."""
        result = self._lib_vscf_key_recipient_info.vscf_key_recipient_info_key_encryption_algorithm(self.ctx)
        instance = VscfImplTag.get_type(result)[0].use_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def encrypted_key(self):
        """Return an encrypted data encryption key."""
        result = self._lib_vscf_key_recipient_info.vscf_key_recipient_info_encrypted_key(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_recipient_info = VscfKeyRecipientInfo()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_key_recipient_info = VscfKeyRecipientInfo()
        inst.ctx = inst._lib_vscf_key_recipient_info.vscf_key_recipient_info_shallow_copy(c_ctx)
        return inst
