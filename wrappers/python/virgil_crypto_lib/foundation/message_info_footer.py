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
from ._c_bridge import VscfMessageInfoFooter
from .signer_info_list import SignerInfoList
from ._c_bridge import VscfImplTag
from virgil_crypto_lib.common._c_bridge import Data


class MessageInfoFooter(object):
    """Handle message signatures and related information."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_message_info_footer = VscfMessageInfoFooter()
        self.ctx = self._lib_vscf_message_info_footer.vscf_message_info_footer_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_message_info_footer.vscf_message_info_footer_delete(self.ctx)

    def has_signer_infos(self):
        """Return true if at least one signer info presents."""
        result = self._lib_vscf_message_info_footer.vscf_message_info_footer_has_signer_infos(self.ctx)
        return result

    def signer_infos(self):
        """Return list with a "signer info" elements."""
        result = self._lib_vscf_message_info_footer.vscf_message_info_footer_signer_infos(self.ctx)
        instance = SignerInfoList.use_c_ctx(result)
        return instance

    def signer_hash_alg_info(self):
        """Return information about algorithm that was used for data hashing."""
        result = self._lib_vscf_message_info_footer.vscf_message_info_footer_signer_hash_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].use_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def signer_digest(self):
        """Return plain text digest that was used to produce signature."""
        result = self._lib_vscf_message_info_footer.vscf_message_info_footer_signer_digest(self.ctx)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_footer = VscfMessageInfoFooter()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_footer = VscfMessageInfoFooter()
        inst.ctx = inst._lib_vscf_message_info_footer.vscf_message_info_footer_shallow_copy(c_ctx)
        return inst
