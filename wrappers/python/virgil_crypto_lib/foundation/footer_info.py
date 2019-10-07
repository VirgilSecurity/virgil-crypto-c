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
from ._c_bridge import VscfFooterInfo
from .signed_data_info import SignedDataInfo


class FooterInfo(object):
    """Handle meta information about footer."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_footer_info = VscfFooterInfo()
        self.ctx = self._lib_vscf_footer_info.vscf_footer_info_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_footer_info.vscf_footer_info_delete(self.ctx)

    def has_signed_data_info(self):
        """Retrun true if signed data info present."""
        result = self._lib_vscf_footer_info.vscf_footer_info_has_signed_data_info(self.ctx)
        return result

    def signed_data_info(self):
        """Return signed data info."""
        result = self._lib_vscf_footer_info.vscf_footer_info_signed_data_info(self.ctx)
        instance = SignedDataInfo.use_c_ctx(result)
        return instance

    def set_data_size(self, data_size):
        """Set data size."""
        self._lib_vscf_footer_info.vscf_footer_info_set_data_size(self.ctx, data_size)

    def data_size(self):
        """Return data size."""
        result = self._lib_vscf_footer_info.vscf_footer_info_data_size(self.ctx)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_footer_info = VscfFooterInfo()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_footer_info = VscfFooterInfo()
        inst.ctx = inst._lib_vscf_footer_info.vscf_footer_info_shallow_copy(c_ctx)
        return inst
