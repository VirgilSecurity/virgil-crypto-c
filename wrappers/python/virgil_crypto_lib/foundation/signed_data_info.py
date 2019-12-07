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
from ._c_bridge import VscfSignedDataInfo
from ._c_bridge import VscfImplTag


class SignedDataInfo(object):
    """Handle meta information about signed data."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_signed_data_info = VscfSignedDataInfo()
        self.ctx = self._lib_vscf_signed_data_info.vscf_signed_data_info_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_signed_data_info.vscf_signed_data_info_delete(self.ctx)

    def hash_alg_info(self):
        """Return information about algorithm that was used to produce data digest."""
        result = self._lib_vscf_signed_data_info.vscf_signed_data_info_hash_alg_info(self.ctx)
        instance = VscfImplTag.get_type(result)[0].use_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_signed_data_info = VscfSignedDataInfo()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_signed_data_info = VscfSignedDataInfo()
        inst.ctx = inst._lib_vscf_signed_data_info.vscf_signed_data_info_shallow_copy(c_ctx)
        return inst
