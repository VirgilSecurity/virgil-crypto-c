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
from ._c_bridge import VscfEccAlgInfo
from .alg_info import AlgInfo


class EccAlgInfo(AlgInfo):
    """Handle algorithm information about ECP."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_ecc_alg_info = VscfEccAlgInfo()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_ecc_alg_info.vscf_ecc_alg_info_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_ecc_alg_info.vscf_ecc_alg_info_delete(self.ctx)

    @classmethod
    def with_members(cls, alg_id, key_id, domain_id):
        """Create algorithm info with EC generic key identificator, EC domain group identificator."""
        inst = cls.__new__(cls)
        inst._lib_vscf_ecc_alg_info = VscfEccAlgInfo()
        inst.ctx = inst._lib_vscf_ecc_alg_info.vscf_ecc_alg_info_new_with_members(alg_id, key_id, domain_id)
        return inst

    def alg_id(self):
        """Provide algorithm identificator."""
        result = self._lib_vscf_ecc_alg_info.vscf_ecc_alg_info_alg_id(self.ctx)
        return result

    def key_id(self):
        """Return EC specific algorithm identificator {unrestricted, ecDH, ecMQV}."""
        result = self._lib_vscf_ecc_alg_info.vscf_ecc_alg_info_key_id(self.ctx)
        return result

    def domain_id(self):
        """Return EC domain group identificator."""
        result = self._lib_vscf_ecc_alg_info.vscf_ecc_alg_info_domain_id(self.ctx)
        return result

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_ecc_alg_info = VscfEccAlgInfo()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_ecc_alg_info = VscfEccAlgInfo()
        inst.ctx = inst._lib_vscf_ecc_alg_info.vscf_ecc_alg_info_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_ecc_alg_info.vscf_ecc_alg_info_shallow_copy(value)
        self._c_impl = self._lib_vscf_ecc_alg_info.vscf_ecc_alg_info_impl(self.ctx)
