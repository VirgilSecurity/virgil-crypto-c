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
from ._c_bridge import VscfAlgFactory
from ._c_bridge import VscfImplTag


class AlgFactory(object):
    """Create algorithms based on the given information."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_alg_factory = VscfAlgFactory()

    def create_hash_from_info(self, alg_info):
        """Create algorithm that implements "hash stream" interface."""
        result = self._lib_vscf_alg_factory.vscf_alg_factory_create_hash_from_info(alg_info.c_impl)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def create_mac_from_info(self, alg_info):
        """Create algorithm that implements "mac stream" interface."""
        result = self._lib_vscf_alg_factory.vscf_alg_factory_create_mac_from_info(alg_info.c_impl)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def create_kdf_from_info(self, alg_info):
        """Create algorithm that implements "kdf" interface."""
        result = self._lib_vscf_alg_factory.vscf_alg_factory_create_kdf_from_info(alg_info.c_impl)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def create_salted_kdf_from_info(self, alg_info):
        """Create algorithm that implements "salted kdf" interface."""
        result = self._lib_vscf_alg_factory.vscf_alg_factory_create_salted_kdf_from_info(alg_info.c_impl)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def create_cipher_from_info(self, alg_info):
        """Create algorithm that implements "cipher" interface."""
        result = self._lib_vscf_alg_factory.vscf_alg_factory_create_cipher_from_info(alg_info.c_impl)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def create_padding_from_info(self, alg_info, random):
        """Create algorithm that implements "padding" interface."""
        result = self._lib_vscf_alg_factory.vscf_alg_factory_create_padding_from_info(alg_info.c_impl, random.c_impl)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance
