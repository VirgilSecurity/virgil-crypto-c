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
from ._c_bridge import VscfKeyAlgFactory
from ._c_bridge._vscf_error import vscf_error_t
from ._c_bridge import VscfImplTag
from ._c_bridge import VscfStatus


class KeyAlgFactory(object):
    """Create a bridge between "raw keys" and algorithms that can import them."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_key_alg_factory = VscfKeyAlgFactory()

    def create_from_alg_id(self, alg_id, random):
        """Create a key algorithm based on an identifier."""
        error = vscf_error_t()
        result = self._lib_vscf_key_alg_factory.vscf_key_alg_factory_create_from_alg_id(alg_id, random.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def create_from_key(self, key, random):
        """Create a key algorithm correspond to a specific key."""
        error = vscf_error_t()
        result = self._lib_vscf_key_alg_factory.vscf_key_alg_factory_create_from_key(key.c_impl, random.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def create_from_raw_public_key(self, public_key, random):
        """Create a key algorithm that can import "raw public key"."""
        error = vscf_error_t()
        result = self._lib_vscf_key_alg_factory.vscf_key_alg_factory_create_from_raw_public_key(public_key.ctx, random.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance

    def create_from_raw_private_key(self, private_key, random):
        """Create a key algorithm that can import "raw private key"."""
        error = vscf_error_t()
        result = self._lib_vscf_key_alg_factory.vscf_key_alg_factory_create_from_raw_private_key(private_key.ctx, random.c_impl, error)
        VscfStatus.handle_status(error.status)
        instance = VscfImplTag.get_type(result)[0].take_c_ctx(cast(result, POINTER(VscfImplTag.get_type(result)[1])))
        return instance
