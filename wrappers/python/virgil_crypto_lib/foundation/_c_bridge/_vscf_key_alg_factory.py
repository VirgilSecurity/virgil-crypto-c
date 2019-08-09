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
from ._vscf_error import vscf_error_t
from ._vscf_raw_public_key import vscf_raw_public_key_t
from ._vscf_raw_private_key import vscf_raw_private_key_t


class VscfKeyAlgFactory(object):
    """Create a bridge between "raw keys" and algorithms that can import them."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_key_alg_factory_create_from_alg_id(self, alg_id, random, error):
        """Create a key algorithm based on an identifier."""
        vscf_key_alg_factory_create_from_alg_id = self._lib.vscf_key_alg_factory_create_from_alg_id
        vscf_key_alg_factory_create_from_alg_id.argtypes = [c_int, POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_key_alg_factory_create_from_alg_id.restype = POINTER(vscf_impl_t)
        return vscf_key_alg_factory_create_from_alg_id(alg_id, random, error)

    def vscf_key_alg_factory_create_from_key(self, key, random, error):
        """Create a key algorithm correspond to a specific key."""
        vscf_key_alg_factory_create_from_key = self._lib.vscf_key_alg_factory_create_from_key
        vscf_key_alg_factory_create_from_key.argtypes = [POINTER(vscf_impl_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_key_alg_factory_create_from_key.restype = POINTER(vscf_impl_t)
        return vscf_key_alg_factory_create_from_key(key, random, error)

    def vscf_key_alg_factory_create_from_raw_public_key(self, public_key, random, error):
        """Create a key algorithm that can import "raw public key"."""
        vscf_key_alg_factory_create_from_raw_public_key = self._lib.vscf_key_alg_factory_create_from_raw_public_key
        vscf_key_alg_factory_create_from_raw_public_key.argtypes = [POINTER(vscf_raw_public_key_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_key_alg_factory_create_from_raw_public_key.restype = POINTER(vscf_impl_t)
        return vscf_key_alg_factory_create_from_raw_public_key(public_key, random, error)

    def vscf_key_alg_factory_create_from_raw_private_key(self, private_key, random, error):
        """Create a key algorithm that can import "raw private key"."""
        vscf_key_alg_factory_create_from_raw_private_key = self._lib.vscf_key_alg_factory_create_from_raw_private_key
        vscf_key_alg_factory_create_from_raw_private_key.argtypes = [POINTER(vscf_raw_private_key_t), POINTER(vscf_impl_t), POINTER(vscf_error_t)]
        vscf_key_alg_factory_create_from_raw_private_key.restype = POINTER(vscf_impl_t)
        return vscf_key_alg_factory_create_from_raw_private_key(private_key, random, error)
