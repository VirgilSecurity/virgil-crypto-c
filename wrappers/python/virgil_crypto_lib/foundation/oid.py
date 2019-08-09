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
from ._c_bridge import VscfOid
from virgil_crypto_lib.common._c_bridge import Data


class Oid(object):
    """Provide conversion logic between OID and algorithm tags."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_oid = VscfOid()

    def __eq__(self, lhs, rhs):
        """Return true if given OIDs are equal."""
        result = self._lib_vscf_oid.vscf_oid_equal(lhs, rhs)
        return result

    def from_alg_id(self, alg_id):
        """Return OID for given algorithm identifier."""
        result = self._lib_vscf_oid.vscf_oid_from_alg_id(alg_id)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def from_id(self, oid_id):
        """Return OID for a given identifier."""
        result = self._lib_vscf_oid.vscf_oid_from_id(oid_id)
        instance = Data.take_c_ctx(result)
        cleaned_bytes = bytearray(instance)
        return cleaned_bytes

    def to_id(self, oid):
        """Return identifier for a given OID."""
        d_oid = Data(oid)
        result = self._lib_vscf_oid.vscf_oid_to_id(d_oid.data)
        return result

    def id_to_alg_id(self, oid_id):
        """Map oid identifier to the algorithm identifier."""
        result = self._lib_vscf_oid.vscf_oid_id_to_alg_id(oid_id)
        return result

    def to_alg_id(self, oid):
        """Return algorithm identifier for given OID."""
        d_oid = Data(oid)
        result = self._lib_vscf_oid.vscf_oid_to_alg_id(d_oid.data)
        return result
