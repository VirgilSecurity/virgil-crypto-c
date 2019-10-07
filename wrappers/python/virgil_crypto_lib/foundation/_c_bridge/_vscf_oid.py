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
from virgil_crypto_lib.common._c_bridge import vsc_data_t


class VscfOid(object):
    """Provide conversion logic between OID and algorithm tags."""

    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_oid_from_alg_id(self, alg_id):
        """Return OID for given algorithm identifier."""
        vscf_oid_from_alg_id = self._lib.vscf_oid_from_alg_id
        vscf_oid_from_alg_id.argtypes = [c_int]
        vscf_oid_from_alg_id.restype = vsc_data_t
        return vscf_oid_from_alg_id(alg_id)

    def vscf_oid_to_alg_id(self, oid):
        """Return algorithm identifier for given OID."""
        vscf_oid_to_alg_id = self._lib.vscf_oid_to_alg_id
        vscf_oid_to_alg_id.argtypes = [vsc_data_t]
        vscf_oid_to_alg_id.restype = c_int
        return vscf_oid_to_alg_id(oid)

    def vscf_oid_from_id(self, oid_id):
        """Return OID for a given identifier."""
        vscf_oid_from_id = self._lib.vscf_oid_from_id
        vscf_oid_from_id.argtypes = [c_int]
        vscf_oid_from_id.restype = vsc_data_t
        return vscf_oid_from_id(oid_id)

    def vscf_oid_to_id(self, oid):
        """Return identifier for a given OID."""
        vscf_oid_to_id = self._lib.vscf_oid_to_id
        vscf_oid_to_id.argtypes = [vsc_data_t]
        vscf_oid_to_id.restype = c_int
        return vscf_oid_to_id(oid)

    def vscf_oid_id_to_alg_id(self, oid_id):
        """Map oid identifier to the algorithm identifier."""
        vscf_oid_id_to_alg_id = self._lib.vscf_oid_id_to_alg_id
        vscf_oid_id_to_alg_id.argtypes = [c_int]
        vscf_oid_id_to_alg_id.restype = c_int
        return vscf_oid_id_to_alg_id(oid_id)

    def vscf_oid_equal(self, lhs, rhs):
        """Return true if given OIDs are equal."""
        vscf_oid_equal = self._lib.vscf_oid_equal
        vscf_oid_equal.argtypes = [vsc_data_t, vsc_data_t]
        vscf_oid_equal.restype = c_bool
        return vscf_oid_equal(lhs, rhs)
