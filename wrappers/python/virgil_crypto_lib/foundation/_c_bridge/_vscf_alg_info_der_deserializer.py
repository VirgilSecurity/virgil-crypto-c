# Copyright (C) 2015-2022 Virgil Security, Inc.
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
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from ._vscf_error import vscf_error_t


class vscf_alg_info_der_deserializer_t(Structure):
    pass


class VscfAlgInfoDerDeserializer(object):
    """Provide DER deserializer of algorithm information."""


    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_alg_info_der_deserializer_new(self):
        vscf_alg_info_der_deserializer_new = self._lib.vscf_alg_info_der_deserializer_new
        vscf_alg_info_der_deserializer_new.argtypes = []
        vscf_alg_info_der_deserializer_new.restype = POINTER(vscf_alg_info_der_deserializer_t)
        return vscf_alg_info_der_deserializer_new()

    def vscf_alg_info_der_deserializer_delete(self, ctx):
        vscf_alg_info_der_deserializer_delete = self._lib.vscf_alg_info_der_deserializer_delete
        vscf_alg_info_der_deserializer_delete.argtypes = [POINTER(vscf_alg_info_der_deserializer_t)]
        vscf_alg_info_der_deserializer_delete.restype = None
        return vscf_alg_info_der_deserializer_delete(ctx)

    def vscf_alg_info_der_deserializer_use_asn1_reader(self, ctx, asn1_reader):
        vscf_alg_info_der_deserializer_use_asn1_reader = self._lib.vscf_alg_info_der_deserializer_use_asn1_reader
        vscf_alg_info_der_deserializer_use_asn1_reader.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), POINTER(vscf_impl_t)]
        vscf_alg_info_der_deserializer_use_asn1_reader.restype = None
        return vscf_alg_info_der_deserializer_use_asn1_reader(ctx, asn1_reader)

    def vscf_alg_info_der_deserializer_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_alg_info_der_deserializer_setup_defaults = self._lib.vscf_alg_info_der_deserializer_setup_defaults
        vscf_alg_info_der_deserializer_setup_defaults.argtypes = [POINTER(vscf_alg_info_der_deserializer_t)]
        vscf_alg_info_der_deserializer_setup_defaults.restype = None
        return vscf_alg_info_der_deserializer_setup_defaults(ctx)

    def vscf_alg_info_der_deserializer_deserialize_simple_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "AlgorithmIdentifier" with optional NULL parameter."""
        vscf_alg_info_der_deserializer_deserialize_simple_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_simple_alg_info
        vscf_alg_info_der_deserializer_deserialize_simple_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_simple_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_simple_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "KeyDerivationFunction" from the ISO/IEC 18033-2."""
        vscf_alg_info_der_deserializer_deserialize_kdf_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_kdf_alg_info
        vscf_alg_info_der_deserializer_deserialize_kdf_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_kdf_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "KeyDevAlgs" from the
https://tools.ietf.org/html/draft-housley-hkdf-oids-00."""
        vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info
        vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "DigestAlgorithm" from the RFC 4231."""
        vscf_alg_info_der_deserializer_deserialize_hmac_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_hmac_alg_info
        vscf_alg_info_der_deserializer_deserialize_hmac_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_hmac_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "AlgorithmIdentifier" with AES parameters:
    - defined in the RFC 3565;
    - defined in the RFC 5084."""
        vscf_alg_info_der_deserializer_deserialize_cipher_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_cipher_alg_info
        vscf_alg_info_der_deserializer_deserialize_cipher_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_cipher_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "AlgorithmIdentifier" with PBKDF2 parameters
defined in the RFC 8018."""
        vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info
        vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "AlgorithmIdentifier" with PBES2 parameters
defined in the RFC 8018."""
        vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info
        vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_ecc_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "AlgorithmIdentifier" with ECParameters
parameters defined in the RFC 5480."""
        vscf_alg_info_der_deserializer_deserialize_ecc_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_ecc_alg_info
        vscf_alg_info_der_deserializer_deserialize_ecc_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_ecc_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_ecc_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_compound_key_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "AlgorithmIdentifier" with
"CompoundKeyParams" parameters.

CompoundKeyAlgorithms ALGORITHM ::= {
    { OID id-CompoundKey parameters CompoundKeyParams }
}

id-CompoundKey ::= { 1 3 6 1 4 1 54811 1 1 }

CompoundKeyParams ::= SEQUENCE {
    cipherAlgorithm AlgorithmIdentifier,
    signerAlgorithm AlgorithmIdentifier
}"""
        vscf_alg_info_der_deserializer_deserialize_compound_key_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_compound_key_alg_info
        vscf_alg_info_der_deserializer_deserialize_compound_key_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_compound_key_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_compound_key_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_hybrid_key_alg_info(self, ctx, oid_id, error):
        """Parse ASN.1 structure "AlgorithmIdentifier" with
"HybridKeyParams" parameters.

HybridKeyAlgorithms ALGORITHM ::= {
    { OID id-HybridKey parameters HybridKeyParams }
}

id-HybridKey ::= { 1 3 6 1 4 1 54811 1 2 }

HybridKeyParams ::= SEQUENCE {
    firstKeyAlgorithm AlgorithmIdentifier,
    secondKeyAlgorithm AlgorithmIdentifier
}"""
        vscf_alg_info_der_deserializer_deserialize_hybrid_key_alg_info = self._lib.vscf_alg_info_der_deserializer_deserialize_hybrid_key_alg_info
        vscf_alg_info_der_deserializer_deserialize_hybrid_key_alg_info.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), c_int, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_hybrid_key_alg_info.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_hybrid_key_alg_info(ctx, oid_id, error)

    def vscf_alg_info_der_deserializer_deserialize_inplace(self, ctx, error):
        """Deserialize by using internal ASN.1 reader.
Note, that caller code is responsible to reset ASN.1 reader with
an input buffer."""
        vscf_alg_info_der_deserializer_deserialize_inplace = self._lib.vscf_alg_info_der_deserializer_deserialize_inplace
        vscf_alg_info_der_deserializer_deserialize_inplace.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize_inplace.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize_inplace(ctx, error)

    def vscf_alg_info_der_deserializer_deserialize(self, ctx, data, error):
        """Deserialize algorithm from the data."""
        vscf_alg_info_der_deserializer_deserialize = self._lib.vscf_alg_info_der_deserializer_deserialize
        vscf_alg_info_der_deserializer_deserialize.argtypes = [POINTER(vscf_alg_info_der_deserializer_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_alg_info_der_deserializer_deserialize.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_deserialize(ctx, data, error)

    def vscf_alg_info_der_deserializer_shallow_copy(self, ctx):
        vscf_alg_info_der_deserializer_shallow_copy = self._lib.vscf_alg_info_der_deserializer_shallow_copy
        vscf_alg_info_der_deserializer_shallow_copy.argtypes = [POINTER(vscf_alg_info_der_deserializer_t)]
        vscf_alg_info_der_deserializer_shallow_copy.restype = POINTER(vscf_alg_info_der_deserializer_t)
        return vscf_alg_info_der_deserializer_shallow_copy(ctx)

    def vscf_alg_info_der_deserializer_impl(self, ctx):
        vscf_alg_info_der_deserializer_impl = self._lib.vscf_alg_info_der_deserializer_impl
        vscf_alg_info_der_deserializer_impl.argtypes = [POINTER(vscf_alg_info_der_deserializer_t)]
        vscf_alg_info_der_deserializer_impl.restype = POINTER(vscf_impl_t)
        return vscf_alg_info_der_deserializer_impl(ctx)
