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


from ctypes import *
from ._c_bridge import VscfAlgInfoDerSerializer
from virgil_crypto_lib.common._c_bridge import Buffer
from .alg_info_serializer import AlgInfoSerializer


class AlgInfoDerSerializer(AlgInfoSerializer):
    """Provide DER serializer of algorithm information."""

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_alg_info_der_serializer = VscfAlgInfoDerSerializer()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_delete(self.ctx)

    def set_asn1_writer(self, asn1_writer):
        self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_use_asn1_writer(self.ctx, asn1_writer.c_impl)

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_setup_defaults(self.ctx)

    def is_alg_require_null_params(self, alg_id):
        """Return true if algorithm identifier requires that optional
parameter will be NULL."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_is_alg_require_null_params(alg_id)
        return result

    def serialized_simple_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
AlgorithmIdentifier with no parameters."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_simple_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_simple_alg_info(self, alg_info):
        """Serialize class "simple alg info" to the ASN.1 structure
AlgorithmIdentifier with no parameters."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_simple_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialized_kdf_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
"KeyDerivationFunction" from the ISO/IEC 18033-2."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_kdf_alg_info(self, alg_info):
        """Serialize class "hash based alg info" to the ASN.1 structure
"KeyDerivationFunction" from the ISO/IEC 18033-2."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_kdf_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialized_hkdf_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
"KeyDevAlgs" from the https://tools.ietf.org/html/draft-housley-hkdf-oids-00."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_hkdf_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_hkdf_alg_info(self, alg_info):
        """Serialize class "hash based alg info" to the ASN.1 structure
"KeyDevAlgs" from the https://tools.ietf.org/html/draft-housley-hkdf-oids-00."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_hkdf_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialized_hmac_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
"DigestAlgorithm" from the RFC 4231."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_hmac_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_hmac_alg_info(self, alg_info):
        """Serialize class "hash based alg info" to the ASN.1 structure
"DigestAlgorithm" from the RFC 4231."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_hmac_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialized_cipher_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
"AlgorithmIdentifier" with AES parameters:
    - defined in the RFC 3565;
    - defined in the RFC 5084."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_cipher_alg_info(self, alg_info):
        """Serialize class "cipher alg info" to the ASN.1 structure
"AlgorithmIdentifier" with AES parameters defined in the RFC 5084."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_cipher_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialized_pbkdf2_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
"PBKDF2Algorithm" from the RFC 8018."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_pbkdf2_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_pbkdf2_alg_info(self, alg_info):
        """Serialize class "salted kdf alg info" to the ASN.1 structure
"PBKDF2Algorithm" from the RFC 8018."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_pbkdf2_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialized_pbes2_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
"PBESF2Algorithm" from the RFC 8018."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_pbes2_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_pbes2_alg_info(self, alg_info):
        """Serialize class "salted kdf alg info" to the ASN.1 structure
"PBES2Algorithm" from the RFC 8018."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_pbes2_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialized_ecc_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
"AlgorithmIdentifier" with "ECParameters" from the RFC 5480."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_ecc_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_ecc_alg_info(self, alg_info):
        """Serialize class "ecc alg info" to the ASN.1 structure
"AlgorithmIdentifier" with "ECParameters" from the RFC 5480."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_ecc_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialized_compound_key_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
"AlgorithmIdentifier" with "CompoundKeyParams" parameters.

CompoundKeyAlgorithms ALGORITHM ::= {
    { OID id-CompoundKey parameters CompoundKeyParams }
}

id-CompoundKey ::= { 1 3 6 1 4 1 54811 1 1 }

CompoundKeyParams ::= SEQUENCE {
    cipherAlgorithm AlgorithmIdentifier,
    signerAlgorithm AlgorithmIdentifier
}"""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_compound_key_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_compound_key_alg_info(self, alg_info):
        """Serialize class "compound key alg info" to the ASN.1 structure
"AlgorithmIdentifier" with "CompoundKeyParams" parameters.

CompoundKeyAlgorithms ALGORITHM ::= {
    { OID id-CompoundKey parameters CompoundKeyParams }
}

id-CompoundKey ::= { 1 3 6 1 4 1 54811 1 1 }

CompoundKeyParams ::= SEQUENCE {
    cipherAlgorithm AlgorithmIdentifier,
    signerAlgorithm AlgorithmIdentifier
}"""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_compound_key_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialized_hybrid_key_alg_info_len(self, alg_info):
        """Return buffer size enough to hold ASN.1 structure
"AlgorithmIdentifier" with "HybridKeyParams" parameters.

HybridKeyAlgorithms ALGORITHM ::= {
    { OID id-HybridKey parameters HybridKeyParams }
}

id-HybridKey ::= { 1 3 6 1 4 1 54811 1 2 }

HybridKeyParams ::= SEQUENCE {
    firstKeyAlgorithm AlgorithmIdentifier,
    secondKeyAlgorithm AlgorithmIdentifier
}"""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_hybrid_key_alg_info_len(self.ctx, alg_info.c_impl)
        return result

    def serialize_hybrid_key_alg_info(self, alg_info):
        """Serialize class "hybrid key alg info" to the ASN.1 structure
"AlgorithmIdentifier" with "HybridKeyParams" parameters.

HybridKeyAlgorithms ALGORITHM ::= {
    { OID id-HybridKey parameters HybridKeyParams }
}

id-HybridKey ::= { 1 3 6 1 4 1 54811 1 2 }

HybridKeyParams ::= SEQUENCE {
    firstKeyAlgorithm AlgorithmIdentifier,
    secondKeyAlgorithm AlgorithmIdentifier
}"""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_hybrid_key_alg_info(self.ctx, alg_info.c_impl)
        return result

    def serialize_inplace(self, alg_info):
        """Serialize by using internal ASN.1 writer.
Note, that caller code is responsible to reset ASN.1 writer with
an output buffer."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize_inplace(self.ctx, alg_info.c_impl)
        return result

    def serialized_len(self, alg_info):
        """Return buffer size enough to hold serialized algorithm."""
        result = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialized_len(self.ctx, alg_info.c_impl)
        return result

    def serialize(self, alg_info):
        """Serialize algorithm info to buffer class."""
        out = Buffer(self.serialized_len(alg_info=alg_info))
        self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_serialize(self.ctx, alg_info.c_impl, out.c_buffer)
        return out.get_bytes()

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_alg_info_der_serializer = VscfAlgInfoDerSerializer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_alg_info_der_serializer = VscfAlgInfoDerSerializer()
        inst.ctx = inst._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_shallow_copy(value)
        self._c_impl = self._lib_vscf_alg_info_der_serializer.vscf_alg_info_der_serializer_impl(self.ctx)
