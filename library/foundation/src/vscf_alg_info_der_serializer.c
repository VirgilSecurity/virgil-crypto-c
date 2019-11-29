//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  This module contains 'alg info der serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_alg_info_der_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg_info.h"
#include "vscf_asn1_tag.h"
#include "vscf_asn1wr.h"
#include "vscf_oid.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_salted_kdf_alg_info.h"
#include "vscf_pbe_alg_info.h"
#include "vscf_ecc_alg_info.h"
#include "vscf_compound_key_alg_info.h"
#include "vscf_chained_key_alg_info.h"
#include "vscf_asn1_writer.h"
#include "vscf_alg_info_der_serializer_defs.h"
#include "vscf_alg_info_der_serializer_internal.h"
#include "vscf_alg_id.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return true if algorithm identifier requires that optional
//  parameter will be NULL.
//
static bool
vscf_alg_info_der_serializer_is_alg_require_null_params(vscf_alg_id_t alg_id);

//
//  Return buffer size enough to hold ASN.1 structure
//  AlgorithmIdentifier with no parameters.
//
static size_t
vscf_alg_info_der_serializer_serialized_simple_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "simple alg info" to the ASN.1 structure
//  AlgorithmIdentifier with no parameters.
//
static size_t
vscf_alg_info_der_serializer_serialize_simple_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Return buffer size enough to hold ASN.1 structure
//  "KeyDerivationFunction" from the ISO/IEC 18033-2.
//
static size_t
vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "hash based alg info" to the ASN.1 structure
//  "KeyDerivationFunction" from the ISO/IEC 18033-2.
//
static size_t
vscf_alg_info_der_serializer_serialize_kdf_alg_info(vscf_alg_info_der_serializer_t *self, const vscf_impl_t *alg_info);

//
//  Return buffer size enough to hold ASN.1 structure
//  "KeyDevAlgs" from the https://tools.ietf.org/html/draft-housley-hkdf-oids-00.
//
static size_t
vscf_alg_info_der_serializer_serialized_hkdf_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "hash based alg info" to the ASN.1 structure
//  "KeyDevAlgs" from the https://tools.ietf.org/html/draft-housley-hkdf-oids-00.
//
static size_t
vscf_alg_info_der_serializer_serialize_hkdf_alg_info(vscf_alg_info_der_serializer_t *self, const vscf_impl_t *alg_info);

//
//  Return buffer size enough to hold ASN.1 structure
//  "DigestAlgorithm" from the RFC 4231.
//
static size_t
vscf_alg_info_der_serializer_serialized_hmac_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "hash based alg info" to the ASN.1 structure
//  "DigestAlgorithm" from the RFC 4231.
//
static size_t
vscf_alg_info_der_serializer_serialize_hmac_alg_info(vscf_alg_info_der_serializer_t *self, const vscf_impl_t *alg_info);

//
//  Return buffer size enough to hold ASN.1 structure
//  "AlgorithmIdentifier" with AES parameters:
//      - defined in the RFC 3565;
//      - defined in the RFC 5084.
//
static size_t
vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "cipher alg info" to the ASN.1 structure
//  "AlgorithmIdentifier" with AES parameters defined in the RFC 5084.
//
static size_t
vscf_alg_info_der_serializer_serialize_cipher_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Return buffer size enough to hold ASN.1 structure
//  "PBKDF2Algorithm" from the RFC 8018.
//
static size_t
vscf_alg_info_der_serializer_serialized_pbkdf2_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "salted kdf alg info" to the ASN.1 structure
//  "PBKDF2Algorithm" from the RFC 8018.
//
static size_t
vscf_alg_info_der_serializer_serialize_pbkdf2_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Return buffer size enough to hold ASN.1 structure
//  "PBESF2Algorithm" from the RFC 8018.
//
static size_t
vscf_alg_info_der_serializer_serialized_pbes2_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "salted kdf alg info" to the ASN.1 structure
//  "PBES2Algorithm" from the RFC 8018.
//
static size_t
vscf_alg_info_der_serializer_serialize_pbes2_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Return buffer size enough to hold ASN.1 structure
//  "AlgorithmIdentifier" with "ECParameters" from the RFC 5480.
//
static size_t
vscf_alg_info_der_serializer_serialized_ecc_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "ecc alg info" to the ASN.1 structure
//  "AlgorithmIdentifier" with "ECParameters" from the RFC 5480.
//
static size_t
vscf_alg_info_der_serializer_serialize_ecc_alg_info(vscf_alg_info_der_serializer_t *self, const vscf_impl_t *alg_info);

//
//  Return buffer size enough to hold ASN.1 structure
//  "AlgorithmIdentifier" with "CompoundKeyParams" parameters.
//
//  CompoundKeyAlgorithms ALGORITHM ::= {
//      { OID id-CompoundKey parameters CompoundKeyParams }
//  }
//
//  id-CompoundKey ::= { 1 3 6 1 4 1 54811 1 1 }
//
//  CompoundKeyParams ::= SEQUENCE {
//      cipherAlgorithm AlgorithmIdentifier
//      signerAlgorithm AlgorithmIdentifier
//      signerDigestAlgorithm AlgorithmIdentifier
//  }
//
static size_t
vscf_alg_info_der_serializer_serialized_compound_key_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "compound key alg info" to the ASN.1 structure
//  "AlgorithmIdentifier" with "CompoundKeyParams" parameters.
//
//  CompoundKeyAlgorithms ALGORITHM ::= {
//      { OID id-CompoundKey parameters CompoundKeyParams }
//  }
//
//  id-CompoundKey ::= { 1 3 6 1 4 1 54811 1 1 }
//
//  CompoundKeyParams ::= SEQUENCE {
//      cipherAlgorithm AlgorithmIdentifier
//      signerAlgorithm AlgorithmIdentifier
//      signerDigestAlgorithm AlgorithmIdentifier
//  }
//
static size_t
vscf_alg_info_der_serializer_serialize_compound_key_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Return buffer size enough to hold ASN.1 structure
//  "AlgorithmIdentifier" with "ChainedKeyParams" parameters.
//
//  ChainedKeyAlgorithms ALGORITHM ::= {
//      { OID id-ChainedKey parameters ChainedKeyParams }
//  }
//
//  id-ChainedKey ::= { 1 3 6 1 4 1 54811 1 2 }
//
//  ChainedKeyParams ::= SEQUENCE {
//      l1CipherAlgorithm AlgorithmIdentifier,
//      l2CipherAlgorithm AlgorithmIdentifier
//  }
//
static size_t
vscf_alg_info_der_serializer_serialized_chained_key_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);

//
//  Serialize class "chained key alg info" to the ASN.1 structure
//  "AlgorithmIdentifier" with "ChainedKeyParams" parameters.
//
//  ChainedKeyAlgorithms ALGORITHM ::= {
//      { OID id-ChainedKey parameters ChainedKeyParams }
//  }
//
//  id-ChainedKey ::= { 1 3 6 1 4 1 54811 1 2 }
//
//  ChainedKeyParams ::= SEQUENCE {
//      l1CipherAlgorithm AlgorithmIdentifier,
//      l2CipherAlgorithm AlgorithmIdentifier
//  }
//
static size_t
vscf_alg_info_der_serializer_serialize_chained_key_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_alg_info_der_serializer_setup_defaults(vscf_alg_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->asn1_writer) {
        vscf_alg_info_der_serializer_take_asn1_writer(self, vscf_asn1wr_impl(vscf_asn1wr_new()));
    }
}

//
//  Return true if algorithm identifier requires that optional
//  parameter will be NULL.
//
static bool
vscf_alg_info_der_serializer_is_alg_require_null_params(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
    case vscf_alg_id_RSA:
        return true;

    case vscf_alg_id_SHA224:
    case vscf_alg_id_SHA256:
    case vscf_alg_id_SHA384:
    case vscf_alg_id_SHA512:
        //  According to RFC 5754 - Using SHA2 Algorithms with Cryptographic Message Syntax.
        //  Implementations MUST generate SHA2 AlgorithmIdentifiers with absent parameters.
        //  But to preserve forward compatibility this BUG is still here.
        //  BUG: Fix this when Virgil Crypto V2 support will end up.
        return true;
    default:
        return false;
    }
}

//
//  Return buffer size enough to hold ASN.1 structure
//  AlgorithmIdentifier with no parameters.
//
static size_t
vscf_alg_info_der_serializer_serialized_simple_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);


    size_t len = 1 + 1 + //  AlgorithmIdentifier ::= SEQUENCE {
                 1 + 1 + 32 + //          algorithm OBJECT IDENTIFIER,
                 2; //          parameters ANY DEFINED BY algorithm OPTIONAL
                              //  }

    return len;
}

//
//  Serialize class "simple alg info" to the ASN.1 structure
//  AlgorithmIdentifier with no parameters.
//
static size_t
vscf_alg_info_der_serializer_serialize_simple_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    //  AlgorithmIdentifier ::= SEQUENCE {
    //          algorithm OBJECT IDENTIFIER,
    //          parameters ANY DEFINED BY algorithm OPTIONAL
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_impl_t *asn1_writer = self->asn1_writer;

    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_simple_alg_info_len(self, alg_info));

    const vscf_simple_alg_info_t *simple_alg_info = (const vscf_simple_alg_info_t *)alg_info;
    vscf_alg_id_t alg_id = vscf_simple_alg_info_alg_id(simple_alg_info);
    vsc_data_t oid = vscf_oid_from_alg_id(alg_id);

    size_t hash_len = 0;
    if (vscf_alg_info_der_serializer_is_alg_require_null_params(alg_id)) {
        hash_len += vscf_asn1_writer_write_null(asn1_writer);
    }
    hash_len += vscf_asn1_writer_write_oid(asn1_writer, oid);
    hash_len += vscf_asn1_writer_write_sequence(asn1_writer, hash_len);

    VSCF_ASSERT(!vscf_asn1_writer_has_error(asn1_writer));

    return hash_len;
}

//
//  Return buffer size enough to hold ASN.1 structure
//  "KeyDerivationFunction" from the ISO/IEC 18033-2.
//
static size_t
vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;
    size_t params_len = vscf_alg_info_der_serializer_serialized_simple_alg_info_len(
            self, vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info));

    size_t len = //  -- From ISO/IEC 18033-2 --
            1 + 1 + //  KDFAlgorithms ALGORITHM ::= {
            1 + 1 + 32 + params_len; //          { OID id-kdf-kdf1 PARMS HashFunction } |
                                     //          { OID id-kdf-kdf2 PARMS HashFunction } ,
                                     //          ... -- Expect additional algorithms --
                                     //  }
    return len;
}

//
//  Serialize class "hash based alg info" to the ASN.1 structure
//  "KeyDerivationFunction" from the ISO/IEC 18033-2.
//
static size_t
vscf_alg_info_der_serializer_serialize_kdf_alg_info(vscf_alg_info_der_serializer_t *self, const vscf_impl_t *alg_info) {

    //  -- From ISO/IEC 18033-2 --
    //  KeyDerivationFunction ::= AlgorithmIdentifier {{ KDFAlgorithms }}
    //  KDFAlgorithms ALGORITHM ::= {
    //          { OID id-kdf-kdf1 PARMS HashFunction } |
    //          { OID id-kdf-kdf2 PARMS HashFunction } ,
    //          ... -- Expect additional algorithms --
    //  }
    //
    //  HashFunction ::= AlgorithmIdentifier {{ HashAlgorithms }}
    //  HashAlgorithms ALGORITHM ::= {
    //          -- nist identifiers
    //          { OID id-sha1 } |
    //          { OID id-sha256 } |
    //          { OID id-sha384 } |
    //          { OID id-sha512 } ,
    //          ... -- Expect additional algorithms --
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_impl_t *asn1_writer = self->asn1_writer;

    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(self, alg_info));

    const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

    //  Write HashFunction.
    size_t params_len = vscf_alg_info_der_serializer_serialize_simple_alg_info(
            self, vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info));

    //  Write KeyDerivationFunction.
    vsc_data_t kdf_oid = vscf_oid_from_alg_id(vscf_hash_based_alg_info_alg_id(hash_based_alg_info));

    size_t kdf_len = 0;
    kdf_len += vscf_asn1_writer_write_oid(asn1_writer, kdf_oid);
    kdf_len += vscf_asn1_writer_write_sequence(asn1_writer, kdf_len + params_len);

    VSCF_ASSERT(!vscf_asn1_writer_has_error(asn1_writer));

    return kdf_len + params_len;
}

//
//  Return buffer size enough to hold ASN.1 structure
//  "KeyDevAlgs" from the https://tools.ietf.org/html/draft-housley-hkdf-oids-00.
//
static size_t
vscf_alg_info_der_serializer_serialized_hkdf_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    size_t len = 1 + 1 + 16; //  KdfAlgorithm KEY-DERIVATION ::= { OID PARAMS ARE absent }
    return len;
}

//
//  Serialize class "hash based alg info" to the ASN.1 structure
//  "KeyDevAlgs" from the https://tools.ietf.org/html/draft-housley-hkdf-oids-00.
//
static size_t
vscf_alg_info_der_serializer_serialize_hkdf_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_impl_t *asn1_writer = self->asn1_writer;

    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_hkdf_alg_info_len(self, alg_info));

    const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

    vscf_alg_id_t hash_alg_id = vscf_alg_info_alg_id(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info));
    vscf_oid_id_t hkdf_oid_id = vscf_oid_id_NONE;

    switch (hash_alg_id) {
    case vscf_alg_id_SHA256:
        hkdf_oid_id = vscf_oid_id_HKDF_WITH_SHA256;
        break;

    case vscf_alg_id_SHA384:
        hkdf_oid_id = vscf_oid_id_HKDF_WITH_SHA384;
        break;

    case vscf_alg_id_SHA512:
        hkdf_oid_id = vscf_oid_id_HKDF_WITH_SHA512;
        break;

    default:
        VSCF_ASSERT("Unexpected algorithm id.");
        break;
    }

    size_t hkdf_len = 0;
    hkdf_len += vscf_asn1_writer_write_oid(asn1_writer, vscf_oid_from_id(hkdf_oid_id));
    hkdf_len += vscf_asn1_writer_write_sequence(asn1_writer, hkdf_len);

    VSCF_ASSERT(!vscf_asn1_writer_has_error(asn1_writer));

    return hkdf_len;
}

//
//  Return buffer size enough to hold ASN.1 structure
//  "DigestAlgorithm" from the RFC 4231.
//
static size_t
vscf_alg_info_der_serializer_serialized_hmac_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    size_t len = 1 + 1 + 16; //  DigestAlgorithm ALGORITHM ::= { OID PARAMS absent }
    return len;
}

//
//  Serialize class "hash based alg info" to the ASN.1 structure
//  "DigestAlgorithm" from the RFC 4231.
//
static size_t
vscf_alg_info_der_serializer_serialize_hmac_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_impl_t *asn1_writer = self->asn1_writer;

    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_hmac_alg_info_len(self, alg_info));

    const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

    vscf_alg_id_t hash_alg_id = vscf_alg_info_alg_id(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info));
    vscf_oid_id_t hmac_oid_id = vscf_oid_id_NONE;

    switch (hash_alg_id) {
    case vscf_alg_id_SHA224:
        hmac_oid_id = vscf_oid_id_HMAC_WITH_SHA224;
        break;

    case vscf_alg_id_SHA256:
        hmac_oid_id = vscf_oid_id_HMAC_WITH_SHA256;
        break;

    case vscf_alg_id_SHA384:
        hmac_oid_id = vscf_oid_id_HMAC_WITH_SHA384;
        break;

    case vscf_alg_id_SHA512:
        hmac_oid_id = vscf_oid_id_HMAC_WITH_SHA512;
        break;

    default:
        VSCF_ASSERT("Unexpected algorithm id.");
        break;
    }

    size_t hmac_len = 0;
    hmac_len += vscf_asn1_writer_write_null(asn1_writer); //  Reuired by the RFC 4231
    hmac_len += vscf_asn1_writer_write_oid(asn1_writer, vscf_oid_from_id(hmac_oid_id));
    hmac_len += vscf_asn1_writer_write_sequence(asn1_writer, hmac_len);

    VSCF_ASSERT(!vscf_asn1_writer_has_error(asn1_writer));

    return hmac_len;
}

//
//  Return buffer size enough to hold ASN.1 structure
//  "AlgorithmIdentifier" with AES parameters:
//      - defined in the RFC 3565;
//      - defined in the RFC 5084.
//
static size_t
vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    size_t len = //
            1 + 1 + //  SymmetricAlgorithms ALGORITHM ::= {
            1 + 1 + 32 + //          { OID id-aes256-GCM PARMS NONCE } ,
                         //          ... -- Expect additional algorithms --
                         //  }
                         //
            2 + 16; //  NONCE ::= OCTET STRING
    return len;
}

//
//  Serialize class "cipher alg info" to the ASN.1 structure
//  "AlgorithmIdentifier" with AES parameters defined in the RFC 5084.
//
static size_t
vscf_alg_info_der_serializer_serialize_cipher_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    //  SymmetricAlgorithms ALGORITHM ::= {
    //          { OID id-aes256-GCM parameters GCMParameters } ,
    //          ... -- Expect additional algorithms --
    //  }
    //
    //  GCMParameters ::= SEQUENCE {
    //          aes-nonce OCTET STRING, -- recommended size is 12 octets
    //          aes-ICVlen AES-GCM-ICVlen DEFAULT 12 }
    //
    //  AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_impl_t *asn1_writer = self->asn1_writer;

    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(self, alg_info));

    const vscf_cipher_alg_info_t *cipher_alg_info = (const vscf_cipher_alg_info_t *)alg_info;

    size_t len = 0;
    vscf_alg_id_t alg_id = vscf_cipher_alg_info_alg_id(cipher_alg_info);

    switch (alg_id) {
        //  According to RFC 5084 - GCMParameters is written as SEQUENCE.
        //  But to preserve forward compatibility with version V2 this BUG is still here.
        //  BUG: Uncomment next code when Virgil Crypto V2 support will end up.
        // case vscf_alg_id_AES256_GCM:
        //     //  Write GCMParameters.
        //     len += vscf_asn1_writer_write_int(asn1_writer, vscf_cipher_alg_info_nonce(cipher_alg_info).len);
        //     len += vscf_asn1_writer_write_octet_str(asn1_writer, vscf_cipher_alg_info_nonce(cipher_alg_info));
        //     len += vscf_asn1_writer_write_sequence(asn1_writer, len);
        //     break;

    default:
        //  Write NONCE only.
        len += vscf_asn1_writer_write_octet_str(asn1_writer, vscf_cipher_alg_info_nonce(cipher_alg_info));
        break;
    }

    //  Write OID.
    vsc_data_t cipher_oid = vscf_oid_from_alg_id(alg_id);
    len += vscf_asn1_writer_write_oid(asn1_writer, cipher_oid);

    //  Write AlgorithmIdentifier SEQUENCE.
    len += vscf_asn1_writer_write_sequence(asn1_writer, len);

    VSCF_ASSERT(!vscf_asn1_writer_has_error(asn1_writer));

    return len;
}

//
//  Return buffer size enough to hold ASN.1 structure
//  "PBKDF2Algorithm" from the RFC 8018.
//
static size_t
vscf_alg_info_der_serializer_serialized_pbkdf2_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    size_t params_len = 1 + 1 + //  PBKDF2-params ::= SEQUENCE {
                                     //      salt CHOICE {
                        1 + 1 + 64 + //          specified OCTET STRING,
                                     //          otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}} -- no used
                                     //      },
                        1 + 1 + 9 + //      iterationCount INTEGER (1..MAX),
                                     //      keyLength INTEGER (1..MAX) OPTIONAL, -- not used
                        1 + 1 + 16; //      prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1 }

    size_t len = 1 + 1 + //  AlgorithmIdentifier ::= SEQUENCE {
                 1 + 1 + 9 + //      algorithm OBJECT IDENTIFIER, -- id-PBKDF2
                 params_len; //      parameters PBKDF2-params }

    return len;
}

//
//  Serialize class "salted kdf alg info" to the ASN.1 structure
//  "PBKDF2Algorithm" from the RFC 8018.
//
static size_t
vscf_alg_info_der_serializer_serialize_pbkdf2_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    //  PBKDF2Algorithms ALGORITHM-IDENTIFIER ::= {
    //      {PBKDF2-params IDENTIFIED BY id-PBKDF2},
    //      ...
    //  }
    //
    //  PBKDF2-params ::= SEQUENCE {
    //      salt CHOICE {
    //          specified OCTET STRING,
    //          otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
    //      },
    //      iterationCount INTEGER (1..MAX),
    //      keyLength INTEGER (1..MAX) OPTIONAL,
    //      prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_impl_t *asn1_writer = self->asn1_writer;

    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_pbkdf2_alg_info_len(self, alg_info));


    const vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = (const vscf_salted_kdf_alg_info_t *)alg_info;

    size_t len = 0;
    vscf_alg_id_t alg_id = vscf_salted_kdf_alg_info_alg_id(salted_kdf_alg_info);

    switch (alg_id) {
    case vscf_alg_id_PKCS5_PBKDF2:
        //  Write PBKDF2-params.
        len += vscf_alg_info_der_serializer_serialize_inplace(
                self, vscf_salted_kdf_alg_info_hash_alg_info(salted_kdf_alg_info));

        len += vscf_asn1_writer_write_uint64(
                asn1_writer, vscf_salted_kdf_alg_info_iteration_count(salted_kdf_alg_info));
        len += vscf_asn1_writer_write_octet_str(asn1_writer, vscf_salted_kdf_alg_info_salt(salted_kdf_alg_info));
        len += vscf_asn1_writer_write_sequence(asn1_writer, len);
        break;

    default:
        VSCF_ASSERT(0 && "Unhandled alg id.");
        break;
    }

    //  Write OID.
    vsc_data_t cipher_oid = vscf_oid_from_alg_id(alg_id);
    len += vscf_asn1_writer_write_oid(asn1_writer, cipher_oid);

    //  Write AlgorithmIdentifier SEQUENCE.
    len += vscf_asn1_writer_write_sequence(asn1_writer, len);

    VSCF_ASSERT(!vscf_asn1_writer_has_error(asn1_writer));

    return len;
}

//
//  Return buffer size enough to hold ASN.1 structure
//  "PBESF2Algorithm" from the RFC 8018.
//
static size_t
vscf_alg_info_der_serializer_serialized_pbes2_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    size_t params_len = 1 + 1 + //  PBES2-params ::= SEQUENCE {
                        1 + 1 + 64 + //      keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
                        1 + 1 + 64; //      encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }

    size_t len = 1 + 1 + //  AlgorithmIdentifier ::= SEQUENCE {
                 1 + 1 + 9 + //      algorithm OBJECT IDENTIFIER, -- id-PBES2
                 params_len; //      parameters PBES2-params }

    return len;
}

//
//  Serialize class "salted kdf alg info" to the ASN.1 structure
//  "PBES2Algorithm" from the RFC 8018.
//
static size_t
vscf_alg_info_der_serializer_serialize_pbes2_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    //  PBES2Algorithms ALGORITHM-IDENTIFIER ::= {
    //      {PBES2-params IDENTIFIED BY id-PBES2},
    //      ...
    //  }
    //
    //  PBES2-params ::= SEQUENCE {
    //      keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
    //      encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
    //  }


    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_impl_t *asn1_writer = self->asn1_writer;

    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_pbes2_alg_info_len(self, alg_info));


    const vscf_pbe_alg_info_t *pbe_alg_info = (const vscf_pbe_alg_info_t *)alg_info;

    size_t len = 0;
    vscf_alg_id_t alg_id = vscf_pbe_alg_info_alg_id(pbe_alg_info);

    switch (alg_id) {
    case vscf_alg_id_PKCS5_PBES2:
        //  Write PBES2-params.
        len += vscf_alg_info_der_serializer_serialize_inplace(self, vscf_pbe_alg_info_cipher_alg_info(pbe_alg_info));

        len += vscf_alg_info_der_serializer_serialize_inplace(self, vscf_pbe_alg_info_kdf_alg_info(pbe_alg_info));

        len += vscf_asn1_writer_write_sequence(asn1_writer, len);
        break;

    default:
        VSCF_ASSERT(0 && "Unhandled alg id.");
        break;
    }

    //  Write OID.
    vsc_data_t cipher_oid = vscf_oid_from_alg_id(alg_id);
    len += vscf_asn1_writer_write_oid(asn1_writer, cipher_oid);

    //  Write AlgorithmIdentifier SEQUENCE.
    len += vscf_asn1_writer_write_sequence(asn1_writer, len);

    VSCF_ASSERT(!vscf_asn1_writer_has_error(asn1_writer));

    return len;
}

//
//  Return buffer size enough to hold ASN.1 structure
//  "AlgorithmIdentifier" with "ECParameters" from the RFC 5480.
//
static size_t
vscf_alg_info_der_serializer_serialized_ecc_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    size_t params_len = 0 + //  ECParameters ::= CHOICE {
                        1 + 1 + 8; //      namedCurve OBJECT IDENTIFIER }

    size_t len = 1 + 1 + //  AlgorithmIdentifier ::= SEQUENCE {
                 1 + 1 + 7 + //      algorithm OBJECT IDENTIFIER, -- id-ecPublicKey
                 params_len; //      parameters ECParameters }

    return len;
}

//
//  Serialize class "ecc alg info" to the ASN.1 structure
//  "AlgorithmIdentifier" with "ECParameters" from the RFC 5480.
//
static size_t
vscf_alg_info_der_serializer_serialize_ecc_alg_info(vscf_alg_info_der_serializer_t *self, const vscf_impl_t *alg_info) {

    //  ECAlgorithms ALGORITHM-IDENTIFIER ::= {
    //      {ECParameters IDENTIFIED BY id-ecPublicKey},
    //      {ECParameters IDENTIFIED BY id-id-ecDH}, -- is not supported by this implementation
    //      {ECParameters IDENTIFIED BY id-ecMQV}, -- is not supported by this implementation
    //      ...
    //  }
    //
    //  ECParameters ::= CHOICE {
    //      namedCurve OBJECT IDENTIFIER
    //      -- implicitCurve NULL (not supported in this implementation)
    //      -- specifiedCurve SpecifiedECDomain
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_impl_t *asn1_writer = self->asn1_writer;

    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_ecc_alg_info_len(self, alg_info));


    const vscf_ecc_alg_info_t *ecc_alg_info = (const vscf_ecc_alg_info_t *)alg_info;

    size_t len = 0;
    vscf_oid_id_t ec_id = vscf_ecc_alg_info_key_id(ecc_alg_info);
    vscf_oid_id_t ec_domain_id = vscf_ecc_alg_info_domain_id(ecc_alg_info);

    VSCF_ASSERT(ec_id == vscf_oid_id_EC_GENERIC_KEY);
    switch (ec_domain_id) {
    case vscf_oid_id_EC_DOMAIN_SECP256R1:
        len += vscf_asn1_writer_write_oid(self->asn1_writer, vscf_oid_from_id(ec_domain_id));
        break;
    default:
        VSCF_ASSERT(0 && "Unexpected OID.");
        return 0;
    }

    len += vscf_asn1_writer_write_oid(self->asn1_writer, vscf_oid_from_id(ec_id));
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    return len;
}

//
//  Return buffer size enough to hold ASN.1 structure
//  "AlgorithmIdentifier" with "CompoundKeyParams" parameters.
//
//  CompoundKeyAlgorithms ALGORITHM ::= {
//      { OID id-CompoundKey parameters CompoundKeyParams }
//  }
//
//  id-CompoundKey ::= { 1 3 6 1 4 1 54811 1 1 }
//
//  CompoundKeyParams ::= SEQUENCE {
//      cipherAlgorithm AlgorithmIdentifier
//      signerAlgorithm AlgorithmIdentifier
//      signerDigestAlgorithm AlgorithmIdentifier
//  }
//
static size_t
vscf_alg_info_der_serializer_serialized_compound_key_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    const vscf_compound_key_alg_info_t *compound_alg_info = (const vscf_compound_key_alg_info_t *)alg_info;
    const vscf_impl_t *cipher_alg_info = vscf_compound_key_alg_info_cipher_alg_info(compound_alg_info);
    const vscf_impl_t *signer_alg_info = vscf_compound_key_alg_info_signer_alg_info(compound_alg_info);
    const vscf_impl_t *signer_hash_alg_info = vscf_compound_key_alg_info_signer_hash_alg_info(compound_alg_info);

    const size_t cipher_alg_info_len = vscf_alg_info_der_serializer_serialized_len(self, cipher_alg_info);
    const size_t signer_alg_info_len = vscf_alg_info_der_serializer_serialized_len(self, signer_alg_info);
    const size_t signer_hash_alg_info_len = vscf_alg_info_der_serializer_serialized_len(self, signer_hash_alg_info);

    const size_t params_len = 1 + 1 + //  CompoundKeyParams ::= SEQUENCE {
                              1 + 1 + cipher_alg_info_len + //      cipherAlgorithm AlgorithmIdentifier
                              1 + 1 + signer_alg_info_len + //      signerAlgorithm AlgorithmIdentifier
                              1 + 1 + signer_hash_alg_info_len; //      signerDigestAlgorithm AlgorithmIdentifier }


    const size_t len = 1 + 1 + //  AlgorithmIdentifier ::= SEQUENCE {
                       1 + 1 + 8 + //      algorithm OBJECT IDENTIFIER, -- id-CompoundKey
                       params_len; //      parameters CompoundKeyParams }

    return len;
}

//
//  Serialize class "compound key alg info" to the ASN.1 structure
//  "AlgorithmIdentifier" with "CompoundKeyParams" parameters.
//
//  CompoundKeyAlgorithms ALGORITHM ::= {
//      { OID id-CompoundKey parameters CompoundKeyParams }
//  }
//
//  id-CompoundKey ::= { 1 3 6 1 4 1 54811 1 1 }
//
//  CompoundKeyParams ::= SEQUENCE {
//      cipherAlgorithm AlgorithmIdentifier
//      signerAlgorithm AlgorithmIdentifier
//      signerDigestAlgorithm AlgorithmIdentifier
//  }
//
static size_t
vscf_alg_info_der_serializer_serialize_compound_key_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);
    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(self->asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_compound_key_alg_info_len(self, alg_info));

    const vscf_compound_key_alg_info_t *compound_alg_info = (const vscf_compound_key_alg_info_t *)alg_info;
    const vscf_alg_id_t alg_id = vscf_compound_key_alg_info_alg_id(compound_alg_info);
    const vscf_impl_t *cipher_alg_info = vscf_compound_key_alg_info_cipher_alg_info(compound_alg_info);
    const vscf_impl_t *signer_alg_info = vscf_compound_key_alg_info_signer_alg_info(compound_alg_info);
    const vscf_impl_t *signer_hash_alg_info = vscf_compound_key_alg_info_signer_hash_alg_info(compound_alg_info);

    //
    //  Write: CompoundKeyParams
    //
    size_t len = 0;
    len += vscf_alg_info_der_serializer_serialize_inplace(self, signer_hash_alg_info);
    len += vscf_alg_info_der_serializer_serialize_inplace(self, signer_alg_info);
    len += vscf_alg_info_der_serializer_serialize_inplace(self, cipher_alg_info);
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    //
    //  Write: AlgorithmIdentifier
    //
    len += vscf_asn1_writer_write_oid(self->asn1_writer, vscf_oid_from_alg_id(alg_id));
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    return len;
}

//
//  Return buffer size enough to hold ASN.1 structure
//  "AlgorithmIdentifier" with "ChainedKeyParams" parameters.
//
//  ChainedKeyAlgorithms ALGORITHM ::= {
//      { OID id-ChainedKey parameters ChainedKeyParams }
//  }
//
//  id-ChainedKey ::= { 1 3 6 1 4 1 54811 1 2 }
//
//  ChainedKeyParams ::= SEQUENCE {
//      l1CipherAlgorithm AlgorithmIdentifier,
//      l2CipherAlgorithm AlgorithmIdentifier
//  }
//
static size_t
vscf_alg_info_der_serializer_serialized_chained_key_alg_info_len(const vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    const vscf_chained_key_alg_info_t *compound_alg_info = (const vscf_chained_key_alg_info_t *)alg_info;
    const vscf_impl_t *l1_cipher_alg_info = vscf_chained_key_alg_info_l1_key_alg_info(compound_alg_info);
    const vscf_impl_t *l2_cipher_alg_info = vscf_chained_key_alg_info_l2_key_alg_info(compound_alg_info);

    const size_t l1_cipher_alg_info_len = vscf_alg_info_der_serializer_serialized_len(self, l1_cipher_alg_info);
    const size_t l2_cipher_alg_info_len = vscf_alg_info_der_serializer_serialized_len(self, l2_cipher_alg_info);

    const size_t params_len = 1 + 1 + //  ChainedKeyParams ::= SEQUENCE {
                              1 + 1 + l1_cipher_alg_info_len + //      l1CipherAlgorithm AlgorithmIdentifier,
                              1 + 1 + l2_cipher_alg_info_len; //      l2CipherAlgorithm AlgorithmIdentifier }


    const size_t len = 1 + 1 + //  AlgorithmIdentifier ::= SEQUENCE {
                       1 + 1 + 8 + //      algorithm OBJECT IDENTIFIER, -- id-ChainedKey
                       params_len; //      parameters ChainedKeyParams }

    return len;
}

//
//  Serialize class "chained key alg info" to the ASN.1 structure
//  "AlgorithmIdentifier" with "ChainedKeyParams" parameters.
//
//  ChainedKeyAlgorithms ALGORITHM ::= {
//      { OID id-ChainedKey parameters ChainedKeyParams }
//  }
//
//  id-ChainedKey ::= { 1 3 6 1 4 1 54811 1 2 }
//
//  ChainedKeyParams ::= SEQUENCE {
//      l1CipherAlgorithm AlgorithmIdentifier,
//      l2CipherAlgorithm AlgorithmIdentifier
//  }
//
static size_t
vscf_alg_info_der_serializer_serialize_chained_key_alg_info(vscf_alg_info_der_serializer_t *self,
        const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);
    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(self->asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_chained_key_alg_info_len(self, alg_info));

    const vscf_chained_key_alg_info_t *compound_alg_info = (const vscf_chained_key_alg_info_t *)alg_info;
    const vscf_alg_id_t alg_id = vscf_chained_key_alg_info_alg_id(compound_alg_info);
    const vscf_impl_t *l1_cipher_alg_info = vscf_chained_key_alg_info_l1_key_alg_info(compound_alg_info);
    const vscf_impl_t *l2_cipher_alg_info = vscf_chained_key_alg_info_l2_key_alg_info(compound_alg_info);

    //
    //  Write: ChainedKeyParams
    //
    size_t len = 0;
    len += vscf_alg_info_der_serializer_serialize_inplace(self, l2_cipher_alg_info);
    len += vscf_alg_info_der_serializer_serialize_inplace(self, l1_cipher_alg_info);
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    //
    //  Write: AlgorithmIdentifier
    //
    len += vscf_asn1_writer_write_oid(self->asn1_writer, vscf_oid_from_alg_id(alg_id));
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    return len;
}

//
//  Serialize by using internal ASN.1 writer.
//  Note, that caller code is responsible to reset ASN.1 writer with
//  an output buffer.
//
VSCF_PUBLIC size_t
vscf_alg_info_der_serializer_serialize_inplace(vscf_alg_info_der_serializer_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(self->asn1_writer) >=
                vscf_alg_info_der_serializer_serialized_len(self, alg_info));

    vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
    case vscf_alg_id_SHA224:
    case vscf_alg_id_SHA256:
    case vscf_alg_id_SHA384:
    case vscf_alg_id_SHA512:
    case vscf_alg_id_RSA:
    case vscf_alg_id_ECC:
    case vscf_alg_id_ED25519:
    case vscf_alg_id_CURVE25519:
    case vscf_alg_id_FALCON:
    case vscf_alg_id_ROUND5:
    case vscf_alg_id_ROUND5_ND_5PKE_5D:
    case vscf_alg_id_POST_QUANTUM:
        return vscf_alg_info_der_serializer_serialize_simple_alg_info(self, alg_info);

    case vscf_alg_id_SECP256R1:
        return vscf_alg_info_der_serializer_serialize_ecc_alg_info(self, alg_info);

    case vscf_alg_id_KDF1:
    case vscf_alg_id_KDF2:
        return vscf_alg_info_der_serializer_serialize_kdf_alg_info(self, alg_info);

    case vscf_alg_id_HKDF:
        return vscf_alg_info_der_serializer_serialize_hkdf_alg_info(self, alg_info);

    case vscf_alg_id_HMAC:
        return vscf_alg_info_der_serializer_serialize_hmac_alg_info(self, alg_info);

    case vscf_alg_id_AES256_GCM:
    case vscf_alg_id_AES256_CBC:
        return vscf_alg_info_der_serializer_serialize_cipher_alg_info(self, alg_info);

    case vscf_alg_id_PKCS5_PBKDF2:
        return vscf_alg_info_der_serializer_serialize_pbkdf2_alg_info(self, alg_info);

    case vscf_alg_id_PKCS5_PBES2:
        return vscf_alg_info_der_serializer_serialize_pbes2_alg_info(self, alg_info);

    case vscf_alg_id_COMPOUND_KEY:
        return vscf_alg_info_der_serializer_serialize_compound_key_alg_info(self, alg_info);

    case vscf_alg_id_CHAINED_KEY:
        return vscf_alg_info_der_serializer_serialize_chained_key_alg_info(self, alg_info);

    case vscf_alg_id_NONE:
        VSCF_ASSERT(0 && "Unhandled alg id.");
        return 0;
    }

    return 0;
}

//
//  Return buffer size enough to hold serialized algorithm.
//
VSCF_PUBLIC size_t
vscf_alg_info_der_serializer_serialized_len(const vscf_alg_info_der_serializer_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    //
    //  Route serialization len.
    //
    vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
    case vscf_alg_id_SHA224:
    case vscf_alg_id_SHA256:
    case vscf_alg_id_SHA384:
    case vscf_alg_id_SHA512:
    case vscf_alg_id_RSA:
    case vscf_alg_id_ECC:
    case vscf_alg_id_ED25519:
    case vscf_alg_id_CURVE25519:
    case vscf_alg_id_FALCON:
    case vscf_alg_id_ROUND5:
    case vscf_alg_id_POST_QUANTUM:
    case vscf_alg_id_ROUND5_ND_5PKE_5D:
        return vscf_alg_info_der_serializer_serialized_simple_alg_info_len(self, alg_info);

    case vscf_alg_id_SECP256R1:
        return vscf_alg_info_der_serializer_serialized_ecc_alg_info_len(self, alg_info);

    case vscf_alg_id_KDF1:
    case vscf_alg_id_KDF2:
        return vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(self, alg_info);

    case vscf_alg_id_HKDF:
        return vscf_alg_info_der_serializer_serialized_hkdf_alg_info_len(self, alg_info);

    case vscf_alg_id_HMAC:
        return vscf_alg_info_der_serializer_serialized_hmac_alg_info_len(self, alg_info);

    case vscf_alg_id_AES256_GCM:
    case vscf_alg_id_AES256_CBC:
        return vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(self, alg_info);

    case vscf_alg_id_PKCS5_PBKDF2:
        return vscf_alg_info_der_serializer_serialized_pbkdf2_alg_info_len(self, alg_info);

    case vscf_alg_id_PKCS5_PBES2:
        return vscf_alg_info_der_serializer_serialized_pbes2_alg_info_len(self, alg_info);

    case vscf_alg_id_COMPOUND_KEY:
        return vscf_alg_info_der_serializer_serialized_compound_key_alg_info_len(self, alg_info);

    case vscf_alg_id_CHAINED_KEY:
        return vscf_alg_info_der_serializer_serialized_chained_key_alg_info_len(self, alg_info);

    case vscf_alg_id_NONE:
        VSCF_ASSERT(0 && "Unhandled alg id.");
        break;
    }

    return 0;
}

//
//  Serialize algorithm info to buffer class.
//
VSCF_PUBLIC void
vscf_alg_info_der_serializer_serialize(vscf_alg_info_der_serializer_t *self, const vscf_impl_t *alg_info,
        vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_alg_info_der_serializer_serialized_len(self, alg_info));

    VSCF_ASSERT_PTR(self->asn1_writer);

    //
    //  Create buffer that maps to the unused bytes from the original buffer.
    //
    vsc_buffer_t der_out;
    vsc_buffer_init(&der_out);

    vsc_buffer_use(&der_out, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    vsc_buffer_switch_reverse_mode(&der_out, true);

    //
    //  Put buffer to the asn1_writer.
    //
    vscf_asn1_writer_reset(self->asn1_writer, vsc_buffer_unused_bytes(&der_out), vsc_buffer_unused_len(&der_out));

    //
    //  Serialize.
    //
    size_t der_out_len = vscf_alg_info_der_serializer_serialize_inplace(self, alg_info);
    vsc_buffer_inc_used(&der_out, der_out_len);

    //
    //  Adjust written bytes to the original buffer mode.
    //
    vsc_buffer_switch_reverse_mode(&der_out, vsc_buffer_is_reverse(out));
    vsc_buffer_inc_used(out, vsc_buffer_len(&der_out));

    vsc_buffer_cleanup(&der_out);
}
