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
//  This module contains 'alg info der deserializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_alg_info_der_deserializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1rd.h"
#include "vscf_oid.h"
#include "vscf_asn1_tag.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_alg_info.h"
#include "vscf_asn1_reader.h"
#include "vscf_alg_info_der_deserializer_defs.h"
#include "vscf_alg_info_der_deserializer_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with optional NULL parameter.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_simple_alg_info(vscf_alg_info_der_deserializer_t *alg_info_der_deserializer,
        vsc_data_t data, vscf_error_ctx_t *error);

//
//  Parse ASN.1 structure "KeyDerivationFunction" from the ISO/IEC 18033-2.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(vscf_alg_info_der_deserializer_t *alg_info_der_deserializer,
        vsc_data_t data, vscf_error_ctx_t *error);

//
//  Parse ASN.1 structure "KeyDevAlgs" from the
//  https://tools.ietf.org/html/draft-housley-hkdf-oids-00.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(vscf_alg_info_der_deserializer_t *alg_info_der_deserializer,
        vsc_data_t data, vscf_error_ctx_t *error);

//
//  Parse ASN.1 structure "DigestAlgorithm" from the RFC 4231.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(vscf_alg_info_der_deserializer_t *alg_info_der_deserializer,
        vsc_data_t data, vscf_error_ctx_t *error);

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with AES parameters:
//      - defined in the RFC 3565;
//      - defined in the RFC 5084.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(vscf_alg_info_der_deserializer_t *alg_info_der_deserializer,
        vsc_data_t data, vscf_error_ctx_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Parse ASN.1 structure "AlgorithmIdentifier" with optional NULL parameter.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_simple_alg_info(
        vscf_alg_info_der_deserializer_t *alg_info_der_deserializer, vsc_data_t data, vscf_error_ctx_t *error) {

    //  AlgorithmIdentifier ::= SEQUENCE {
    //          algorithm OBJECT IDENTIFIER,
    //          parameters ANY DEFINED BY algorithm OPTIONAL
    //  }

    VSCF_ASSERT_PTR(alg_info_der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(alg_info_der_deserializer->asn1_reader);

    vscf_impl_t *asn1_reader = alg_info_der_deserializer->asn1_reader;
    vscf_asn1_reader_reset(asn1_reader, data);

    vscf_asn1_reader_read_sequence(asn1_reader);
    vsc_data_t alg_oid = vscf_asn1_reader_read_oid(asn1_reader);

    if (vscf_asn1_reader_get_tag(asn1_reader) == vscf_asn1_tag_NULL) {
        vscf_asn1_reader_read_null(asn1_reader);
    }

    vscf_error_t status = vscf_asn1_reader_error(asn1_reader);

    if (vscf_SUCCESS == status) {
        vscf_alg_id_t alg_id = vscf_oid_to_alg_id(alg_oid);
        return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(alg_id));
    } else {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, status);
    }

    return NULL;
}

//
//  Parse ASN.1 structure "KeyDerivationFunction" from the ISO/IEC 18033-2.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(
        vscf_alg_info_der_deserializer_t *alg_info_der_deserializer, vsc_data_t data, vscf_error_ctx_t *error) {

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

    VSCF_ASSERT_PTR(alg_info_der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_UNUSED(error);

    VSCF_ASSERT_PTR(alg_info_der_deserializer->asn1_reader);

    vscf_impl_t *asn1_reader = alg_info_der_deserializer->asn1_reader;
    vscf_asn1_reader_reset(asn1_reader, data);

    //  Read KeyDerivationFunction.
    vscf_asn1_reader_read_sequence(asn1_reader);
    vsc_data_t alg_oid = vscf_asn1_reader_read_oid(asn1_reader);

    //  Read HashFunction.
    vscf_asn1_reader_read_sequence(asn1_reader);
    vsc_data_t hash_oid = vscf_asn1_reader_read_oid(asn1_reader);

    vscf_error_t status = vscf_asn1_reader_error(asn1_reader);
    if (status != vscf_SUCCESS) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, status);
        return NULL;
    }

    const vscf_alg_id_t alg_id = vscf_oid_to_alg_id(alg_oid);
    const vscf_alg_id_t hash_id = vscf_oid_to_alg_id(hash_oid);

    if ((alg_id == vscf_alg_id_NONE) || (hash_id == vscf_alg_id_NONE)) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_error_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    vscf_impl_t *hash_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(hash_id));
    vscf_impl_t *hash_based_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(alg_id, hash_alg_info));

    vscf_impl_destroy(&hash_alg_info);

    return hash_based_alg_info;
}

//
//  Parse ASN.1 structure "KeyDevAlgs" from the
//  https://tools.ietf.org/html/draft-housley-hkdf-oids-00.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(
        vscf_alg_info_der_deserializer_t *alg_info_der_deserializer, vsc_data_t data, vscf_error_ctx_t *error) {

    //  KeyDevAlgs KEY-DERIVATION ::= {
    //       kda-hkdf-with-sha256 |
    //       kda-hkdf-with-sha384 |
    //       kda-hkdf-with-sha512,
    //       ... }
    //
    //  kda-hkdf-with-sha256 KEY-DERIVATION ::= {
    //      IDENTIFIER id-alg-hkdf-with-sha256
    //      PARAMS ARE absent
    //      SMIME-CAPS { IDENTIFIED BY id-alg-hkdf-with-sha256 } }
    //
    //   kda-hkdf-with-sha384 KEY-DERIVATION ::= {
    //       IDENTIFIER id-alg-hkdf-with-sha384
    //       PARAMS ARE absent
    //       SMIME-CAPS { IDENTIFIED BY id-alg-hkdf-with-sha384 } }
    //
    //   kda-hkdf-with-sha512 KEY-DERIVATION ::= {
    //       IDENTIFIER id-alg-hkdf-with-sha512
    //       PARAMS ARE absent
    //        SMIME-CAPS { IDENTIFIED BY id-alg-hkdf-with-sha512 } }


    VSCF_ASSERT_PTR(alg_info_der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_UNUSED(error);

    VSCF_ASSERT_PTR(alg_info_der_deserializer->asn1_reader);

    vscf_impl_t *asn1_reader = alg_info_der_deserializer->asn1_reader;
    vscf_asn1_reader_reset(asn1_reader, data);

    //  Read KeyDevAlgs.
    vscf_asn1_reader_read_sequence(asn1_reader);
    vsc_data_t alg_oid = vscf_asn1_reader_read_oid(asn1_reader);

    vscf_error_t status = vscf_asn1_reader_error(asn1_reader);
    if (status != vscf_SUCCESS) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, status);
        return NULL;
    }

    const vscf_oid_id_t oid_id = vscf_oid_to_id(alg_oid);
    if (oid_id == vscf_oid_id_NONE) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_error_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    vscf_alg_id_t hash_alg_id = vscf_alg_id_NONE;

    switch (oid_id) {
    case vscf_oid_id_HKDF_WITH_SHA256:
        hash_alg_id = vscf_alg_id_SHA256;
        break;

    case vscf_oid_id_HKDF_WITH_SHA384:
        hash_alg_id = vscf_alg_id_SHA384;
        break;

    case vscf_oid_id_HKDF_WITH_SHA512:
        hash_alg_id = vscf_alg_id_SHA512;
        break;

    default:
        VSCF_ASSERT("Unexpected OID.");
        break;
    }

    vscf_impl_t *hash_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(hash_alg_id));
    vscf_impl_t *hash_based_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(vscf_alg_id_HKDF, hash_alg_info));

    vscf_impl_destroy(&hash_alg_info);

    return hash_based_alg_info;
}

//
//  Parse ASN.1 structure "DigestAlgorithm" from the RFC 4231.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(
        vscf_alg_info_der_deserializer_t *alg_info_der_deserializer, vsc_data_t data, vscf_error_ctx_t *error) {

    //  DigestAlgorithms ALGORITHM ::= {
    //       id-hmacWithSHA224 |
    //       id-hmacWithSHA256 |
    //       id-hmacWithSHA384 |
    //       id-hmacWithSHA512,
    //       ... }

    VSCF_ASSERT_PTR(alg_info_der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_UNUSED(error);

    VSCF_ASSERT_PTR(alg_info_der_deserializer->asn1_reader);

    vscf_impl_t *asn1_reader = alg_info_der_deserializer->asn1_reader;
    vscf_asn1_reader_reset(asn1_reader, data);

    //  Read KeyDevAlgs.
    vscf_asn1_reader_read_sequence(asn1_reader);
    vsc_data_t alg_oid = vscf_asn1_reader_read_oid(asn1_reader);

    vscf_error_t status = vscf_asn1_reader_error(asn1_reader);
    if (status != vscf_SUCCESS) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, status);
        return NULL;
    }

    const vscf_oid_id_t oid_id = vscf_oid_to_id(alg_oid);
    if (oid_id == vscf_oid_id_NONE) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_error_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    vscf_alg_id_t hash_alg_id = vscf_alg_id_NONE;

    switch (oid_id) {
    case vscf_oid_id_HMAC_WITH_SHA224:
        hash_alg_id = vscf_alg_id_SHA224;
        break;

    case vscf_oid_id_HMAC_WITH_SHA256:
        hash_alg_id = vscf_alg_id_SHA256;
        break;

    case vscf_oid_id_HMAC_WITH_SHA384:
        hash_alg_id = vscf_alg_id_SHA384;
        break;

    case vscf_oid_id_HMAC_WITH_SHA512:
        hash_alg_id = vscf_alg_id_SHA512;
        break;
    default:
        VSCF_ASSERT("Unexpected OID.");
        break;
    }

    vscf_impl_t *hash_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(hash_alg_id));
    vscf_impl_t *hash_based_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(vscf_alg_id_HMAC, hash_alg_info));

    vscf_impl_destroy(&hash_alg_info);

    return hash_based_alg_info;
}

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with AES parameters:
//      - defined in the RFC 3565;
//      - defined in the RFC 5084.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(
        vscf_alg_info_der_deserializer_t *alg_info_der_deserializer, vsc_data_t data, vscf_error_ctx_t *error) {

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

    VSCF_ASSERT_PTR(alg_info_der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(alg_info_der_deserializer->asn1_reader);

    vscf_impl_t *asn1_reader = alg_info_der_deserializer->asn1_reader;
    vscf_asn1_reader_reset(asn1_reader, data);

    //  Read OID.
    vscf_asn1_reader_read_sequence(asn1_reader);
    vsc_data_t cipher_oid = vscf_asn1_reader_read_oid(asn1_reader);

    if (vscf_asn1_reader_error(asn1_reader) != vscf_SUCCESS) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_asn1_reader_error(asn1_reader));
        return NULL;
    }

    vscf_alg_id_t alg_id = vscf_oid_to_alg_id(cipher_oid);

    //  Read PARAMS, aka NONCE.
    vsc_data_t cipher_nonce = vsc_data_empty();

    if (vscf_asn1_reader_get_tag(asn1_reader) == (vscf_asn1_tag_CONSTRUCTED | vscf_asn1_tag_SEQUENCE)) {
        //  Read GCMParameters.
        vscf_asn1_reader_read_sequence(asn1_reader);
        cipher_nonce = vscf_asn1_reader_read_octet_str(asn1_reader);
        size_t nonce_len = vscf_asn1_reader_read_int(asn1_reader);

        if (cipher_nonce.len != nonce_len) {
            VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_error_BAD_ASN1);
            return NULL;
        }
    } else {
        //  Read NONCE.
        cipher_nonce = vscf_asn1_reader_read_octet_str(asn1_reader);
    }

    if (vscf_asn1_reader_error(asn1_reader) == vscf_SUCCESS) {
        return vscf_cipher_alg_info_impl(vscf_cipher_alg_info_new_with_members(alg_id, cipher_nonce));
    } else {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_asn1_reader_error(asn1_reader));
        return NULL;
    }
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_alg_info_der_deserializer_setup_defaults(vscf_alg_info_der_deserializer_t *alg_info_der_deserializer) {

    VSCF_ASSERT_PTR(alg_info_der_deserializer);

    if (NULL == alg_info_der_deserializer->asn1_reader) {
        vscf_alg_info_der_deserializer_take_asn1_reader(alg_info_der_deserializer, vscf_asn1rd_impl(vscf_asn1rd_new()));
    }

    return vscf_SUCCESS;
}

//
//  Deserialize algorithm from the data.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize(
        vscf_alg_info_der_deserializer_t *alg_info_der_deserializer, vsc_data_t data, vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(alg_info_der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(alg_info_der_deserializer->asn1_reader);
    VSCF_UNUSED(error);

    //
    //  Define algorithm identifier.
    //
    vscf_impl_t *asn1_reader = alg_info_der_deserializer->asn1_reader;
    vscf_asn1_reader_reset(asn1_reader, data);
    vscf_asn1_reader_read_sequence(asn1_reader);
    vsc_data_t alg_oid = vscf_asn1_reader_read_oid(asn1_reader);

    vscf_error_t asn1_status = vscf_asn1_reader_error(asn1_reader);
    if (asn1_status != vscf_SUCCESS) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, asn1_status);
        return NULL;
    }

    vscf_alg_id_t alg_id = vscf_oid_to_alg_id(alg_oid);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    //
    //  Proxy further deserialization for specific algorithm.
    //
    switch (alg_id) {
    case vscf_alg_id_SHA224:
    case vscf_alg_id_SHA256:
    case vscf_alg_id_SHA384:
    case vscf_alg_id_SHA512:
    case vscf_alg_id_RSA:
    case vscf_alg_id_ED25519:
    case vscf_alg_id_X25519:
        return vscf_alg_info_der_deserializer_deserialize_simple_alg_info(alg_info_der_deserializer, data, error);

    case vscf_alg_id_KDF1:
    case vscf_alg_id_KDF2:
        return vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(alg_info_der_deserializer, data, error);

    case vscf_alg_id_HKDF:
        return vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(alg_info_der_deserializer, data, error);

    case vscf_alg_id_HMAC:
        return vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(alg_info_der_deserializer, data, error);

    case vscf_alg_id_AES256_GCM:
        return vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(alg_info_der_deserializer, data, error);

    case vscf_alg_id_PKCS5_PBKDF2:
    case vscf_alg_id_PKCS5_PBES2:
    case vscf_alg_id_NONE:
        VSCF_ASSERT(0 && "Unhandled alg id.");
        break;
    }

    return NULL;
}
