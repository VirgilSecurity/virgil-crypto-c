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
#include "vscf_salted_kdf_alg_info.h"
#include "vscf_pbe_alg_info.h"
#include "vscf_ecc_alg_info.h"
#include "vscf_padding_cipher_alg_info.h"
#include "vscf_alg_info.h"
#include "vscf_asn1_reader.h"
#include "vscf_alg_info_der_deserializer_defs.h"
#include "vscf_alg_info_der_deserializer_internal.h"
#include "vscf_oid_id.h"

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
vscf_alg_info_der_deserializer_deserialize_simple_alg_info(vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id,
        vscf_error_t *error);

//
//  Parse ASN.1 structure "KeyDerivationFunction" from the ISO/IEC 18033-2.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id,
        vscf_error_t *error);

//
//  Parse ASN.1 structure "KeyDevAlgs" from the
//  https://tools.ietf.org/html/draft-housley-hkdf-oids-00.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id,
        vscf_error_t *error);

//
//  Parse ASN.1 structure "DigestAlgorithm" from the RFC 4231.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id,
        vscf_error_t *error);

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with AES parameters:
//      - defined in the RFC 3565;
//      - defined in the RFC 5084.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id,
        vscf_error_t *error);

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with PBKDF2 parameters
//  defined in the RFC 8018.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info(vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id,
        vscf_error_t *error);

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with PBES2 parameters
//  defined in the RFC 8018.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info(vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id,
        vscf_error_t *error);

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with ECParameters
//  parameters defined in the RFC 5480.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_ecc_alg_info(vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id,
        vscf_error_t *error);

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with
//  PaddingCipherParameters parameters.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_padding_cipher_alg_info(vscf_alg_info_der_deserializer_t *self,
        vscf_oid_id_t oid_id, vscf_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserializer_setup_defaults(vscf_alg_info_der_deserializer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->asn1_reader) {
        vscf_alg_info_der_deserializer_take_asn1_reader(self, vscf_asn1rd_impl(vscf_asn1rd_new()));
    }
}

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with optional NULL parameter.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_simple_alg_info(
        vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id, vscf_error_t *error) {

    //  AlgorithmIdentifier ::= SEQUENCE {
    //          algorithm OBJECT IDENTIFIER,
    //          parameters ANY DEFINED BY algorithm OPTIONAL
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);

    //  According to RFC 5754 - Using SHA2 Algorithms with Cryptographic Message Syntax.
    //  Implementations MUST accept SHA2 AlgorithmIdentifiers with NULL parameters.
    vscf_asn1_reader_read_null_optional(self->asn1_reader);

    vscf_status_t status = vscf_asn1_reader_status(self->asn1_reader);

    if (vscf_status_SUCCESS == status) {
        vscf_alg_id_t alg_id = vscf_oid_id_to_alg_id(oid_id);
        return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(alg_id));
    } else {
        VSCF_ERROR_SAFE_UPDATE(error, status);
    }

    return NULL;
}

//
//  Parse ASN.1 structure "KeyDerivationFunction" from the ISO/IEC 18033-2.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(
        vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id, vscf_error_t *error) {

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
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);

    //  Read HashFunction.
    vscf_impl_t *hash_alg_info = vscf_alg_info_der_deserializer_deserialize_inplace(self, error);
    if (hash_alg_info == NULL) {
        return NULL;
    }

    const vscf_alg_id_t alg_id = vscf_oid_id_to_alg_id(oid_id);

    vscf_impl_t *hash_based_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(alg_id, &hash_alg_info));

    return hash_based_alg_info;
}

//
//  Parse ASN.1 structure "KeyDevAlgs" from the
//  https://tools.ietf.org/html/draft-housley-hkdf-oids-00.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(
        vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id, vscf_error_t *error) {

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


    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);
    VSCF_UNUSED(error);

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
        VSCF_ASSERT(0 && "Unexpected OID.");
        break;
    }

    vscf_impl_t *hash_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(hash_alg_id));
    vscf_impl_t *hash_based_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(vscf_alg_id_HKDF, &hash_alg_info));

    return hash_based_alg_info;
}

//
//  Parse ASN.1 structure "DigestAlgorithm" from the RFC 4231.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(
        vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id, vscf_error_t *error) {

    //  DigestAlgorithms ALGORITHM ::= {
    //       id-hmacWithSHA224 |
    //       id-hmacWithSHA256 |
    //       id-hmacWithSHA384 |
    //       id-hmacWithSHA512,
    //       ... }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);
    VSCF_UNUSED(error);

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
        VSCF_ASSERT(0 && "Unexpected OID.");
        break;
    }

    //  parameters NULL : NULL is reuired by the RFC 4231,
    //  but this rule is relaxed to keep backward compatibility with Virgil Crypto v2,
    //  that do not write NULL for this AlgorithmIdentifier.
    vscf_asn1_reader_read_null_optional(self->asn1_reader);

    vscf_impl_t *hash_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(hash_alg_id));
    vscf_impl_t *hash_based_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(vscf_alg_id_HMAC, &hash_alg_info));

    return hash_based_alg_info;
}

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with AES parameters:
//      - defined in the RFC 3565;
//      - defined in the RFC 5084.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(
        vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id, vscf_error_t *error) {

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
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);

    //  Read PARAMS, aka NONCE.
    vsc_data_t cipher_nonce = vsc_data_empty();

    if (vscf_asn1_reader_get_tag(self->asn1_reader) == (vscf_asn1_tag_CONSTRUCTED | vscf_asn1_tag_SEQUENCE)) {
        //  Read GCMParameters.
        vscf_asn1_reader_read_sequence(self->asn1_reader);
        cipher_nonce = vscf_asn1_reader_read_octet_str(self->asn1_reader);
        size_t nonce_len = vscf_asn1_reader_read_int(self->asn1_reader);

        if (cipher_nonce.len != nonce_len) {
            VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
            return NULL;
        }
    } else {
        //  Read NONCE.
        cipher_nonce = vscf_asn1_reader_read_octet_str(self->asn1_reader);
    }

    if (!vscf_asn1_reader_has_error(self->asn1_reader)) {
        const vscf_alg_id_t alg_id = vscf_oid_id_to_alg_id(oid_id);
        return vscf_cipher_alg_info_impl(vscf_cipher_alg_info_new_with_members(alg_id, cipher_nonce));
    } else {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_asn1_reader_status(self->asn1_reader));
        return NULL;
    }
}

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with PBKDF2 parameters
//  defined in the RFC 8018.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info(
        vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id, vscf_error_t *error) {

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
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);


    //
    //  Read: PBKDF2-params.
    //
    vscf_asn1_reader_read_sequence(self->asn1_reader);
    vsc_data_t salt = vscf_asn1_reader_read_octet_str(self->asn1_reader);
    unsigned int iteration_count = vscf_asn1_reader_read_uint(self->asn1_reader);

    if (vscf_asn1_reader_get_tag(self->asn1_reader) == vscf_asn1_tag_INTEGER) {
        (void)vscf_asn1_reader_read_uint(self->asn1_reader);
    }

    if (vsc_data_is_empty(salt)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
    }

    if (iteration_count < 1) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
    }

    vscf_impl_t *prf = vscf_alg_info_der_deserializer_deserialize_inplace(self, error);
    if (prf == NULL) {
        return NULL;
    }

    vscf_salted_kdf_alg_info_t *pbkdf2_alg_info =
            vscf_salted_kdf_alg_info_new_with_members(vscf_alg_id_PKCS5_PBKDF2, &prf, salt, iteration_count);

    return vscf_salted_kdf_alg_info_impl(pbkdf2_alg_info);
}

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with PBES2 parameters
//  defined in the RFC 8018.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info(
        vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id, vscf_error_t *error) {

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
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);

    vscf_asn1_reader_read_sequence(self->asn1_reader);

    vscf_impl_t *kdf = vscf_alg_info_der_deserializer_deserialize_inplace(self, error);
    if (NULL == kdf) {
        return NULL;
    }

    vscf_impl_t *cipher = vscf_alg_info_der_deserializer_deserialize_inplace(self, error);
    if (NULL == cipher) {
        vscf_impl_destroy(&kdf);
        return NULL;
    }

    vscf_pbe_alg_info_t *pbe = vscf_pbe_alg_info_new_with_members(vscf_alg_id_PKCS5_PBES2, &kdf, &cipher);

    return vscf_pbe_alg_info_impl(pbe);
}

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with ECParameters
//  parameters defined in the RFC 5480.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_ecc_alg_info(
        vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id, vscf_error_t *error) {

    //  ECParameters ::= CHOICE {
    //      namedCurve OBJECT IDENTIFIER
    //      -- implicitCurve NULL (not supported in this implementation)
    //      -- specifiedCurve SpecifiedECDomain
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);

    vsc_data_t named_curve_oid = vscf_asn1_reader_read_oid(self->asn1_reader);
    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_SEC1_PUBLIC_KEY);
        return NULL;
    }

    const vscf_oid_id_t named_curve_id = vscf_oid_to_id(named_curve_oid);
    if (named_curve_id == vscf_oid_id_NONE) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    const vscf_alg_id_t ec_alg_id = vscf_oid_id_to_alg_id(named_curve_id);
    vscf_ecc_alg_info_t *alg_info = vscf_ecc_alg_info_new_with_members(ec_alg_id, oid_id, named_curve_id);
    return vscf_ecc_alg_info_impl(alg_info);
}

//
//  Parse ASN.1 structure "AlgorithmIdentifier" with
//  PaddingCipherParameters parameters.
//
static vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_padding_cipher_alg_info(
        vscf_alg_info_der_deserializer_t *self, vscf_oid_id_t oid_id, vscf_error_t *error) {

    //  PaddingCipherParameters ::= SEQUENCE {
    //      underlyingCipher AlgorithmIdentifier,
    //      paddingFrame INTEGER(1..MAX)
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(oid_id != vscf_oid_id_NONE);

    vscf_asn1_reader_read_sequence(self->asn1_reader);

    vscf_impl_t *cipher = vscf_alg_info_der_deserializer_deserialize_inplace(self, error);
    if (NULL == cipher) {
        return NULL;
    }

    const size_t paddingFrame = vscf_asn1_reader_read_uint(self->asn1_reader);
    if (vscf_asn1_reader_has_error(self->asn1_reader) || (paddingFrame == 0)) {
        vscf_impl_destroy(&cipher);
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
        return NULL;
    }

    vscf_padding_cipher_alg_info_t *alg_info = vscf_padding_cipher_alg_info_new_with_members(&cipher, paddingFrame);

    return vscf_padding_cipher_alg_info_impl(alg_info);
}

//
//  Deserialize by using internal ASN.1 reader.
//  Note, that caller code is responsible to reset ASN.1 reader with
//  an input buffer.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize_inplace(vscf_alg_info_der_deserializer_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);

    if (error && vscf_error_has_error(error)) {
        return NULL;
    }

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        return NULL;
    }

    //
    //  Define algorithm identifier.
    //
    vscf_asn1_reader_read_sequence(self->asn1_reader);
    vsc_data_t alg_oid = vscf_asn1_reader_read_oid(self->asn1_reader);

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_asn1_reader_status(self->asn1_reader));
        return NULL;
    }


    //
    //  Proxy further deserialization for specific algorithm.
    //
    vscf_oid_id_t oid_id = vscf_oid_to_id(alg_oid);

    switch (oid_id) {
    case vscf_oid_id_SHA224:
    case vscf_oid_id_SHA256:
    case vscf_oid_id_SHA384:
    case vscf_oid_id_SHA512:
    case vscf_oid_id_RSA:
    case vscf_oid_id_ED25519:
    case vscf_oid_id_CURVE25519:
        return vscf_alg_info_der_deserializer_deserialize_simple_alg_info(self, oid_id, error);

    case vscf_oid_id_EC_GENERIC_KEY:
        return vscf_alg_info_der_deserializer_deserialize_ecc_alg_info(self, oid_id, error);

    case vscf_oid_id_KDF1:
    case vscf_oid_id_KDF2:
        return vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(self, oid_id, error);

    case vscf_oid_id_HKDF_WITH_SHA256:
    case vscf_oid_id_HKDF_WITH_SHA384:
    case vscf_oid_id_HKDF_WITH_SHA512:
        return vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(self, oid_id, error);

    case vscf_oid_id_HMAC_WITH_SHA224:
    case vscf_oid_id_HMAC_WITH_SHA256:
    case vscf_oid_id_HMAC_WITH_SHA384:
    case vscf_oid_id_HMAC_WITH_SHA512:
        return vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(self, oid_id, error);

    case vscf_oid_id_AES256_GCM:
    case vscf_oid_id_AES256_CBC:
        return vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(self, oid_id, error);

    case vscf_oid_id_PKCS5_PBKDF2:
        return vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info(self, oid_id, error);

    case vscf_oid_id_PKCS5_PBES2:
        return vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info(self, oid_id, error);

    case vscf_oid_id_PADDING_CIPHER:
        return vscf_alg_info_der_deserializer_deserialize_padding_cipher_alg_info(self, oid_id, error);

    case vscf_oid_id_CMS_DATA:
    case vscf_oid_id_CMS_ENVELOPED_DATA:
    case vscf_oid_id_EC_DOMAIN_SECP256R1:
    case vscf_oid_id_NONE:
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    return NULL;
}

//
//  Deserialize algorithm from the data.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize(
        vscf_alg_info_der_deserializer_t *self, vsc_data_t data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(self->asn1_reader);

    vscf_asn1_reader_reset(self->asn1_reader, data);

    return vscf_alg_info_der_deserializer_deserialize_inplace(self, error);
}
