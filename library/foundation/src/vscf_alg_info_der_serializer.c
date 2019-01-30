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
#include "vscf_asn1wr.h"
#include "vscf_oid.h"
#include "vscf_asn1_tag.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_kdf_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_alg_info.h"
#include "vscf_asn1_writer.h"
#include "vscf_alg_info_der_serializer_defs.h"
#include "vscf_alg_info_der_serializer_internal.h"
#include "vscf_alg_id.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return true if algorithm identifier requires that optinal
//  parameter will be NULL.
//
static bool
vscf_alg_info_der_serializer_is_alg_require_null_params(vscf_alg_id_t alg_id);

//
//  Return buffer size enough to hold serialized class "simple alg info".
//
static size_t
vscf_alg_info_der_serializer_serialized_simple_alg_info_len(vscf_alg_info_der_serializer_t *alg_info_der_serializer,
        const vscf_simple_alg_info_t *simple_alg_info);

//
//  Serialize class "simple alg info".
//
static size_t
vscf_alg_info_der_serializer_serialize_simple_alg_info(vscf_alg_info_der_serializer_t *alg_info_der_serializer,
        const vscf_simple_alg_info_t *simple_alg_info, vsc_buffer_t *out);

//
//  Return buffer size enough to hold serialized class "kdf alg info".
//
static size_t
vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(vscf_alg_info_der_serializer_t *alg_info_der_serializer,
        const vscf_kdf_alg_info_t *kdf_alg_info);

//
//  Serialize class "kdf alg info".
//
static size_t
vscf_alg_info_der_serializer_serialize_kdf_alg_info(vscf_alg_info_der_serializer_t *alg_info_der_serializer,
        const vscf_kdf_alg_info_t *kdf_alg_info, vsc_buffer_t *out);

//
//  Return buffer size enough to hold serialized class "cipher alg info".
//
static size_t
vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(vscf_alg_info_der_serializer_t *alg_info_der_serializer,
        const vscf_cipher_alg_info_t *cipher_alg_info);

//
//  Serialize class "cipher alg info".
//
static size_t
vscf_alg_info_der_serializer_serialize_cipher_alg_info(vscf_alg_info_der_serializer_t *alg_info_der_serializer,
        const vscf_cipher_alg_info_t *cipher_alg_info, vsc_buffer_t *out);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Return true if algorithm identifier requires that optinal
//  parameter will be NULL.
//
static bool
vscf_alg_info_der_serializer_is_alg_require_null_params(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
    case vscf_alg_id_RSA:
        return true;

    default:
        return false;
    }
}

//
//  Return buffer size enough to hold serialized class "simple alg info".
//
static size_t
vscf_alg_info_der_serializer_serialized_simple_alg_info_len(
        vscf_alg_info_der_serializer_t *alg_info_der_serializer, const vscf_simple_alg_info_t *simple_alg_info) {

    VSCF_ASSERT_PTR(alg_info_der_serializer);
    VSCF_ASSERT_PTR(simple_alg_info);

    size_t len = 1 + 1 +      //  AlgorithmIdentifier ::= SEQUENCE {
                 1 + 1 + 32 + //          algorithm OBJECT IDENTIFIER,
                 0;           //          parameters ANY DEFINED BY algorithm OPTIONAL
                              //  }

    return len;
}

//
//  Serialize class "simple alg info".
//
static size_t
vscf_alg_info_der_serializer_serialize_simple_alg_info(vscf_alg_info_der_serializer_t *alg_info_der_serializer,
        const vscf_simple_alg_info_t *simple_alg_info, vsc_buffer_t *out) {

    //  AlgorithmIdentifier ::= SEQUENCE {
    //          algorithm OBJECT IDENTIFIER,
    //          parameters ANY DEFINED BY algorithm OPTIONAL
    //  }

    VSCF_ASSERT_PTR(alg_info_der_serializer);
    VSCF_ASSERT_PTR(simple_alg_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_is_reverse(out));
    VSCF_ASSERT_PTR(alg_info_der_serializer->asn1_writer);

    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_alg_info_der_serializer_serialized_simple_alg_info_len(alg_info_der_serializer, simple_alg_info));

    vscf_impl_t *asn1_writer = alg_info_der_serializer->asn1_writer;
    vscf_asn1_writer_reset(asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    vscf_alg_id_t alg_id = vscf_simple_alg_info_alg_id(simple_alg_info);
    vsc_data_t oid = vscf_oid_from_alg_id(alg_id);
    size_t hash_len = 0;
    if (vscf_alg_info_der_serializer_is_alg_require_null_params(alg_id)) {
        hash_len += vscf_asn1_writer_write_null(asn1_writer);
    }
    hash_len += vscf_asn1_writer_write_oid(asn1_writer, oid);
    hash_len += vscf_asn1_writer_write_sequence(asn1_writer, hash_len);
    VSCF_ASSERT(vscf_asn1_writer_error(asn1_writer) == vscf_SUCCESS);

    vsc_buffer_inc_used(out, hash_len);

    return hash_len;
}

//
//  Return buffer size enough to hold serialized class "kdf alg info".
//
static size_t
vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(
        vscf_alg_info_der_serializer_t *alg_info_der_serializer, const vscf_kdf_alg_info_t *kdf_alg_info) {

    VSCF_ASSERT_PTR(alg_info_der_serializer);
    VSCF_ASSERT_PTR(kdf_alg_info);

    size_t params_len = vscf_alg_info_der_serializer_serialized_simple_alg_info_len(
            alg_info_der_serializer, vscf_kdf_alg_info_hash_alg_info(kdf_alg_info));

    size_t len =                     //  -- From ISO/IEC 18033-2 --
            1 + 1 +                  //  KDFAlgorithms ALGORITHM ::= {
            1 + 1 + 32 + params_len; //          { OID id-kdf-kdf1 PARMS HashFunction } |
                                     //          { OID id-kdf-kdf2 PARMS HashFunction } ,
                                     //          ... -- Expect additional algorithms --
                                     //  }
    return len;
}

//
//  Serialize class "kdf alg info".
//
static size_t
vscf_alg_info_der_serializer_serialize_kdf_alg_info(vscf_alg_info_der_serializer_t *alg_info_der_serializer,
        const vscf_kdf_alg_info_t *kdf_alg_info, vsc_buffer_t *out) {

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

    VSCF_ASSERT_PTR(alg_info_der_serializer);
    VSCF_ASSERT_PTR(kdf_alg_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_is_reverse(out));
    VSCF_ASSERT_PTR(alg_info_der_serializer->asn1_writer);

    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(alg_info_der_serializer, kdf_alg_info));

    //  Write HashFunction.
    size_t params_len = vscf_alg_info_der_serializer_serialize_simple_alg_info(
            alg_info_der_serializer, vscf_kdf_alg_info_hash_alg_info(kdf_alg_info), out);

    //  Write KeyDerivationFunction.
    vscf_impl_t *asn1_writer = alg_info_der_serializer->asn1_writer;
    vscf_asn1_writer_reset(asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    vsc_data_t kdf_oid = vscf_oid_from_alg_id(vscf_kdf_alg_info_alg_id(kdf_alg_info));
    size_t kdf_len = 0;
    kdf_len += vscf_asn1_writer_write_oid(asn1_writer, kdf_oid);
    kdf_len += vscf_asn1_writer_write_sequence(asn1_writer, kdf_len + params_len);
    VSCF_ASSERT(vscf_asn1_writer_error(asn1_writer) == vscf_SUCCESS);

    vsc_buffer_inc_used(out, kdf_len);

    return kdf_len + params_len;
}

//
//  Return buffer size enough to hold serialized class "cipher alg info".
//
static size_t
vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(
        vscf_alg_info_der_serializer_t *alg_info_der_serializer, const vscf_cipher_alg_info_t *cipher_alg_info) {

    VSCF_ASSERT_PTR(alg_info_der_serializer);
    VSCF_ASSERT_PTR(cipher_alg_info);

    size_t len =         //
            1 + 1 +      //  SymmetricAlgorithms ALGORITHM ::= {
            1 + 1 + 32 + //          { OID id-aes256-GCM PARMS NONCE } ,
                         //          ... -- Expect additional algorithms --
                         //  }
                         //
            2 + 16;      //  NONCE ::= OCTET STRING
    return len;
}

//
//  Serialize class "cipher alg info".
//
static size_t
vscf_alg_info_der_serializer_serialize_cipher_alg_info(vscf_alg_info_der_serializer_t *alg_info_der_serializer,
        const vscf_cipher_alg_info_t *cipher_alg_info, vsc_buffer_t *out) {

    //  SymmetricAlgorithms ALGORITHM ::= {
    //          { OID id-aes256-GCM PARMS NONCE } ,
    //          ... -- Expect additional algorithms --
    //  }
    //
    //  NONCE ::= OCTET STRING

    VSCF_ASSERT_PTR(alg_info_der_serializer);
    VSCF_ASSERT_PTR(cipher_alg_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_is_reverse(out));
    VSCF_ASSERT_PTR(alg_info_der_serializer->asn1_writer);

    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(alg_info_der_serializer, cipher_alg_info));

    vscf_impl_t *asn1_writer = alg_info_der_serializer->asn1_writer;
    vscf_asn1_writer_reset(asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    //  Write NONCE.
    size_t len = 0;
    len += vscf_asn1_writer_write_octet_str(asn1_writer, vscf_cipher_alg_info_nonce(cipher_alg_info));

    //  Write OID.
    vsc_data_t cipher_oid = vscf_oid_from_alg_id(vscf_cipher_alg_info_alg_id(cipher_alg_info));
    len += vscf_asn1_writer_write_oid(asn1_writer, cipher_oid);

    //  Write AlgorithmIdentifier SEQUENCE.
    len += vscf_asn1_writer_write_sequence(asn1_writer, len);
    VSCF_ASSERT(vscf_asn1_writer_error(asn1_writer) == vscf_SUCCESS);

    vsc_buffer_inc_used(out, len);

    return len;
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_alg_info_der_serializer_setup_defaults(vscf_alg_info_der_serializer_t *alg_info_der_serializer) {

    VSCF_ASSERT_PTR(alg_info_der_serializer);

    if (NULL == alg_info_der_serializer->asn1_writer) {
        vscf_alg_info_der_serializer_take_asn1_writer(alg_info_der_serializer, vscf_asn1wr_impl(vscf_asn1wr_new()));
    }

    return vscf_SUCCESS;
}

//
//  Return buffer size enough to hold serialized algorithm.
//
VSCF_PUBLIC size_t
vscf_alg_info_der_serializer_serialized_len(
        vscf_alg_info_der_serializer_t *alg_info_der_serializer, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info_der_serializer);
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
    case vscf_alg_id_ED25519:
    case vscf_alg_id_X25519:
        return vscf_alg_info_der_serializer_serialized_simple_alg_info_len(
                alg_info_der_serializer, (const vscf_simple_alg_info_t *)alg_info);

    case vscf_alg_id_KDF1:
    case vscf_alg_id_KDF2:
        return vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(
                alg_info_der_serializer, (const vscf_kdf_alg_info_t *)alg_info);

    case vscf_alg_id_AES256_GCM:
        return vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(
                alg_info_der_serializer, (const vscf_cipher_alg_info_t *)alg_info);

    case vscf_alg_id_NONE:
        VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
        break;
    }

    return 0;
}

//
//  Serialize algorithm info to buffer class.
//
VSCF_PUBLIC void
vscf_alg_info_der_serializer_serialize(
        vscf_alg_info_der_serializer_t *alg_info_der_serializer, const vscf_impl_t *alg_info, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(alg_info_der_serializer);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_alg_info_der_serializer_serialized_len(alg_info_der_serializer, alg_info));

    VSCF_ASSERT_PTR(alg_info_der_serializer->asn1_writer);

    vsc_buffer_t *der_out = vsc_buffer_new();
    vsc_buffer_use(der_out, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    vsc_buffer_switch_reverse_mode(der_out, true);

    //
    //  Route serialization.
    //
    vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
    case vscf_alg_id_SHA224:
    case vscf_alg_id_SHA256:
    case vscf_alg_id_SHA384:
    case vscf_alg_id_SHA512:
    case vscf_alg_id_RSA:
    case vscf_alg_id_ED25519:
    case vscf_alg_id_X25519:
        vscf_alg_info_der_serializer_serialize_simple_alg_info(
                alg_info_der_serializer, (const vscf_simple_alg_info_t *)alg_info, der_out);
        break;

    case vscf_alg_id_KDF1:
    case vscf_alg_id_KDF2:
        vscf_alg_info_der_serializer_serialize_kdf_alg_info(
                alg_info_der_serializer, (const vscf_kdf_alg_info_t *)alg_info, der_out);
        break;

    case vscf_alg_id_AES256_GCM:
        vscf_alg_info_der_serializer_serialize_cipher_alg_info(
                alg_info_der_serializer, (const vscf_cipher_alg_info_t *)alg_info, der_out);
        break;

    case vscf_alg_id_NONE:
        VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
        break;
    }

    //
    //  Adjust written bytes to the original buffer mode.
    //
    vsc_buffer_switch_reverse_mode(der_out, vsc_buffer_is_reverse(out));
    vsc_buffer_inc_used(out, vsc_buffer_len(der_out));

    vsc_buffer_destroy(&der_out);
}
