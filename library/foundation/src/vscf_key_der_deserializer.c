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
//  This module contains 'key der deserializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_der_deserializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_alg_info_der_deserializer.h"
#include "vscf_oid.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1_tag.h"
#include "vscf_asn1_reader.h"
#include "vscf_key_der_deserializer_defs.h"
#include "vscf_key_der_deserializer_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Deserialize PKCS#8 Private Key by using internal ASN.1 reader.
//
static vscf_raw_key_t *
vscf_key_der_deserializer_deserialize_pkcs8_private_key_inplace(vscf_key_der_deserializer_t *self, size_t seq_left_len,
        int version, vscf_error_t *error);

//
//  Deserialize SEC1 Private Key by using internal ASN.1 reader.
//
static vscf_raw_key_t *
vscf_key_der_deserializer_deserialize_sec1_private_key_inplace(vscf_key_der_deserializer_t *self, size_t seq_left_len,
        int version, vscf_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_key_der_deserializer_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_key_der_deserializer_init_ctx(vscf_key_der_deserializer_t *self) {

    VSCF_ASSERT_PTR(self);

    self->alg_info_der_deserializer = vscf_alg_info_der_deserializer_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_key_der_deserializer_cleanup_ctx(vscf_key_der_deserializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_deserializer_destroy(&self->alg_info_der_deserializer);
}

//
//  This method is called when interface 'asn1 reader' was setup.
//
VSCF_PRIVATE void
vscf_key_der_deserializer_did_setup_asn1_reader(vscf_key_der_deserializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_deserializer_use_asn1_reader(self->alg_info_der_deserializer, self->asn1_reader);
}

//
//  This method is called when interface 'asn1 reader' was released.
//
VSCF_PRIVATE void
vscf_key_der_deserializer_did_release_asn1_reader(vscf_key_der_deserializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_deserializer_release_asn1_reader(self->alg_info_der_deserializer);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_key_der_deserializer_setup_defaults(vscf_key_der_deserializer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->asn1_reader) {
        vscf_key_der_deserializer_take_asn1_reader(self, vscf_asn1rd_impl(vscf_asn1rd_new()));
    }
}

//
//  Deserialize Public Key by using internal ASN.1 reader.
//  Note, that caller code is responsible to reset ASN.1 reader with
//  an input buffer.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_key_der_deserializer_deserialize_public_key_inplace(vscf_key_der_deserializer_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);

    //
    //  Supported Public Key formats:
    //      - SubjectPublicKeyInfo for RSA, where params are NULL
    //      - SubjectPublicKeyInfo for Ed25519, where params are absent
    //      - SubjectPublicKeyInfo for ECP, where params are ECParameters
    //

    //  SubjectPublicKeyInfo ::= SEQUENCE {
    //          algorithm AlgorithmIdentifier,
    //          subjectPublicKey BIT STRING
    //  }

    //  ECParameters ::= CHOICE {
    //      namedCurve OBJECT IDENTIFIER
    //      -- implicitCurve NULL (not supported in this implementation)
    //      -- specifiedCurve SpecifiedECDomain
    //  }

    if (error && vscf_error_has_error(error)) {
        return NULL;
    }

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        return NULL;
    }

    //
    //  Read SubjectPublicKeyInfo
    //
    vscf_asn1_reader_read_sequence(self->asn1_reader);

    //
    //  Read algorithm
    //
    vscf_impl_t *alg_info = vscf_alg_info_der_deserializer_deserialize_inplace(self->alg_info_der_deserializer, error);
    if (NULL == alg_info) {
        return NULL;
    }

    const vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    vscf_impl_destroy(&alg_info);

    //
    //  Read subjectPublicKey
    //
    vsc_data_t public_key_bits = vscf_asn1_reader_read_bitstring_as_octet_str(self->asn1_reader);

    //
    //  Finalize
    //
    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PUBLIC_KEY);
        return NULL;
    }

    return vscf_raw_key_new_with_data(alg_id, public_key_bits);
}

//
//  Deserialize Private Key by using internal ASN.1 reader.
//  Note, that caller code is responsible to reset ASN.1 reader with
//  an input buffer.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_key_der_deserializer_deserialize_private_key_inplace(vscf_key_der_deserializer_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);

    //
    //  Supported Public Key formats:
    //      - PrivateKeyInfo (PKCS#8 - RFC 5208)
    //      - ECPrivateKey (SEC1 - RFC 5915)
    //
    //
    //  PrivateKeyInfo ::= SEQUENCE {
    //          version Version,
    //          privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
    //          privateKey PrivateKey,
    //          attributes [0] IMPLICIT Attributes OPTIONAL
    //  }
    //
    //  ECPrivateKey ::= SEQUENCE {
    //      version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    //      privateKey OCTET STRING,
    //      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    //      publicKey [1] BIT STRING OPTIONAL
    //  }
    //

    if (error && vscf_error_has_error(error)) {
        return NULL;
    }

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        return NULL;
    }

    //
    //  Read PrivateKeyInfo | ECPrivateKey
    //
    const size_t total_len = vscf_asn1_reader_left_len(self->asn1_reader);
    const size_t seq_len = vscf_asn1_reader_get_data_len(self->asn1_reader);

    vscf_asn1_reader_read_sequence(self->asn1_reader);

    //
    //  Read version - suitable for both keys
    //
    int version = vscf_asn1_reader_read_int(self->asn1_reader);

    //
    //  Inspect tag to distinguish between PrivateKeyInfo and ECPrivateKey
    //
    int distinguish_tag = vscf_asn1_reader_get_tag(self->asn1_reader);

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_DER_PRIVATE_KEY);
        return NULL;
    }

    const size_t left_len = vscf_asn1_reader_left_len(self->asn1_reader);
    VSCF_ASSERT(left_len < total_len);

    const size_t read_len = total_len - left_len;
    if (seq_len < read_len) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_DER_PRIVATE_KEY);
        return NULL;
    }

    const size_t seq_left_len = seq_len - read_len;
    if (distinguish_tag == vscf_asn1_tag_OCTET_STRING) {
        return vscf_key_der_deserializer_deserialize_sec1_private_key_inplace(self, seq_left_len, version, error);

    } else if (distinguish_tag == (vscf_asn1_tag_CONSTRUCTED | vscf_asn1_tag_SEQUENCE)) {
        return vscf_key_der_deserializer_deserialize_pkcs8_private_key_inplace(self, seq_left_len, version, error);

    } else {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_DER_PRIVATE_KEY);
        return NULL;
    }
}

//
//  Deserialize PKCS#8 Private Key by using internal ASN.1 reader.
//
static vscf_raw_key_t *
vscf_key_der_deserializer_deserialize_pkcs8_private_key_inplace(
        vscf_key_der_deserializer_t *self, size_t seq_left_len, int version, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT_PTR(seq_left_len >= vscf_asn1_reader_left_len(self->asn1_reader));

    //
    //  Check version
    //
    if (version != 0) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY);
        return NULL;
    }

    const size_t total_left_len = vscf_asn1_reader_left_len(self->asn1_reader);

    //
    //  Read privateKeyAlgorithm
    //
    vscf_asn1_reader_read_sequence(self->asn1_reader);
    vsc_data_t key_oid = vscf_asn1_reader_read_oid(self->asn1_reader);

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY);
        return NULL;
    }

    const vscf_oid_id_t alg_oid_id = vscf_oid_to_id(key_oid);
    if (alg_oid_id == vscf_oid_id_NONE) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    //
    //  Read privateKey
    //
    vscf_raw_key_t *raw_key = NULL;
    if (alg_oid_id == vscf_oid_id_EC_GENERIC_KEY) {
        vscf_asn1_reader_read_oid(self->asn1_reader);
        vscf_asn1_reader_read_tag(self->asn1_reader, vscf_asn1_tag_OCTET_STRING);
        raw_key = vscf_key_der_deserializer_deserialize_private_key_inplace(self, error);

    } else {
        vscf_asn1_reader_read_null_optional(self->asn1_reader);
        vsc_data_t private_key_data = vscf_asn1_reader_read_octet_str(self->asn1_reader);
        vscf_alg_id_t alg_id = vscf_oid_id_to_alg_id(alg_oid_id);
        raw_key = vscf_raw_key_new_with_data(alg_id, private_key_data);
    }

    if (raw_key == NULL) {
        return NULL;
    }

    //
    //  Read OPTIONAL attributes[0]
    //
    const size_t left_len = vscf_asn1_reader_left_len(self->asn1_reader);
    const size_t read_len = total_left_len - left_len;

    if (seq_left_len > read_len) {
        //
        //  OPTIONAL attributes[0] detected
        //
        const size_t attributes_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 0);
        if (attributes_len == 0) {
            VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY);
            goto error;
        }
        //  Ignore attributes.
        vscf_asn1_reader_read_data(self->asn1_reader, attributes_len);
    }

    //
    //  Check errors
    //
    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY);
        goto error;
    }

    return raw_key;

error:
    vscf_raw_key_destroy(&raw_key);
    return NULL;
}

//
//  Deserialize SEC1 Private Key by using internal ASN.1 reader.
//
static vscf_raw_key_t *
vscf_key_der_deserializer_deserialize_sec1_private_key_inplace(
        vscf_key_der_deserializer_t *self, size_t seq_left_len, int version, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_UNUSED(seq_left_len);

    //  ...
    //      privateKey OCTET STRING,
    //      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    //      publicKey [1] BIT STRING OPTIONAL
    //
    //  -- implementations that conform RFC 5915 MUST always include the parameters field
    //  -- implementations that conform RFC 5915 SHOULD always include the publicKey field
    //  -- the public key can always be recomputed

    //
    //  Check version
    //
    if (version != 1) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY);
        return NULL;
    }

    //
    //  Read privateKey
    //
    vsc_data_t private_key_data = vscf_asn1_reader_read_octet_str(self->asn1_reader);

    //
    //  Read OPTIONAL parameters[0] (it is required by RFC 5915)
    //
    const size_t params_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 0);
    if (params_len == 0) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY);
        return NULL;
    }

    vsc_data_t named_curve_oid = vscf_asn1_reader_read_oid(self->asn1_reader);
    const vscf_oid_id_t named_curve_id = vscf_oid_to_id(named_curve_oid);
    if (named_curve_id == vscf_oid_id_NONE) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY);
        return NULL;
    }

    //
    //  Read OPTIONAL publicKey (it is required by RFC 5915)
    //
    const size_t public_key_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 1);
    if (public_key_len == 0) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY);
        return NULL;
    }

    vsc_data_t public_key_bits = vscf_asn1_reader_read_bitstring_as_octet_str(self->asn1_reader);
    VSCF_UNUSED(public_key_bits);

    //
    //  Check errors
    //
    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY);
        return NULL;
    }

    const vscf_alg_id_t alg_id = vscf_oid_id_to_alg_id(named_curve_id);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    return vscf_raw_key_new_with_data(alg_id, private_key_data);
}

//
//  Deserialize given public key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_key_der_deserializer_deserialize_public_key(
        vscf_key_der_deserializer_t *self, vsc_data_t public_key_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(public_key_data));
    VSCF_ASSERT_PTR(self->asn1_reader);

    vscf_asn1_reader_reset(self->asn1_reader, public_key_data);
    return vscf_key_der_deserializer_deserialize_public_key_inplace(self, error);
}

//
//  Deserialize given private key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_key_der_deserializer_deserialize_private_key(
        vscf_key_der_deserializer_t *self, vsc_data_t private_key_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(private_key_data));
    VSCF_ASSERT_PTR(self->asn1_reader);

    vscf_asn1_reader_reset(self->asn1_reader, private_key_data);
    return vscf_key_der_deserializer_deserialize_private_key_inplace(self, error);
}
