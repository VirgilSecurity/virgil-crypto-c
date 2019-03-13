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
//  This module contains 'pkcs8 der deserializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pkcs8_der_deserializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_oid.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1_tag.h"
#include "vscf_alg.h"
#include "vscf_asn1_reader.h"
#include "vscf_pkcs8_der_deserializer_defs.h"
#include "vscf_pkcs8_der_deserializer_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Deserialize Public Key by using internal ASN.1 reader.
//  Note, that caller code is responsible to reset ASN.1 reader with
//  an input buffer.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_der_deserializer_deserialize_public_key_inplace(vscf_pkcs8_der_deserializer_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);

    //  SubjectPublicKeyInfo ::= SEQUENCE {
    //          algorithm AlgorithmIdentifier,
    //          subjectPublicKey BIT STRING
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
    vscf_asn1_reader_read_sequence(self->asn1_reader);
    vsc_data_t key_oid = vscf_asn1_reader_read_oid(self->asn1_reader);

    if (vscf_asn1_reader_get_tag(self->asn1_reader) == vscf_asn1_tag_NULL) {
        vscf_asn1_reader_read_null(self->asn1_reader);
    }

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

    vscf_alg_id_t alg_id = vscf_oid_to_alg_id(key_oid);

    return vscf_raw_key_new_with_data(alg_id, public_key_bits);
}

//
//  Deserialize Public Key by using internal ASN.1 reader.
//  Note, that caller code is responsible to reset ASN.1 reader with
//  an input buffer.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_der_deserializer_deserialize_private_key_inplace(vscf_pkcs8_der_deserializer_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);

    //  PrivateKeyInfo ::= SEQUENCE {
    //          version Version,
    //          privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
    //          privateKey PrivateKey,
    //          attributes [0] IMPLICIT Attributes OPTIONAL
    //  }

    if (error && vscf_error_has_error(error)) {
        return NULL;
    }

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        return NULL;
    }

    //
    //  Read PrivateKeyInfo
    //
    vscf_asn1_reader_read_sequence(self->asn1_reader);

    //
    //  Read version
    //
    int version = vscf_asn1_reader_read_int(self->asn1_reader);

    //
    //  Read privateKeyAlgorithm
    //
    vscf_asn1_reader_read_sequence(self->asn1_reader);
    vsc_data_t key_oid = vscf_asn1_reader_read_oid(self->asn1_reader);

    if (vscf_asn1_reader_get_tag(self->asn1_reader) == vscf_asn1_tag_NULL) {
        vscf_asn1_reader_read_null(self->asn1_reader);
    }

    //
    //  Read privateKey
    //
    vsc_data_t private_key_bits = vscf_asn1_reader_read_octet_str(self->asn1_reader);

    //
    //  Finalize
    //
    if ((vscf_asn1_reader_has_error(self->asn1_reader)) || (version != 0)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY);
        return NULL;
    }

    vscf_alg_id_t alg_id = vscf_oid_to_alg_id(key_oid);

    return vscf_raw_key_new_with_data(alg_id, private_key_bits);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_pkcs8_der_deserializer_setup_defaults(vscf_pkcs8_der_deserializer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->asn1_reader) {
        vscf_pkcs8_der_deserializer_take_asn1_reader(self, vscf_asn1rd_impl(vscf_asn1rd_new()));
    }

    return vscf_status_SUCCESS;
}

//
//  Deserialize given public key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_der_deserializer_deserialize_public_key(
        vscf_pkcs8_der_deserializer_t *self, vsc_data_t public_key_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(public_key_data));
    VSCF_ASSERT_PTR(self->asn1_reader);

    vscf_asn1_reader_reset(self->asn1_reader, public_key_data);
    return vscf_pkcs8_der_deserializer_deserialize_public_key_inplace(self, error);
}

//
//  Deserialize given private key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_der_deserializer_deserialize_private_key(
        vscf_pkcs8_der_deserializer_t *self, vsc_data_t private_key_data, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(private_key_data));
    VSCF_ASSERT_PTR(self->asn1_reader);

    vscf_asn1_reader_reset(self->asn1_reader, private_key_data);
    return vscf_pkcs8_der_deserializer_deserialize_private_key_inplace(self, error);
}
