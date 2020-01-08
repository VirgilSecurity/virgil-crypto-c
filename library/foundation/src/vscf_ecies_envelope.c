//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
//  Provides function to process ECIES envelope ASN.1 structure:
//
//      ECIES-Envelope-Schema DEFINITIONS EXPLICIT TAGS ::=
//      BEGIN
//
//         IMPORTS
//
//           -- Imports from RFC 5280, Appendix A.1
//              AlgorithmIdentifier
//                  FROM PKIX1Explicit88
//                      { iso(1) identified-organization(3) dod(6)
//                        internet(1) security(5) mechanisms(5) pkix(7)
//                        mod(0) pkix1-explicit(18) }
//
//           -- Imports from ISO/IEC 18033-2, Appendix B
//              KeyDerivationFunction
//                  FROM AlgorithmObjectIdentifiers
//                      { iso(1) standard(0) encryption-algorithms(18033) part(2)
//                        asn1-module(0) algorithm-object-identifiers(0) };
//
//
//          ECIES-Envelope ::= SEQUENCE {
//              version          INTEGER { v0(0) },
//              originator       OriginatorPublicKey,
//              kdf              KeyDerivationFunction,
//              hmac             DigestInfo,
//              encryptedContent EncryptedContentInfo
//          }
//
//          OriginatorPublicKey ::= SEQUENCE {
//              algorithm AlgorithmIdentifier,
//              publicKey BIT STRING
//          }
//
//          DigestInfo ::= SEQUENCE {
//              digestAlgorithm    DigestAlgorithmIdentifier,
//              digest             Digest
//          }
//
//          DigestAlgorithmIdentifier ::= AlgorithmIdentifier
//
//          Digest ::= OCTET STRING
//
//          EncryptedContentInfo ::= SEQUENCE {
//              contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//              encryptedContent EncryptedContent
//          }
//
//          ContentEncryptionAlgorithmIdentifier :: = AlgorithmIdentifier
//
//          EncryptedContent ::= OCTET STRING
//      END
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ecies_envelope.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_alg.h"
#include "vscf_hmac.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_key_asn1_serializer.h"
#include "vscf_key_asn1_deserializer.h"
#include "vscf_alg_info_der_serializer.h"
#include "vscf_alg_info_der_deserializer.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_alg_factory.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return size of 'vscf_ecies_envelope_t'.
//
VSCF_PUBLIC size_t
vscf_ecies_envelope_ctx_size(void) {

    return sizeof(vscf_ecies_envelope_t);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Return buffer length required to hold packed ECIES-Envelope.
//
VSCF_PUBLIC size_t
vscf_ecies_envelope_packed_len(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ephemeral_public_key);
    VSCF_ASSERT_PTR(self->kdf);
    VSCF_ASSERT_PTR(self->mac);
    VSCF_ASSERT_PTR(self->mac_digest);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->encrypted_content);

    return 256 + vsc_buffer_len(self->encrypted_content) + 32;
}

//
//  Pack properties to the ASN.1 structure.
//
//  ECIES-Envelope ::= SEQUENCE {
//      version INTEGER { v0(0) },
//      originator OriginatorPublicKey,
//      kdf KeyDerivationFunction,
//      hmac DigestInfo,
//      encryptedContent EncryptedContentInfo }
//
//  OriginatorPublicKey ::= SEQUENCE {
//      algorithm AlgorithmIdentifier,
//      publicKey BIT STRING }
//
//  DigestInfo ::= SEQUENCE {
//      digestAlgorithm DigestAlgorithmIdentifier,
//      digest Digest }
//
//  DigestAlgorithmIdentifier ::= AlgorithmIdentifier
//  Digest ::= OCTET STRING
//
//  EncryptedContentInfo ::= SEQUENCE {
//      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//      encryptedContent EncryptedContent }
//
//  ContentEncryptionAlgorithmIdentifier :: = AlgorithmIdentifier
//  EncryptedContent ::= OCTET STRING
//
VSCF_PUBLIC vscf_status_t
vscf_ecies_envelope_pack(vscf_ecies_envelope_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ephemeral_public_key);
    VSCF_ASSERT_PTR(self->kdf);
    VSCF_ASSERT_PTR(self->mac);
    VSCF_ASSERT_PTR(self->mac_digest);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->encrypted_content);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ecies_envelope_packed_len(self));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_asn1wr_t *asn1wr = vscf_asn1wr_new();
    vscf_asn1wr_reset(asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    vscf_alg_info_der_serializer_t *alg_info_der_serializer = vscf_alg_info_der_serializer_new();
    vscf_alg_info_der_serializer_use_asn1_writer(alg_info_der_serializer, vscf_asn1wr_impl(asn1wr));

    vscf_key_asn1_serializer_t *key_asn1_serializer = vscf_key_asn1_serializer_new();
    vscf_key_asn1_serializer_use_asn1_writer(key_asn1_serializer, vscf_asn1wr_impl(asn1wr));

    size_t len = 0;

    //
    //  Write: encryptedContentInfo.
    //
    size_t encrypted_content_info_len = 0;

    vscf_impl_t *cipher_info = vscf_alg_produce_alg_info(self->cipher);
    encrypted_content_info_len += vscf_asn1wr_write_octet_str(asn1wr, vsc_buffer_data(self->encrypted_content));
    encrypted_content_info_len += vscf_alg_info_der_serializer_serialize_inplace(alg_info_der_serializer, cipher_info);
    encrypted_content_info_len += vscf_asn1wr_write_sequence(asn1wr, encrypted_content_info_len);
    vscf_impl_destroy(&cipher_info);

    len += encrypted_content_info_len;

    //
    //  Write: mac.
    //
    size_t digest_info_len = 0;

    vscf_hash_based_alg_info_t *mac_info = (vscf_hash_based_alg_info_t *)vscf_alg_produce_alg_info(self->mac);
    const vscf_impl_t *hmac_hash_info = vscf_hash_based_alg_info_hash_alg_info(mac_info);

    digest_info_len += vscf_asn1wr_write_octet_str(asn1wr, vsc_buffer_data(self->mac_digest));
    digest_info_len += vscf_alg_info_der_serializer_serialize_inplace(alg_info_der_serializer, hmac_hash_info);
    digest_info_len += vscf_asn1wr_write_sequence(asn1wr, digest_info_len);
    vscf_hash_based_alg_info_destroy(&mac_info);

    len += digest_info_len;

    //
    //  Write: kdf.
    //
    vscf_impl_t *kdf_info = vscf_alg_produce_alg_info(self->kdf);
    len += vscf_alg_info_der_serializer_serialize_inplace(alg_info_der_serializer, kdf_info);
    vscf_impl_destroy(&kdf_info);

    //
    // Write: originator.
    //
    len += vscf_key_asn1_serializer_serialize_public_key_inplace(
            key_asn1_serializer, self->ephemeral_public_key, &error);

    //
    // Write: version.
    //
    len += vscf_asn1wr_write_int(asn1wr, 0);
    len += vscf_asn1wr_write_sequence(asn1wr, len);

    vscf_status_t status = vscf_status_SUCCESS;

    if (vscf_asn1wr_has_error(asn1wr)) {
        status = vscf_asn1wr_status(asn1wr);
    }

    if (vscf_error_has_error(&error)) {
        status = vscf_error_status(&error);
    }

    if (status == vscf_status_SUCCESS) {
        vscf_asn1wr_finish(asn1wr, vsc_buffer_is_reverse(out));
        vsc_buffer_inc_used(out, len);
    }

    vscf_key_asn1_serializer_destroy(&key_asn1_serializer);
    vscf_alg_info_der_serializer_destroy(&alg_info_der_serializer);
    vscf_asn1wr_destroy(&asn1wr);

    return status;
}

//
//  Unpack ECIES-Envelope ASN.1 structure.
//  Unpacked data can be accessed thru getters.
//
VSCF_PUBLIC vscf_status_t
vscf_ecies_envelope_unpack(vscf_ecies_envelope_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Remove previous data.
    //
    vscf_ecies_envelope_cleanup_properties(self);

    vscf_asn1rd_t *asn1rd = vscf_asn1rd_new();
    vscf_asn1rd_reset(asn1rd, data);

    vscf_alg_info_der_deserializer_t *alg_info_der_deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_use_asn1_reader(alg_info_der_deserializer, vscf_asn1rd_impl(asn1rd));

    vscf_key_asn1_deserializer_t *key_asn1_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_use_asn1_reader(key_asn1_deserializer, vscf_asn1rd_impl(asn1rd));

    vscf_asn1rd_read_sequence(asn1rd);

    //
    // Read: version.
    //
    const int version = vscf_asn1rd_read_int(asn1rd);

    //
    // Read: originator.
    //
    self->ephemeral_public_key =
            vscf_key_asn1_deserializer_deserialize_public_key_inplace(key_asn1_deserializer, &error);

    //
    // Read: kdf.
    //
    vscf_impl_t *kdf_info = vscf_alg_info_der_deserializer_deserialize_inplace(alg_info_der_deserializer, &error);
    if (kdf_info) {
        self->kdf = vscf_alg_factory_create_kdf_from_info(kdf_info);
        vscf_impl_destroy(&kdf_info);
    }

    //
    // Read: hmac.
    //
    vscf_asn1rd_read_sequence(asn1rd);
    vscf_impl_t *hmac_hash_info = vscf_alg_info_der_deserializer_deserialize_inplace(alg_info_der_deserializer, &error);

    if (hmac_hash_info != NULL) {
        vscf_hmac_t *hmac = vscf_hmac_new();
        vscf_hmac_take_hash(hmac, vscf_alg_factory_create_hash_from_info(hmac_hash_info));
        self->mac = vscf_hmac_impl(hmac);
        vscf_impl_destroy(&hmac_hash_info);
    }

    vsc_data_t mac_digest = vscf_asn1rd_read_octet_str(asn1rd);
    if (mac_digest.len > 0) {
        self->mac_digest = vsc_buffer_new_with_data(mac_digest);
    }

    //
    // Read: encryptedContentInfo.
    //
    vscf_asn1rd_read_sequence(asn1rd);
    vscf_impl_t *cipher_info = vscf_alg_info_der_deserializer_deserialize_inplace(alg_info_der_deserializer, &error);
    if (cipher_info) {
        self->cipher = vscf_alg_factory_create_cipher_from_info(cipher_info);
        vscf_impl_destroy(&cipher_info);
    }

    vsc_data_t encrypted_content = vscf_asn1rd_read_octet_str(asn1rd);
    if (encrypted_content.len > 0) {
        self->encrypted_content = vsc_buffer_new_with_data(encrypted_content);
    }

    //
    //  Handle errors.
    //
    if (version != 0) {
        vscf_error_update(&error, vscf_status_ERROR_BAD_ENCRYPTED_DATA);
    } else {
        vscf_error_update(&error, vscf_asn1rd_status(asn1rd));
    }

    vscf_key_asn1_deserializer_destroy(&key_asn1_deserializer);
    vscf_alg_info_der_deserializer_destroy(&alg_info_der_deserializer);
    vscf_asn1rd_destroy(&asn1rd);

    if (vscf_error_has_error(&error)) {
        vscf_ecies_envelope_cleanup_properties(self);
    }

    return vscf_error_status(&error);
}

//
//  Destroy internal objects.
//
VSCF_PUBLIC void
vscf_ecies_envelope_cleanup_properties(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_raw_public_key_destroy(&self->ephemeral_public_key);
    vscf_impl_destroy(&self->kdf);
    vscf_impl_destroy(&self->mac);
    vscf_impl_destroy(&self->cipher);
    vsc_buffer_destroy(&self->mac_digest);
    vsc_buffer_destroy(&self->encrypted_content);
}
