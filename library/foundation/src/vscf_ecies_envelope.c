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
#include "vscf_ecies_envelope_defs.h"
#include "vscf_alg.h"
#include "vscf_hmac.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_pkcs8_der_serializer.h"
#include "vscf_pkcs8_der_deserializer.h"
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
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_ecies_envelope_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_ecies_envelope_init_ctx(vscf_ecies_envelope_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_ecies_envelope_cleanup_ctx(vscf_ecies_envelope_t *self);

//
//  Return size of 'vscf_ecies_envelope_t'.
//
VSCF_PUBLIC size_t
vscf_ecies_envelope_ctx_size(void) {

    return sizeof(vscf_ecies_envelope_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_ecies_envelope_init(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_ecies_envelope_t));

    self->refcnt = 1;

    vscf_ecies_envelope_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_ecies_envelope_cleanup(vscf_ecies_envelope_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscf_ecies_envelope_cleanup_ctx(self);

        vscf_zeroize(self, sizeof(vscf_ecies_envelope_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_ecies_envelope_t *
vscf_ecies_envelope_new(void) {

    vscf_ecies_envelope_t *self = (vscf_ecies_envelope_t *) vscf_alloc(sizeof (vscf_ecies_envelope_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_ecies_envelope_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_ecies_envelope_delete(vscf_ecies_envelope_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_ecies_envelope_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_ecies_envelope_new ()'.
//
VSCF_PUBLIC void
vscf_ecies_envelope_destroy(vscf_ecies_envelope_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_ecies_envelope_t *self = *self_ref;
    *self_ref = NULL;

    vscf_ecies_envelope_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_ecies_envelope_t *
vscf_ecies_envelope_shallow_copy(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_ecies_envelope_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_ecies_envelope_init_ctx(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    //  Nothing to be done.
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_ecies_envelope_cleanup_ctx(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ecies_envelope_cleanup_properties(self);
}

//
//  Set "ephemeral public ke".
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_ephemeral_public_key(vscf_ecies_envelope_t *self, vscf_impl_t **ephemeral_public_key_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(ephemeral_public_key_ref);
    VSCF_ASSERT_PTR(*ephemeral_public_key_ref);

    self->ephemeral_public_key = *ephemeral_public_key_ref;
    *ephemeral_public_key_ref = NULL;
}

//
//  Set "kdf" algorithm information.
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_kdf(vscf_ecies_envelope_t *self, vscf_impl_t **kdf_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(kdf_ref);
    VSCF_ASSERT_PTR(*kdf_ref);

    self->kdf = *kdf_ref;
    *kdf_ref = NULL;
}

//
//  Set "mac" algorithm information.
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_mac(vscf_ecies_envelope_t *self, vscf_impl_t **mac_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(mac_ref);
    VSCF_ASSERT_PTR(*mac_ref);

    self->mac = *mac_ref;
    *mac_ref = NULL;
}

//
//  Set "mac" digest.
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_mac_digest(vscf_ecies_envelope_t *self, vsc_buffer_t **mac_digest_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(mac_digest_ref);
    VSCF_ASSERT_PTR(*mac_digest_ref);

    self->mac_digest = *mac_digest_ref;
    *mac_digest_ref = NULL;
}

//
//  Set "cipher" algorithm information.
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_cipher(vscf_ecies_envelope_t *self, vscf_impl_t **cipher_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher_ref);
    VSCF_ASSERT_PTR(*cipher_ref);

    self->cipher = *cipher_ref;
    *cipher_ref = NULL;
}

//
//  Set "encrypted content".
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_encrypted_content(vscf_ecies_envelope_t *self, vsc_buffer_t **encrypted_content_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(encrypted_content_ref);
    VSCF_ASSERT_PTR(*encrypted_content_ref);

    self->encrypted_content = *encrypted_content_ref;
    *encrypted_content_ref = NULL;
}

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

    vscf_pkcs8_der_serializer_t *pkcs8 = vscf_pkcs8_der_serializer_new();
    vscf_pkcs8_der_serializer_use_asn1_writer(pkcs8, vscf_asn1wr_impl(asn1wr));

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
    len += vscf_pkcs8_der_serializer_serialize_public_key_inplace(pkcs8, self->ephemeral_public_key, &error);

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
        vsc_buffer_inc_used(out, len);

        if (!vsc_buffer_is_reverse(out)) {
            vscf_asn1wr_finish(asn1wr);
        }
    }

    vscf_pkcs8_der_serializer_destroy(&pkcs8);
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
    vscf_ecies_envelope_cleanup_ctx(self);

    vscf_asn1rd_t *asn1rd = vscf_asn1rd_new();
    vscf_asn1rd_reset(asn1rd, data);

    vscf_alg_info_der_deserializer_t *alg_info_der_deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_use_asn1_reader(alg_info_der_deserializer, vscf_asn1rd_impl(asn1rd));

    vscf_pkcs8_der_deserializer_t *pkcs8 = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_use_asn1_reader(pkcs8, vscf_asn1rd_impl(asn1rd));

    vscf_asn1rd_read_sequence(asn1rd);

    //
    // Read: version.
    //
    const int version = vscf_asn1rd_read_int(asn1rd);

    //
    // Read: originator.
    //
    vscf_raw_key_t *originator_raw_key = vscf_pkcs8_der_deserializer_deserialize_public_key_inplace(pkcs8, &error);
    if (originator_raw_key) {
        self->ephemeral_public_key = vscf_alg_factory_create_public_key_from_raw_key(originator_raw_key);
        vscf_raw_key_destroy(&originator_raw_key);
    }

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

    vscf_pkcs8_der_deserializer_destroy(&pkcs8);
    vscf_alg_info_der_deserializer_destroy(&alg_info_der_deserializer);
    vscf_asn1rd_destroy(&asn1rd);

    if (vscf_error_has_error(&error)) {
        vscf_ecies_envelope_cleanup_ctx(self);
    }

    return vscf_error_status(&error);
}

//
//  Destroy internal objects.
//
VSCF_PUBLIC void
vscf_ecies_envelope_cleanup_properties(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->ephemeral_public_key);
    vscf_impl_destroy(&self->kdf);
    vscf_impl_destroy(&self->mac);
    vscf_impl_destroy(&self->cipher);
    vsc_buffer_destroy(&self->mac_digest);
    vsc_buffer_destroy(&self->encrypted_content);
}
