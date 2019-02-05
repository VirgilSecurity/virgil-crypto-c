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
//  This module contains 'message info der serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_message_info_der_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_alg_info_der_serializer.h"
#include "vscf_alg_info_der_deserializer.h"
#include "vscf_oid.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_writer.h"
#include "vscf_message_info_der_serializer_defs.h"
#include "vscf_message_info_der_serializer_internal.h"
#include "vscf_key_recipient_info.h"
#include "vscf_password_recipient_info.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static size_t
vscf_message_info_der_serializer_serialized_custom_params_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialize_custom_params(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialized_key_recipient_info_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_key_recipient_info_t *key_recipient_info);

static size_t
vscf_message_info_der_serializer_serialize_key_recipient_info(
        vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_key_recipient_info_t *key_recipient_info);

static size_t
vscf_message_info_der_serializer_serialized_password_recipient_info_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_password_recipient_info_t *password_recipient_info);

static size_t
vscf_message_info_der_serializer_serialize_password_recipient_info(
        vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_password_recipient_info_t *password_recipient_info);

static size_t
vscf_message_info_der_serializer_serialized_recipient_infos_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialize_recipient_infos(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialized_encrypted_content_info_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialize_encrypted_content_info(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialized_enveloped_data_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialize_enveloped_data(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialized_cms_content_info_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialize_cms_content_info(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_message_info_der_serializer_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_init_ctx(vscf_message_info_der_serializer_t *message_info_der_serializer) {

    VSCF_ASSERT_PTR(message_info_der_serializer);

    message_info_der_serializer->alg_info_serializer = vscf_alg_info_der_serializer_new();
    message_info_der_serializer->alg_info_deserializer = vscf_alg_info_der_deserializer_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_cleanup_ctx(vscf_message_info_der_serializer_t *message_info_der_serializer) {

    VSCF_ASSERT_PTR(message_info_der_serializer);

    vscf_alg_info_der_serializer_destroy(&message_info_der_serializer->alg_info_serializer);
    vscf_alg_info_der_deserializer_destroy(&message_info_der_serializer->alg_info_deserializer);
}

//
//  This method is called when interface 'asn1 reader' was setup.
//
VSCF_PRIVATE vscf_error_t
vscf_message_info_der_serializer_did_setup_asn1_reader(
        vscf_message_info_der_serializer_t *message_info_der_serializer) {

    VSCF_ASSERT_PTR(message_info_der_serializer);

    vscf_alg_info_der_deserializer_use_asn1_reader(
            message_info_der_serializer->alg_info_deserializer, message_info_der_serializer->asn1_reader);

    return vscf_SUCCESS;
}

//
//  This method is called when interface 'asn1 reader' was released.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_release_asn1_reader(
        vscf_message_info_der_serializer_t *message_info_der_serializer) {

    VSCF_ASSERT_PTR(message_info_der_serializer);

    vscf_alg_info_der_deserializer_release_asn1_reader(message_info_der_serializer->alg_info_deserializer);
}

//
//  This method is called when interface 'asn1 writer' was setup.
//
VSCF_PRIVATE vscf_error_t
vscf_message_info_der_serializer_did_setup_asn1_writer(
        vscf_message_info_der_serializer_t *message_info_der_serializer) {

    VSCF_ASSERT_PTR(message_info_der_serializer);

    vscf_alg_info_der_serializer_use_asn1_writer(
            message_info_der_serializer->alg_info_serializer, message_info_der_serializer->asn1_writer);

    return vscf_SUCCESS;
}

//
//  This method is called when interface 'asn1 writer' was released.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_release_asn1_writer(
        vscf_message_info_der_serializer_t *message_info_der_serializer) {

    VSCF_ASSERT_PTR(message_info_der_serializer);

    vscf_alg_info_der_serializer_release_asn1_writer(message_info_der_serializer->alg_info_serializer);
}

static size_t
vscf_message_info_der_serializer_serialized_custom_params_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    //  TODO: This is STUB. Implement me.

    return 0;
}

static size_t
vscf_message_info_der_serializer_serialize_custom_params(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info) {

    //  VirgilCustomParams ::= SET SIZE (1..MAX) OF KeyValue
    //
    //  KeyValue ::= SEQUENCE {
    //      key Key,
    //      val Value
    //  }
    //
    //  Key ::= UTF8String
    //
    //  Value ::= CHOICE {
    //      int [0] EXPLICIT INTEGER,
    //      str [1] EXPLICIT UTF8String,
    //      data [2] EXPLICIT OCTET STRING
    //  }

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    //  TODO: This is STUB. Implement me.

    return 0;
}

static size_t
vscf_message_info_der_serializer_serialized_key_recipient_info_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_key_recipient_info_t *key_recipient_info) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(key_recipient_info);

    size_t len = 1 + 1 + 3 +       //  KeyTransRecipientInfo ::= SEQUENCE {
                 1 + 1 + 1 +       //      version CMSVersion, -- always set to 0 or 2
                 1 + 1 + 64 +      //      rid RecipientIdentifier,
                 1 + 1 + 32 +      //      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
                 1 + 1 + 2 + 1024; //      encryptedKey EncryptedKey }

    return len;
}

static size_t
vscf_message_info_der_serializer_serialize_key_recipient_info(
        vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_key_recipient_info_t *key_recipient_info) {

    //  KeyTransRecipientInfo ::= SEQUENCE {
    //      version CMSVersion, -- always set to 0 or 2
    //      rid RecipientIdentifier,
    //      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    //      encryptedKey EncryptedKey }
    //
    //  RecipientIdentifier ::= CHOICE {
    //      issuerAndSerialNumber IssuerAndSerialNumber,
    //      subjectKeyIdentifier [0] SubjectKeyIdentifier }
    //
    //  SubjectKeyIdentifier ::= OCTET STRING
    //
    //  EncryptedKey ::= OCTET STRING

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(key_recipient_info);

    size_t key_recipient_info_len = 0;

    //
    //  Write: encryptedKey.
    //
    key_recipient_info_len += vscf_asn1_writer_write_octet_str(
            message_info_der_serializer->asn1_writer, vscf_key_recipient_info_encrypted_key(key_recipient_info));

    //
    //  Write: keyEncryptionAlgorithm.
    //
    const vscf_impl_t *key_encryption_alg_info = vscf_key_recipient_info_key_encryption_algorithm(key_recipient_info);
    key_recipient_info_len += vscf_alg_info_der_serializer_serialize_inplace(
            message_info_der_serializer->alg_info_serializer, key_encryption_alg_info);

    //
    //  Write: rid.
    //
    size_t rid_len = 0;
    rid_len += vscf_asn1_writer_write_octet_str(
            message_info_der_serializer->asn1_writer, vscf_key_recipient_info_recipient_id(key_recipient_info));
    rid_len += vscf_asn1_writer_write_context_tag(message_info_der_serializer->asn1_writer, 0, rid_len);

    key_recipient_info_len += rid_len;

    //
    //  Write: version {2}
    //
    key_recipient_info_len += vscf_asn1_writer_write_int(message_info_der_serializer->asn1_writer, 2);

    //
    //  Write: KeyTransRecipientInfo
    //
    key_recipient_info_len +=
            vscf_asn1_writer_write_sequence(message_info_der_serializer->asn1_writer, key_recipient_info_len);

    return key_recipient_info_len;
}

static size_t
vscf_message_info_der_serializer_serialized_password_recipient_info_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_password_recipient_info_t *password_recipient_info) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(password_recipient_info);

    size_t len = 1 + 2 +       //  PasswordRecipientInfo ::= SEQUENCE {
                 1 + 1 + 1 +   //    version CMSVersion, -- Always set to 0
                 0 +           //    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL, -- not used
                 1 + 1 + 127 + //    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
                 1 + 1 + 32;   //    encryptedKey EncryptedKey }

    return len;
}

static size_t
vscf_message_info_der_serializer_serialize_password_recipient_info(
        vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_password_recipient_info_t *password_recipient_info) {

    //  PasswordRecipientInfo ::= SEQUENCE {
    //    version CMSVersion, -- Always set to 0
    //    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
    //                                 OPTIONAL, -- not used
    //    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    //    encryptedKey EncryptedKey }


    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(password_recipient_info);

    size_t password_recipient_info_len = 0;

    //
    //  Write: encryptedKey.
    //
    password_recipient_info_len += vscf_asn1_writer_write_octet_str(message_info_der_serializer->asn1_writer,
            vscf_password_recipient_info_encrypted_key(password_recipient_info));

    //
    //  Write: keyEncryptionAlgorithm.
    //
    const vscf_impl_t *key_encryption_alg_info =
            vscf_password_recipient_info_key_encryption_algorithm(password_recipient_info);
    password_recipient_info_len += vscf_alg_info_der_serializer_serialize_inplace(
            message_info_der_serializer->alg_info_serializer, key_encryption_alg_info);

    //
    //  Write: version {0}
    //
    password_recipient_info_len += vscf_asn1_writer_write_int(message_info_der_serializer->asn1_writer, 0);

    //
    //  Write: KeyTransRecipientInfo
    //
    password_recipient_info_len +=
            vscf_asn1_writer_write_sequence(message_info_der_serializer->asn1_writer, password_recipient_info_len);

    return password_recipient_info_len;
}

static size_t
vscf_message_info_der_serializer_serialized_recipient_infos_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info) {

    //  RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
    //
    //  RecipientInfo ::= CHOICE {
    //      ktri KeyTransRecipientInfo,
    //      kari [1] KeyAgreeRecipientInfo, -- not supported
    //      kekri [2] KEKRecipientInfo, -- not supported
    //      pwri [3] PasswordRecipientInfo,
    //      ori [4] OtherRecipientInfo -- not supported
    //  }

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    size_t len = 1 + 1 + 8; //  RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

    //  ktri KeyTransRecipientInfo,
    for (const vscf_key_recipient_info_list_t *list = vscf_message_info_key_recipient_info_list(message_info);
            (list != NULL) && vscf_key_recipient_info_list_has_item(list);
            list = vscf_key_recipient_info_list_next(list)) {

        const vscf_key_recipient_info_t *info = vscf_key_recipient_info_list_item(list);


        len += vscf_message_info_der_serializer_serialized_key_recipient_info_len(message_info_der_serializer, info);
    }

    // pwri [3] PasswordRecipientInfo,
    for (const vscf_password_recipient_info_list_t *list = vscf_message_info_password_recipient_info_list(message_info);
            (list != NULL) && vscf_password_recipient_info_list_has_item(list);
            list = vscf_password_recipient_info_list_next(list)) {

        const vscf_password_recipient_info_t *info = vscf_password_recipient_info_list_item(list);

        len += 1 + 3;
        len += vscf_message_info_der_serializer_serialized_password_recipient_info_len(
                message_info_der_serializer, info);
    }

    return len;
}

static size_t
vscf_message_info_der_serializer_serialize_recipient_infos(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info) {

    //  RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
    //
    //  RecipientInfo ::= CHOICE {
    //      ktri KeyTransRecipientInfo,
    //      kari [1] KeyAgreeRecipientInfo, -- not supported
    //      kekri [2] KEKRecipientInfo, -- not supported
    //      pwri [3] PasswordRecipientInfo,
    //      ori [4] OtherRecipientInfo -- not supported
    //  }

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    size_t recipient_infos_len = 0;

    for (const vscf_key_recipient_info_list_t *list = vscf_message_info_key_recipient_info_list(message_info);
            (list != NULL) && vscf_key_recipient_info_list_has_item(list);
            list = vscf_key_recipient_info_list_next(list)) {

        const vscf_key_recipient_info_t *info = vscf_key_recipient_info_list_item(list);

        size_t info_len =
                vscf_message_info_der_serializer_serialize_key_recipient_info(message_info_der_serializer, info);

        recipient_infos_len += info_len;
    }

    for (const vscf_password_recipient_info_list_t *list = vscf_message_info_password_recipient_info_list(message_info);
            (list != NULL) && vscf_password_recipient_info_list_has_item(list);
            list = vscf_password_recipient_info_list_next(list)) {

        const vscf_password_recipient_info_t *info = vscf_password_recipient_info_list_item(list);

        size_t info_len = 0;

        info_len +=
                vscf_message_info_der_serializer_serialize_password_recipient_info(message_info_der_serializer, info);

        info_len += vscf_asn1_writer_write_context_tag(message_info_der_serializer->asn1_writer, 3, info_len);

        recipient_infos_len += info_len;
    }

    recipient_infos_len += vscf_asn1_writer_write_set(message_info_der_serializer->asn1_writer, recipient_infos_len);

    return recipient_infos_len;
}

static size_t
vscf_message_info_der_serializer_serialized_encrypted_content_info_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    size_t len = 1 + 1 +      //  EncryptedContentInfo ::= SEQUENCE {
                 1 + 1 + 9 +  //      contentType ContentType, -- always PKCS#7 'data' OID
                 1 + 1 + 32 + //      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
                 0;           //      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used }

    return len;
}

static size_t
vscf_message_info_der_serializer_serialize_encrypted_content_info(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info) {

    //  EncryptedContentInfo ::= SEQUENCE {
    //      contentType ContentType, -- always PKCS#7 'data' OID
    //      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    //      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
    //  }
    //
    //  ContentType ::= OBJECT IDENTIFIER
    //  ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
    //  EncryptedContent ::= OCTET STRING

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    size_t encrypted_content_info_len = 0;

    //
    //  Write: contentEncryptionAlgorithm.
    //
    const vscf_impl_t *content_encryption_alg_info = vscf_message_info_data_encryption_alg_info(message_info);
    encrypted_content_info_len += vscf_alg_info_der_serializer_serialize_inplace(
            message_info_der_serializer->alg_info_serializer, content_encryption_alg_info);

    //
    //  Write: contentType.
    //
    encrypted_content_info_len += vscf_asn1_writer_write_oid(
            message_info_der_serializer->asn1_writer, vscf_oid_from_id(vscf_oid_id_CMS_DATA));

    //
    //  Write: EncryptedContentInfo.
    //
    encrypted_content_info_len +=
            vscf_asn1_writer_write_sequence(message_info_der_serializer->asn1_writer, encrypted_content_info_len);

    return encrypted_content_info_len;
}

static size_t
vscf_message_info_der_serializer_serialized_enveloped_data_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    size_t recipient_infos_len =
            vscf_message_info_der_serializer_serialized_recipient_infos_len(message_info_der_serializer, message_info);

    size_t encrypted_content_info_len = vscf_message_info_der_serializer_serialized_encrypted_content_info_len(
            message_info_der_serializer, message_info);

    size_t len = 1 + 1 + 8 +                  //  EnvelopedData ::= SEQUENCE {
                 1 + 1 + 1 +                  //      version CMSVersion,
                 0 +                          //      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
                 recipient_infos_len +        //      recipientInfos RecipientInfos,
                 encrypted_content_info_len + //      encryptedContentInfo EncryptedContentInfo,
                 0; //      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used }

    return len;
}

static size_t
vscf_message_info_der_serializer_serialize_enveloped_data(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info) {

    //  EnvelopedData ::= SEQUENCE {
    //      version CMSVersion,
    //      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
    //      recipientInfos RecipientInfos,
    //      encryptedContentInfo EncryptedContentInfo,
    //      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
    //  }
    //
    //  CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);


    //
    //  Define version.
    //
    int enveloped_data_version = 2;
    const vscf_password_recipient_info_list_t *pwri_list = vscf_message_info_password_recipient_info_list(message_info);
    if ((pwri_list != NULL) && vscf_password_recipient_info_list_has_item(pwri_list)) {
        enveloped_data_version = 3;
    }

    //
    //  Write EnvelopedData.
    //
    size_t enveloped_data_len = 0;

    enveloped_data_len += vscf_message_info_der_serializer_serialize_encrypted_content_info(
            message_info_der_serializer, message_info);

    enveloped_data_len +=
            vscf_message_info_der_serializer_serialize_recipient_infos(message_info_der_serializer, message_info);

    enveloped_data_len += vscf_asn1_writer_write_int(message_info_der_serializer->asn1_writer, enveloped_data_version);

    enveloped_data_len += vscf_asn1_writer_write_sequence(message_info_der_serializer->asn1_writer, enveloped_data_len);

    return enveloped_data_len;
}

static size_t
vscf_message_info_der_serializer_serialized_cms_content_info_len(
        const vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    size_t enveloped_data_len =
            vscf_message_info_der_serializer_serialized_enveloped_data_len(message_info_der_serializer, message_info);

    size_t len = 1 + 1 + 8 +         //  ContentInfo ::= SEQUENCE {
                 1 + 1 + 9 +         //      contentType ContentType,
                 enveloped_data_len; //      content [0] EXPLICIT ANY DEFINED BY contentType }

    return len;
}

static size_t
vscf_message_info_der_serializer_serialize_cms_content_info(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info) {

    //  ContentInfo ::= SEQUENCE {
    //      contentType ContentType,
    //      content [0] EXPLICIT ANY DEFINED BY contentType
    //  }
    //
    //  ContentType ::= OBJECT IDENTIFIER

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    size_t content_info_len = 0;
    content_info_len +=
            vscf_message_info_der_serializer_serialize_enveloped_data(message_info_der_serializer, message_info);

    content_info_len +=
            vscf_asn1_writer_write_context_tag(message_info_der_serializer->asn1_writer, 0, content_info_len);

    content_info_len += vscf_asn1_writer_write_oid(
            message_info_der_serializer->asn1_writer, vscf_oid_from_id(vscf_oid_id_CMS_ENVELOPED_DATA));

    content_info_len += vscf_asn1_writer_write_sequence(message_info_der_serializer->asn1_writer, content_info_len);

    return content_info_len;
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_message_info_der_serializer_setup_defaults(vscf_message_info_der_serializer_t *message_info_der_serializer) {

    VSCF_ASSERT_PTR(message_info_der_serializer);

    if (NULL == message_info_der_serializer->asn1_reader) {
        vscf_message_info_der_serializer_take_asn1_reader(
                message_info_der_serializer, vscf_asn1rd_impl(vscf_asn1rd_new()));
    }

    if (NULL == message_info_der_serializer->asn1_writer) {
        vscf_message_info_der_serializer_take_asn1_writer(
                message_info_der_serializer, vscf_asn1wr_impl(vscf_asn1wr_new()));
    }

    return vscf_SUCCESS;
}

//
//  Return buffer size enough to hold serialized message info.
//
VSCF_PUBLIC size_t
vscf_message_info_der_serializer_serialized_len(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    size_t cms_content_info_len =
            vscf_message_info_der_serializer_serialized_cms_content_info_len(message_info_der_serializer, message_info);

    size_t custom_params_len =
            vscf_message_info_der_serializer_serialized_custom_params_len(message_info_der_serializer, message_info);

    size_t len = 1 + 1 + 8 +            //  VirgilMessageInfo ::= SEQUENCE {
                 1 + 1 + 1 +            //      version ::= INTEGER { v0(0) },
                 cms_content_info_len + //      cmsContent ContentInfo, -- Imports from RFC 5652
                 custom_params_len;     //      customParams [0] IMPLICIT VirgilCustomParams OPTIONAL }

    return len;
}

//
//  Serialize class "message info".
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_serialize(vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info, vsc_buffer_t *out) {

    //  VirgilMessageInfo ::= SEQUENCE {
    //      version ::= INTEGER { v0(0) },
    //      cmsContent ContentInfo, -- Imports from RFC 5652
    //      customParams [0] IMPLICIT VirgilCustomParams OPTIONAL
    //  }

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(out));
    VSCF_ASSERT_PTR(message_info_der_serializer->asn1_writer);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_message_info_der_serializer_serialized_len(message_info_der_serializer, message_info));

    bool stored_out_mode = vsc_buffer_is_reverse(out);
    vsc_buffer_switch_reverse_mode(out, true);
    vscf_asn1_writer_reset(
            message_info_der_serializer->asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    size_t message_info_len = 0;
    message_info_len +=
            vscf_message_info_der_serializer_serialize_custom_params(message_info_der_serializer, message_info);

    message_info_len +=
            vscf_message_info_der_serializer_serialize_cms_content_info(message_info_der_serializer, message_info);

    message_info_len += vscf_asn1_writer_write_int(message_info_der_serializer->asn1_writer, 0);

    message_info_len += vscf_asn1_writer_write_sequence(message_info_der_serializer->asn1_writer, message_info_len);

    vsc_buffer_inc_used(out, message_info_len);
    vscf_asn1_writer_release(message_info_der_serializer->asn1_writer);

    vsc_buffer_switch_reverse_mode(out, stored_out_mode);
}

//
//  Deserialize class "message info".
//
VSCF_PUBLIC const vscf_message_info_t *
vscf_message_info_der_serializer_deserialize(vscf_message_info_der_serializer_t *message_info_der_serializer,
        vsc_data_t data, const vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_UNUSED(error);

    //  TODO: This is STUB. Implement me.

    return NULL;
}
