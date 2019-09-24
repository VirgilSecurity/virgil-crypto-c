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
#include "vscf_asn1_tag.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_alg_info_der_serializer.h"
#include "vscf_alg_info_der_deserializer.h"
#include "vscf_oid.h"
#include "vscf_message_info_custom_params_internal.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_writer.h"
#include "vscf_message_info_der_serializer_defs.h"
#include "vscf_message_info_der_serializer_internal.h"
#include "vscf_message_info_custom_params.h"
#include "vscf_key_recipient_info.h"
#include "vscf_password_recipient_info.h"
#include "vscf_signer_info.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <mbedtls/asn1.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return size in bytes enough to hold serialized custom params.
//
static size_t
vscf_message_info_der_serializer_serialized_custom_params_len(const vscf_message_info_der_serializer_t *self,
        const vscf_message_info_custom_params_t *custom_params);

//
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
//
static size_t
vscf_message_info_der_serializer_serialize_custom_params(vscf_message_info_der_serializer_t *self,
        const vscf_message_info_custom_params_t *custom_params);

//
//  Serialize signed data info with internal ASN.1 writer.
//
//  VirgilSignedDataInfo ::= SEQUENCE {
//      version INTEGER { v0(0) },
//      digestAlgorithm AlgorithmIdentifier,
//      dataSize INTEGER,
//      signedParams [0] EXPLICIT VirgilCustomParams OPTIONAL
//  }
//
static size_t
vscf_message_info_der_serializer_serialize_signed_data_info_inplace(vscf_message_info_der_serializer_t *self,
        const vscf_signed_data_info_t *signed_data_info);

static size_t
vscf_message_info_der_serializer_serialized_key_recipient_info_len(const vscf_message_info_der_serializer_t *self,
        const vscf_key_recipient_info_t *key_recipient_info);

//
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
//
static size_t
vscf_message_info_der_serializer_serialize_key_recipient_info(vscf_message_info_der_serializer_t *self,
        const vscf_key_recipient_info_t *key_recipient_info);

static size_t
vscf_message_info_der_serializer_serialized_password_recipient_info_len(const vscf_message_info_der_serializer_t *self,
        const vscf_password_recipient_info_t *password_recipient_info);

//
//  PasswordRecipientInfo ::= SEQUENCE {
//      version CMSVersion, -- Always set to 0
//      keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
//                                 OPTIONAL, -- not used
//      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//      encryptedKey EncryptedKey
//  }
//
static size_t
vscf_message_info_der_serializer_serialize_password_recipient_info(vscf_message_info_der_serializer_t *self,
        const vscf_password_recipient_info_t *password_recipient_info);

static size_t
vscf_message_info_der_serializer_serialized_recipient_infos_len(const vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info);

//
//  RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
//
//  RecipientInfo ::= CHOICE {
//      ktri KeyTransRecipientInfo,
//      kari [1] KeyAgreeRecipientInfo, -- not supported
//      kekri [2] KEKRecipientInfo, -- not supported
//      pwri [3] PasswordRecipientInfo,
//      ori [4] OtherRecipientInfo -- not supported
//  }
//
static size_t
vscf_message_info_der_serializer_serialize_recipient_infos(vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialized_encrypted_content_info_len(const vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info);

//
//  EncryptedContentInfo ::= SEQUENCE {
//      contentType ContentType, -- always PKCS#7 'data' OID
//      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
//  }
//
//  ContentType ::= OBJECT IDENTIFIER
//  ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
//  EncryptedContent ::= OCTET STRING
//
static size_t
vscf_message_info_der_serializer_serialize_encrypted_content_info(vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialized_enveloped_data_len(const vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info);

//
//  EnvelopedData ::= SEQUENCE {
//      version CMSVersion,
//      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
//      recipientInfos RecipientInfos,
//      encryptedContentInfo EncryptedContentInfo,
//      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
//  }
//
//  CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
static size_t
vscf_message_info_der_serializer_serialize_enveloped_data(vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info);

static size_t
vscf_message_info_der_serializer_serialized_cms_content_info_len(const vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info);

//
//  ContentInfo ::= SEQUENCE {
//      contentType ContentType,
//      content [0] EXPLICIT ANY DEFINED BY contentType
//  }
//
//  ContentType ::= OBJECT IDENTIFIER
//
static size_t
vscf_message_info_der_serializer_serialize_cms_content_info(vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info);

//
//  VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo
//
static size_t
vscf_message_info_der_serializer_serialized_signer_infos_len(const vscf_message_info_der_serializer_t *self,
        const vscf_message_info_footer_t *message_info_footer);

//
//  VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo
//
static size_t
vscf_message_info_der_serializer_serialize_signer_infos(vscf_message_info_der_serializer_t *self,
        const vscf_message_info_footer_t *message_info_footer);

//
//  VirgilSignerInfo ::= SEQUENCE {
//      version INTEGER { v0(0) } DEFAULT v0,
//      signerIdentifier VirgilSignerIdentifier,
//      signerAlgorithm VirgilSignerAlgorithm,
//      signature VirgilSignatureValue
//  }
//
//  VirgilSignerIdentifier ::= OCTET STRING
//
//  VirgilSignerAlgorithm ::= AlgorithmIdentifier
//
//  VirgilSignatureValue ::= OCTET STRING
//
static size_t
vscf_message_info_der_serializer_serialized_signer_info_len(const vscf_message_info_der_serializer_t *self,
        const vscf_signer_info_t *signer_info);

//
//  VirgilSignerInfo ::= SEQUENCE {
//      version INTEGER { v0(0) } DEFAULT v0,
//      signerIdentifier VirgilSignerIdentifier,
//      signerAlgorithm VirgilSignerAlgorithm,
//      signature VirgilSignatureValue
//  }
//
//  VirgilSignerIdentifier ::= OCTET STRING
//
//  VirgilSignerAlgorithm ::= AlgorithmIdentifier
//
//  VirgilSignatureValue ::= OCTET STRING
//
static size_t
vscf_message_info_der_serializer_serialize_signer_info(vscf_message_info_der_serializer_t *self,
        const vscf_signer_info_t *signer_info);

//
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
//
static void
vscf_message_info_der_serializer_deserialize_custom_params(vscf_message_info_der_serializer_t *self,
        vscf_message_info_custom_params_t *custom_params, vscf_error_t *error);

//
//  VirgilSignedDataInfo ::= SEQUENCE {
//      version INTEGER { v0(0) },
//      digestAlgorithm AlgorithmIdentifier,
//      dataSize INTEGER,
//      signedParams [0] EXPLICIT VirgilCustomParams OPTIONAL
//  }
//
static void
vscf_message_info_der_serializer_deserialize_signed_data_info(vscf_message_info_der_serializer_t *self,
        vscf_message_info_t *message_info, vscf_error_t *error);

//
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
//
static void
vscf_message_info_der_serializer_deserialize_key_recipient_info(vscf_message_info_der_serializer_t *self,
        vscf_message_info_t *message_info, vscf_error_t *error);

//
//  PasswordRecipientInfo ::= SEQUENCE {
//      version CMSVersion, -- Always set to 0
//      keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
//                                 OPTIONAL, -- not used
//      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//      encryptedKey EncryptedKey
//  }
//
static void
vscf_message_info_der_serializer_deserialize_password_recipient_info(vscf_message_info_der_serializer_t *self,
        vscf_message_info_t *message_info, vscf_error_t *error);

//
//  RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
//
//  RecipientInfo ::= CHOICE {
//      ktri KeyTransRecipientInfo,
//      kari [1] KeyAgreeRecipientInfo, -- not supported
//      kekri [2] KEKRecipientInfo, -- not supported
//      pwri [3] PasswordRecipientInfo,
//      ori [4] OtherRecipientInfo -- not supported
//  }
//
static void
vscf_message_info_der_serializer_deserialize_recipient_infos(vscf_message_info_der_serializer_t *self,
        vscf_message_info_t *message_info, vscf_error_t *error);

//
//  EncryptedContentInfo ::= SEQUENCE {
//      contentType ContentType, -- always PKCS#7 'data' OID
//      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
//  }
//
//  ContentType ::= OBJECT IDENTIFIER
//  ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
//  EncryptedContent ::= OCTET STRING
//
static void
vscf_message_info_der_serializer_deserialize_encrypted_content_info(vscf_message_info_der_serializer_t *self,
        vscf_message_info_t *message_info, vscf_error_t *error);

//
//  EnvelopedData ::= SEQUENCE {
//      version CMSVersion,
//      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
//      recipientInfos RecipientInfos,
//      encryptedContentInfo EncryptedContentInfo,
//      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
//  }
//
//  CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
static void
vscf_message_info_der_serializer_deserialize_enveloped_data(vscf_message_info_der_serializer_t *self,
        vscf_message_info_t *message_info, vscf_error_t *error);

//
//  ContentInfo ::= SEQUENCE {
//      contentType ContentType,
//      content [0] EXPLICIT ANY DEFINED BY contentType
//  }
//
//  ContentType ::= OBJECT IDENTIFIER
//
static void
vscf_message_info_der_serializer_deserialize_cms_content_info(vscf_message_info_der_serializer_t *self,
        vscf_message_info_t *message_info, vscf_error_t *error);

//
//  VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo
//
static void
vscf_message_info_der_serializer_deserialize_signer_infos(vscf_message_info_der_serializer_t *self,
        vscf_message_info_footer_t *message_info_footer, vscf_error_t *error);

//
//  VirgilSignerInfo ::= SEQUENCE {
//      version INTEGER { v0(0) } DEFAULT v0,
//      signerIdentifier VirgilSignerIdentifier,
//      signerAlgorithm VirgilSignerAlgorithm,
//      signature VirgilSignatureValue
//  }
//
//  VirgilSignerIdentifier ::= OCTET STRING
//
//  VirgilSignerAlgorithm ::= AlgorithmIdentifier
//
//  VirgilSignatureValue ::= OCTET STRING
//
static void
vscf_message_info_der_serializer_deserialize_signer_info(vscf_message_info_der_serializer_t *self,
        vscf_message_info_footer_t *message_info_footer, vscf_error_t *error);


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
vscf_message_info_der_serializer_init_ctx(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    self->alg_info_serializer = vscf_alg_info_der_serializer_new();
    self->alg_info_deserializer = vscf_alg_info_der_deserializer_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_cleanup_ctx(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_serializer_destroy(&self->alg_info_serializer);
    vscf_alg_info_der_deserializer_destroy(&self->alg_info_deserializer);
}

//
//  This method is called when interface 'asn1 reader' was setup.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_setup_asn1_reader(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_deserializer_use_asn1_reader(self->alg_info_deserializer, self->asn1_reader);
}

//
//  This method is called when interface 'asn1 reader' was released.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_release_asn1_reader(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_deserializer_release_asn1_reader(self->alg_info_deserializer);
}

//
//  This method is called when interface 'asn1 writer' was setup.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_setup_asn1_writer(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_serializer_use_asn1_writer(self->alg_info_serializer, self->asn1_writer);
}

//
//  This method is called when interface 'asn1 writer' was released.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_release_asn1_writer(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_serializer_release_asn1_writer(self->alg_info_serializer);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_setup_defaults(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->asn1_reader) {
        vscf_message_info_der_serializer_take_asn1_reader(self, vscf_asn1rd_impl(vscf_asn1rd_new()));
    }

    if (NULL == self->asn1_writer) {
        vscf_message_info_der_serializer_take_asn1_writer(self, vscf_asn1wr_impl(vscf_asn1wr_new()));
    }
}

//
//  Return size in bytes enough to hold serialized custom params.
//
static size_t
vscf_message_info_der_serializer_serialized_custom_params_len(
        const vscf_message_info_der_serializer_t *self, const vscf_message_info_custom_params_t *custom_params) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(custom_params);

    if (vscf_message_info_custom_params_first_param(custom_params) == NULL) {
        return 0;
    }

    size_t len = 1 + 1 + 8;

    for (const vscf_list_key_value_node_t *param = vscf_message_info_custom_params_first_param(custom_params);
            param != NULL; param = vscf_message_info_custom_params_next_param(param)) {

        //  KeyValue
        len += 1 + 1 + 8;

        //  Key
        vsc_data_t key = vscf_message_info_custom_params_param_key(param);
        len += 1 + 1 + 8 + key.len;

        //  Value
        if (vscf_message_info_custom_params_is_int_param(param)) {
            len += 1 + 1 + 8 + 1 + 1 + 8;

        } else if (vscf_message_info_custom_params_is_string_param(param)) {
            vsc_data_t string = vscf_message_info_custom_params_as_string_value(param);
            len += 1 + 1 + 8 + 1 + 1 + 8 + string.len;

        } else if (vscf_message_info_custom_params_is_data_param(param)) {
            vsc_data_t data = vscf_message_info_custom_params_as_data_value(param);
            len += 1 + 1 + 8 + 1 + 1 + 8 + data.len;
        } else {
            VSCF_ASSERT(0 && "Unhandled custom param.");
        }
    }

    return len;
}

//
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
//
static size_t
vscf_message_info_der_serializer_serialize_custom_params(
        vscf_message_info_der_serializer_t *self, const vscf_message_info_custom_params_t *custom_params) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(custom_params);

    size_t len = 0;

    for (const vscf_list_key_value_node_t *param = vscf_message_info_custom_params_first_param(custom_params);
            param != NULL; param = vscf_message_info_custom_params_next_param(param)) {

        size_t key_value_len = 0;

        //
        //  Write: val.
        //
        if (vscf_message_info_custom_params_is_int_param(param)) {
            int value = vscf_message_info_custom_params_as_int_value(param);
            key_value_len += vscf_asn1_writer_write_int(self->asn1_writer, value);
            key_value_len += vscf_asn1_writer_write_context_tag(self->asn1_writer, 0, key_value_len);

        } else if (vscf_message_info_custom_params_is_string_param(param)) {
            vsc_data_t value = vscf_message_info_custom_params_as_string_value(param);
            key_value_len += vscf_asn1_writer_write_utf8_str(self->asn1_writer, value);
            key_value_len += vscf_asn1_writer_write_context_tag(self->asn1_writer, 1, key_value_len);

        } else if (vscf_message_info_custom_params_is_data_param(param)) {
            vsc_data_t value = vscf_message_info_custom_params_as_data_value(param);
            key_value_len += vscf_asn1_writer_write_octet_str(self->asn1_writer, value);
            key_value_len += vscf_asn1_writer_write_context_tag(self->asn1_writer, 2, key_value_len);
        } else {
            VSCF_ASSERT(0 && "Unhandled custom param.");
        }

        //
        //  Write: key.
        //
        vsc_data_t key = vscf_message_info_custom_params_param_key(param);
        key_value_len += vscf_asn1_writer_write_utf8_str(self->asn1_writer, key);

        //
        //  Write: KeyValue.
        //
        key_value_len += vscf_asn1_writer_write_sequence(self->asn1_writer, key_value_len);

        //
        //  Increase common top levevl sequence length.
        //
        len += key_value_len;
    }

    if (len > 0) {
        len += vscf_asn1_writer_write_set(self->asn1_writer, len);
        len += vscf_asn1_writer_write_context_tag(self->asn1_writer, 0, len);
    }

    return len;
}

//
//  Return size in bytes enough to hold serialized signed data info.
//
//  VirgilSignedDataInfo ::= SEQUENCE {
//      version INTEGER { v0(0) },
//      digestAlgorithm AlgorithmIdentifier,
//      dataSize INTEGER,
//      signedParams [0] EXPLICIT VirgilCustomParams OPTIONAL
//  }
//
VSCF_PRIVATE size_t
vscf_message_info_der_serializer_serialized_signed_data_info_len(
        const vscf_message_info_der_serializer_t *self, const vscf_signed_data_info_t *signed_data_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(signed_data_info);

    const vscf_message_info_custom_params_t *signed_params =
            vscf_signed_data_info_custom_params((vscf_signed_data_info_t *)signed_data_info);
    const size_t signed_params_len = vscf_message_info_der_serializer_serialized_custom_params_len(self, signed_params);

    const size_t len = 1 + 1 + 4 +        //  VirgilSignedDataInfo ::= SEQUENCE {
                       1 + 1 + 1 +        //      version INTEGER { v0(0) },
                       1 + 1 + 16 +       //      digestAlgorithm AlgorithmIdentifier,
                       1 + 1 + 8 +        //      dataSize INTEGER,
                       signed_params_len; //      signedParams [0] EXPLICIT VirgilCustomParams OPTIONAL }

    return len;
}

//
//  Serialize signed data info with internal ASN.1 writer.
//
//  VirgilSignedDataInfo ::= SEQUENCE {
//      version INTEGER { v0(0) },
//      digestAlgorithm AlgorithmIdentifier,
//      dataSize INTEGER,
//      signedParams [0] EXPLICIT VirgilCustomParams OPTIONAL
//  }
//
static size_t
vscf_message_info_der_serializer_serialize_signed_data_info_inplace(
        vscf_message_info_der_serializer_t *self, const vscf_signed_data_info_t *signed_data_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(signed_data_info);
    VSCF_ASSERT_PTR(self->asn1_writer);

    const size_t version = 0;
    const vscf_impl_t *digest_algorithm = vscf_signed_data_info_hash_alg_info(signed_data_info);
    const size_t data_size = vscf_signed_data_info_data_size(signed_data_info);
    const vscf_message_info_custom_params_t *custom_params =
            vscf_signed_data_info_custom_params((vscf_signed_data_info_t *)signed_data_info);

    size_t len = 0;
    len += vscf_message_info_der_serializer_serialize_custom_params(self, custom_params);
    len += vscf_asn1_writer_write_uint(self->asn1_writer, data_size);
    len += vscf_alg_info_der_serializer_serialize_inplace(self->alg_info_serializer, digest_algorithm);
    len += vscf_asn1_writer_write_int(self->asn1_writer, version);
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    if (len > 0) {
        len += vscf_asn1_writer_write_context_tag(self->asn1_writer, 1, len);
    }

    VSCF_ASSERT(!vscf_asn1_writer_has_error(self->asn1_writer));

    return len;
}

//
//  Serialize signed data info.
//
//  VirgilSignedDataInfo ::= SEQUENCE {
//      version INTEGER { v0(0) },
//      digestAlgorithm AlgorithmIdentifier,
//      dataSize INTEGER,
//      signedParams [0] EXPLICIT VirgilCustomParams OPTIONAL
//  }
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_serialize_signed_data_info(
        vscf_message_info_der_serializer_t *self, const vscf_signed_data_info_t *signed_data_info, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_writer);
    VSCF_ASSERT_PTR(signed_data_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_message_info_der_serializer_serialized_signed_data_info_len(self, signed_data_info));

    vscf_asn1_writer_reset(self->asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    const size_t len = vscf_message_info_der_serializer_serialize_signed_data_info_inplace(self, signed_data_info);
    vscf_asn1_writer_finish(self->asn1_writer, vsc_buffer_is_reverse(out));
    vsc_buffer_inc_used(out, len);
}

static size_t
vscf_message_info_der_serializer_serialized_key_recipient_info_len(
        const vscf_message_info_der_serializer_t *self, const vscf_key_recipient_info_t *key_recipient_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key_recipient_info);

    size_t encrypted_key_len = vscf_key_recipient_info_encrypted_key(key_recipient_info).len;

    size_t len = 1 + 1 + 3 +                    //  KeyTransRecipientInfo ::= SEQUENCE {
                 1 + 1 + 1 +                    //      version CMSVersion, -- always set to 0 or 2
                 1 + 1 + 64 +                   //      rid RecipientIdentifier,
                 1 + 1 + 32 +                   //      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
                 1 + 1 + 2 + encrypted_key_len; //      encryptedKey EncryptedKey }

    return len;
}

//
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
//
static size_t
vscf_message_info_der_serializer_serialize_key_recipient_info(
        vscf_message_info_der_serializer_t *self, const vscf_key_recipient_info_t *key_recipient_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key_recipient_info);

    size_t key_recipient_info_len = 0;

    //
    //  Write: encryptedKey.
    //
    key_recipient_info_len += vscf_asn1_writer_write_octet_str(
            self->asn1_writer, vscf_key_recipient_info_encrypted_key(key_recipient_info));

    //
    //  Write: keyEncryptionAlgorithm.
    //
    const vscf_impl_t *key_encryption_alg_info = vscf_key_recipient_info_key_encryption_algorithm(key_recipient_info);
    key_recipient_info_len +=
            vscf_alg_info_der_serializer_serialize_inplace(self->alg_info_serializer, key_encryption_alg_info);

    //
    //  Write: rid.
    //
    size_t rid_len = 0;
    rid_len += vscf_asn1_writer_write_octet_str(
            self->asn1_writer, vscf_key_recipient_info_recipient_id(key_recipient_info));
    rid_len += vscf_asn1_writer_write_context_tag(self->asn1_writer, 0, rid_len);

    key_recipient_info_len += rid_len;

    //
    //  Write: version {2}
    //
    key_recipient_info_len += vscf_asn1_writer_write_int(self->asn1_writer, 2);

    //
    //  Write: KeyTransRecipientInfo
    //
    key_recipient_info_len += vscf_asn1_writer_write_sequence(self->asn1_writer, key_recipient_info_len);

    return key_recipient_info_len;
}

static size_t
vscf_message_info_der_serializer_serialized_password_recipient_info_len(
        const vscf_message_info_der_serializer_t *self, const vscf_password_recipient_info_t *password_recipient_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(password_recipient_info);

    size_t len = 1 + 2 +       //  PasswordRecipientInfo ::= SEQUENCE {
                 1 + 1 + 1 +   //    version CMSVersion, -- Always set to 0
                 0 +           //    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL, -- not used
                 1 + 1 + 127 + //    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
                 1 + 1 + 32;   //    encryptedKey EncryptedKey }

    return len;
}

//
//  PasswordRecipientInfo ::= SEQUENCE {
//      version CMSVersion, -- Always set to 0
//      keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
//                                 OPTIONAL, -- not used
//      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//      encryptedKey EncryptedKey
//  }
//
static size_t
vscf_message_info_der_serializer_serialize_password_recipient_info(
        vscf_message_info_der_serializer_t *self, const vscf_password_recipient_info_t *password_recipient_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(password_recipient_info);

    size_t password_recipient_info_len = 0;

    //
    //  Write: encryptedKey.
    //
    password_recipient_info_len += vscf_asn1_writer_write_octet_str(
            self->asn1_writer, vscf_password_recipient_info_encrypted_key(password_recipient_info));

    //
    //  Write: keyEncryptionAlgorithm.
    //
    const vscf_impl_t *key_encryption_alg_info =
            vscf_password_recipient_info_key_encryption_algorithm(password_recipient_info);
    password_recipient_info_len +=
            vscf_alg_info_der_serializer_serialize_inplace(self->alg_info_serializer, key_encryption_alg_info);

    //
    //  Write: version {0}
    //
    password_recipient_info_len += vscf_asn1_writer_write_int(self->asn1_writer, 0);

    //
    //  Write: KeyTransRecipientInfo
    //
    password_recipient_info_len += vscf_asn1_writer_write_sequence(self->asn1_writer, password_recipient_info_len);

    return password_recipient_info_len;
}

static size_t
vscf_message_info_der_serializer_serialized_recipient_infos_len(
        const vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    size_t len = 1 + 1 + 8; //  RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

    //  ktri KeyTransRecipientInfo,
    for (const vscf_key_recipient_info_list_t *list = vscf_message_info_key_recipient_info_list(message_info);
            (list != NULL) && vscf_key_recipient_info_list_has_item(list);
            list = vscf_key_recipient_info_list_next(list)) {

        const vscf_key_recipient_info_t *info = vscf_key_recipient_info_list_item(list);


        len += vscf_message_info_der_serializer_serialized_key_recipient_info_len(self, info);
    }

    // pwri [3] PasswordRecipientInfo,
    for (const vscf_password_recipient_info_list_t *list = vscf_message_info_password_recipient_info_list(message_info);
            (list != NULL) && vscf_password_recipient_info_list_has_item(list);
            list = vscf_password_recipient_info_list_next(list)) {

        const vscf_password_recipient_info_t *info = vscf_password_recipient_info_list_item(list);

        len += 1 + 3;
        len += vscf_message_info_der_serializer_serialized_password_recipient_info_len(self, info);
    }

    return len;
}

//
//  RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
//
//  RecipientInfo ::= CHOICE {
//      ktri KeyTransRecipientInfo,
//      kari [1] KeyAgreeRecipientInfo, -- not supported
//      kekri [2] KEKRecipientInfo, -- not supported
//      pwri [3] PasswordRecipientInfo,
//      ori [4] OtherRecipientInfo -- not supported
//  }
//
static size_t
vscf_message_info_der_serializer_serialize_recipient_infos(
        vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info) {

    //  RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
    //
    //  RecipientInfo ::= CHOICE {
    //      ktri KeyTransRecipientInfo,
    //      kari [1] KeyAgreeRecipientInfo, -- not supported
    //      kekri [2] KEKRecipientInfo, -- not supported
    //      pwri [3] PasswordRecipientInfo,
    //      ori [4] OtherRecipientInfo -- not supported
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    size_t recipient_infos_len = 0;

    for (const vscf_key_recipient_info_list_t *list = vscf_message_info_key_recipient_info_list(message_info);
            (list != NULL) && vscf_key_recipient_info_list_has_item(list);
            list = vscf_key_recipient_info_list_next(list)) {

        const vscf_key_recipient_info_t *info = vscf_key_recipient_info_list_item(list);

        size_t info_len = vscf_message_info_der_serializer_serialize_key_recipient_info(self, info);

        recipient_infos_len += info_len;
    }

    for (const vscf_password_recipient_info_list_t *list = vscf_message_info_password_recipient_info_list(message_info);
            (list != NULL) && vscf_password_recipient_info_list_has_item(list);
            list = vscf_password_recipient_info_list_next(list)) {

        const vscf_password_recipient_info_t *info = vscf_password_recipient_info_list_item(list);

        size_t info_len = 0;

        info_len += vscf_message_info_der_serializer_serialize_password_recipient_info(self, info);

        info_len += vscf_asn1_writer_write_context_tag(self->asn1_writer, 3, info_len);

        recipient_infos_len += info_len;
    }

    recipient_infos_len += vscf_asn1_writer_write_set(self->asn1_writer, recipient_infos_len);

    return recipient_infos_len;
}

static size_t
vscf_message_info_der_serializer_serialized_encrypted_content_info_len(
        const vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    size_t len = 1 + 1 +      //  EncryptedContentInfo ::= SEQUENCE {
                 1 + 1 + 9 +  //      contentType ContentType, -- always PKCS#7 'data' OID
                 1 + 1 + 32 + //      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
                 0;           //      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used }

    return len;
}

//
//  EncryptedContentInfo ::= SEQUENCE {
//      contentType ContentType, -- always PKCS#7 'data' OID
//      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
//  }
//
//  ContentType ::= OBJECT IDENTIFIER
//  ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
//  EncryptedContent ::= OCTET STRING
//
static size_t
vscf_message_info_der_serializer_serialize_encrypted_content_info(
        vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info) {

    //  EncryptedContentInfo ::= SEQUENCE {
    //      contentType ContentType, -- always PKCS#7 'data' OID
    //      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    //      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
    //  }
    //
    //  ContentType ::= OBJECT IDENTIFIER
    //  ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
    //  EncryptedContent ::= OCTET STRING

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    size_t encrypted_content_info_len = 0;

    //
    //  Write: contentEncryptionAlgorithm.
    //
    const vscf_impl_t *content_encryption_alg_info = vscf_message_info_data_encryption_alg_info(message_info);
    encrypted_content_info_len +=
            vscf_alg_info_der_serializer_serialize_inplace(self->alg_info_serializer, content_encryption_alg_info);

    //
    //  Write: contentType.
    //
    encrypted_content_info_len += vscf_asn1_writer_write_oid(self->asn1_writer, vscf_oid_from_id(vscf_oid_id_CMS_DATA));

    //
    //  Write: EncryptedContentInfo.
    //
    encrypted_content_info_len += vscf_asn1_writer_write_sequence(self->asn1_writer, encrypted_content_info_len);

    return encrypted_content_info_len;
}

static size_t
vscf_message_info_der_serializer_serialized_enveloped_data_len(
        const vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    size_t recipient_infos_len = vscf_message_info_der_serializer_serialized_recipient_infos_len(self, message_info);

    size_t encrypted_content_info_len =
            vscf_message_info_der_serializer_serialized_encrypted_content_info_len(self, message_info);

    size_t len = 1 + 1 + 8 +                  //  EnvelopedData ::= SEQUENCE {
                 1 + 1 + 1 +                  //      version CMSVersion,
                 0 +                          //      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
                 recipient_infos_len +        //      recipientInfos RecipientInfos,
                 encrypted_content_info_len + //      encryptedContentInfo EncryptedContentInfo,
                 0; //      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used }

    return len;
}

//
//  EnvelopedData ::= SEQUENCE {
//      version CMSVersion,
//      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
//      recipientInfos RecipientInfos,
//      encryptedContentInfo EncryptedContentInfo,
//      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
//  }
//
//  CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
static size_t
vscf_message_info_der_serializer_serialize_enveloped_data(
        vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info) {

    //  EnvelopedData ::= SEQUENCE {
    //      version CMSVersion,
    //      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
    //      recipientInfos RecipientInfos,
    //      encryptedContentInfo EncryptedContentInfo,
    //      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
    //  }
    //
    //  CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }

    VSCF_ASSERT_PTR(self);
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

    enveloped_data_len += vscf_message_info_der_serializer_serialize_encrypted_content_info(self, message_info);

    enveloped_data_len += vscf_message_info_der_serializer_serialize_recipient_infos(self, message_info);

    enveloped_data_len += vscf_asn1_writer_write_int(self->asn1_writer, enveloped_data_version);

    enveloped_data_len += vscf_asn1_writer_write_sequence(self->asn1_writer, enveloped_data_len);

    return enveloped_data_len;
}

static size_t
vscf_message_info_der_serializer_serialized_cms_content_info_len(
        const vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    size_t enveloped_data_len = vscf_message_info_der_serializer_serialized_enveloped_data_len(self, message_info);

    size_t len = 1 + 1 + 8 +         //  ContentInfo ::= SEQUENCE {
                 1 + 1 + 9 +         //      contentType ContentType,
                 enveloped_data_len; //      content [0] EXPLICIT ANY DEFINED BY contentType }

    return len;
}

//
//  ContentInfo ::= SEQUENCE {
//      contentType ContentType,
//      content [0] EXPLICIT ANY DEFINED BY contentType
//  }
//
//  ContentType ::= OBJECT IDENTIFIER
//
static size_t
vscf_message_info_der_serializer_serialize_cms_content_info(
        vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info) {

    //  ContentInfo ::= SEQUENCE {
    //      contentType ContentType,
    //      content [0] EXPLICIT ANY DEFINED BY contentType
    //  }
    //
    //  ContentType ::= OBJECT IDENTIFIER

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    size_t content_info_len = 0;
    content_info_len += vscf_message_info_der_serializer_serialize_enveloped_data(self, message_info);

    content_info_len += vscf_asn1_writer_write_context_tag(self->asn1_writer, 0, content_info_len);

    content_info_len += vscf_asn1_writer_write_oid(self->asn1_writer, vscf_oid_from_id(vscf_oid_id_CMS_ENVELOPED_DATA));

    content_info_len += vscf_asn1_writer_write_sequence(self->asn1_writer, content_info_len);

    return content_info_len;
}

//
//  VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo
//
static size_t
vscf_message_info_der_serializer_serialized_signer_infos_len(
        const vscf_message_info_der_serializer_t *self, const vscf_message_info_footer_t *message_info_footer) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info_footer);

    const vscf_signer_info_list_t *list = vscf_message_info_footer_signer_infos(message_info_footer);
    if (NULL == list || !vscf_signer_info_list_has_item(list)) {
        return 0;
    }

    size_t len = 1 + 1 + 8; //  VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo
    do {
        const vscf_signer_info_t *info = vscf_signer_info_list_item(list);
        len += vscf_message_info_der_serializer_serialized_signer_info_len(self, info);
    } while ((list = vscf_signer_info_list_next(list)) != NULL);

    return len;
}

//
//  VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo
//
static size_t
vscf_message_info_der_serializer_serialize_signer_infos(
        vscf_message_info_der_serializer_t *self, const vscf_message_info_footer_t *message_info_footer) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info_footer);

    const vscf_signer_info_list_t *list = vscf_message_info_footer_signer_infos(message_info_footer);

    if (NULL == list || !vscf_signer_info_list_has_item(list)) {
        return 0;
    }

    size_t signer_infos_len = 0;
    do {

        const vscf_signer_info_t *info = vscf_signer_info_list_item(list);

        size_t info_len = vscf_message_info_der_serializer_serialize_signer_info(self, info);

        signer_infos_len += info_len;
    } while ((list = vscf_signer_info_list_next(list)) != NULL);

    signer_infos_len += vscf_asn1_writer_write_set(self->asn1_writer, signer_infos_len);
    signer_infos_len += vscf_asn1_writer_write_context_tag(self->asn1_writer, 0, signer_infos_len);

    return signer_infos_len;
}

//
//  VirgilSignerInfo ::= SEQUENCE {
//      version INTEGER { v0(0) } DEFAULT v0,
//      signerIdentifier VirgilSignerIdentifier,
//      signerAlgorithm VirgilSignerAlgorithm,
//      signature VirgilSignatureValue
//  }
//
//  VirgilSignerIdentifier ::= OCTET STRING
//
//  VirgilSignerAlgorithm ::= AlgorithmIdentifier
//
//  VirgilSignatureValue ::= OCTET STRING
//
static size_t
vscf_message_info_der_serializer_serialized_signer_info_len(
        const vscf_message_info_der_serializer_t *self, const vscf_signer_info_t *signer_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(signer_info);

    const size_t signer_id_len = vscf_signer_info_signer_id(signer_info).len;
    const size_t signature_len = vscf_signer_info_signature(signer_info).len;

    const size_t len = 1 + 1 + 2 +                 //  VirgilSignerInfo ::= SEQUENCE {
                       1 + 1 + 1 +                 //      version INTEGER { v0(0) } DEFAULT v0,
                       1 + 1 + 2 + signer_id_len + //      signerIdentifier VirgilSignerIdentifier,
                       1 + 1 + 32 +                //      signerAlgorithm VirgilSignerAlgorithm,
                       1 + 1 + 2 + signature_len;  //      signature VirgilSignatureValue }

    return len;
}

//
//  VirgilSignerInfo ::= SEQUENCE {
//      version INTEGER { v0(0) } DEFAULT v0,
//      signerIdentifier VirgilSignerIdentifier,
//      signerAlgorithm VirgilSignerAlgorithm,
//      signature VirgilSignatureValue
//  }
//
//  VirgilSignerIdentifier ::= OCTET STRING
//
//  VirgilSignerAlgorithm ::= AlgorithmIdentifier
//
//  VirgilSignatureValue ::= OCTET STRING
//
static size_t
vscf_message_info_der_serializer_serialize_signer_info(
        vscf_message_info_der_serializer_t *self, const vscf_signer_info_t *signer_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(signer_info);

    size_t len = 0;

    //
    //  Write: signature
    //
    len += vscf_asn1_writer_write_octet_str(self->asn1_writer, vscf_signer_info_signature(signer_info));

    //
    //  Write: signerAlgorithm
    //
    const vscf_impl_t *signer_alg_info = vscf_signer_info_signer_alg_info(signer_info);
    len += vscf_alg_info_der_serializer_serialize_inplace(self->alg_info_serializer, signer_alg_info);

    //
    //  Write: signerIdentifier
    //
    len += vscf_asn1_writer_write_octet_str(self->asn1_writer, vscf_signer_info_signer_id(signer_info));

    //
    //  Write: version
    //
    len += vscf_asn1_writer_write_int(self->asn1_writer, 0);

    //
    //  Write: VirgilSignerInfo
    //
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    return len;
}

//
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
//
static void
vscf_message_info_der_serializer_deserialize_custom_params(vscf_message_info_der_serializer_t *self,
        vscf_message_info_custom_params_t *custom_params, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT_PTR(custom_params);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    if (vscf_asn1_reader_left_len(self->asn1_reader) == 0) {
        return;
    }

    const size_t custom_params_tag_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 0);
    if (custom_params_tag_len == 0) {
        return;
    }

    size_t custom_params_len = vscf_asn1_reader_read_set(self->asn1_reader);

    while (custom_params_len != 0) {
        const size_t custom_param_len = vscf_asn1_reader_get_data_len(self->asn1_reader);

        if (custom_params_len >= custom_param_len) {
            custom_params_len -= custom_param_len;
        } else {
            VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
            return;
        }

        vscf_asn1_reader_read_sequence(self->asn1_reader);
        vsc_data_t key = vscf_asn1_reader_read_utf8_str(self->asn1_reader);

        if (vscf_asn1_reader_read_context_tag(self->asn1_reader, 0) > 0) {
            int value = vscf_asn1_reader_read_int(self->asn1_reader);
            vscf_message_info_custom_params_add_int(custom_params, key, value);

        } else if (vscf_asn1_reader_read_context_tag(self->asn1_reader, 1) > 0) {
            vsc_data_t value = vscf_asn1_reader_read_utf8_str(self->asn1_reader);
            vscf_message_info_custom_params_add_string(custom_params, key, value);

        } else if (vscf_asn1_reader_read_context_tag(self->asn1_reader, 2) > 0) {
            vsc_data_t value = vscf_asn1_reader_read_octet_str(self->asn1_reader);
            vscf_message_info_custom_params_add_data(custom_params, key, value);

        } else {
            VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
            return;
        }
    }
}

//
//  VirgilSignedDataInfo ::= SEQUENCE {
//      version INTEGER { v0(0) },
//      digestAlgorithm AlgorithmIdentifier,
//      dataSize INTEGER,
//      signedParams [0] EXPLICIT VirgilCustomParams OPTIONAL
//  }
//
static void
vscf_message_info_der_serializer_deserialize_signed_data_info(
        vscf_message_info_der_serializer_t *self, vscf_message_info_t *message_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT_PTR(message_info);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    if (vscf_asn1_reader_left_len(self->asn1_reader) == 0) {
        return;
    }

    const size_t signed_data_info_tag_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 1);
    if (signed_data_info_tag_len == 0) {
        return;
    }

    //
    //  Read: VirgilSignedDataInfo
    //
    vscf_asn1_reader_read_sequence(self->asn1_reader);

    //
    //  Read: version
    //
    const int version = vscf_asn1_reader_read_int(self->asn1_reader);
    if (version != 0) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO);
        return;
    }

    //
    //  Read: digestAlgorithm
    //
    vscf_impl_t *hash_alg_info = vscf_alg_info_der_deserializer_deserialize_inplace(self->alg_info_deserializer, error);
    if (NULL == hash_alg_info) {
        //  TODO: Log underlying error
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO);
        return;
    }

    vscf_signed_data_info_t *signed_data_info = vscf_signed_data_info_new();
    vscf_signed_data_info_set_hash_alg_info(signed_data_info, &hash_alg_info);

    //
    //  Read: dataSize
    //
    const unsigned int data_size = vscf_asn1_reader_read_uint(self->asn1_reader);
    vscf_signed_data_info_set_data_size(signed_data_info, data_size);


    //
    //  Read: signedParams
    //
    vscf_message_info_custom_params_t *custom_params = vscf_signed_data_info_custom_params(signed_data_info);
    vscf_message_info_der_serializer_deserialize_custom_params(self, custom_params, error);

    //
    //  Accompish
    //
    if (!vscf_error_has_error(error) && !vscf_asn1_reader_has_error(self->asn1_reader)) {
        vscf_message_info_set_signed_data_info(message_info, signed_data_info /* retained */);
    }

    vscf_signed_data_info_destroy(&signed_data_info);
}

//
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
//
static void
vscf_message_info_der_serializer_deserialize_key_recipient_info(
        vscf_message_info_der_serializer_t *self, vscf_message_info_t *message_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    vscf_asn1_reader_read_sequence(self->asn1_reader);
    const int version = vscf_asn1_reader_read_int(self->asn1_reader);

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    if (version != 2) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
        return;
    }

    const size_t rid_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 0);

    if (rid_len == 0) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
        return;
    }

    vsc_data_t rid = vscf_asn1_reader_read_octet_str(self->asn1_reader);
    vscf_impl_t *key_encryption_alg_info =
            vscf_alg_info_der_deserializer_deserialize_inplace(self->alg_info_deserializer, error);
    vsc_data_t encrypted_key = vscf_asn1_reader_read_octet_str(self->asn1_reader);

    if (key_encryption_alg_info == NULL) {
        return;
    }

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        vscf_impl_destroy(&key_encryption_alg_info);
        return;
    }

    vscf_key_recipient_info_t *key_recipient_info =
            vscf_key_recipient_info_new_with_data(rid, key_encryption_alg_info, encrypted_key);

    vscf_impl_destroy(&key_encryption_alg_info);

    vscf_message_info_add_key_recipient(message_info, &key_recipient_info);
}

//
//  PasswordRecipientInfo ::= SEQUENCE {
//      version CMSVersion, -- Always set to 0
//      keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
//                                 OPTIONAL, -- not used
//      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//      encryptedKey EncryptedKey
//  }
//
static void
vscf_message_info_der_serializer_deserialize_password_recipient_info(
        vscf_message_info_der_serializer_t *self, vscf_message_info_t *message_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    vscf_asn1_reader_read_sequence(self->asn1_reader);
    const int version = vscf_asn1_reader_read_int(self->asn1_reader);

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    if (version != 0) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
        return;
    }

    const size_t kdf_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 0);
    if (kdf_len > 0) {
        //  Read: KeyDerivationAlgorithmIdentifier OPTIONAL.
        (void)vscf_asn1_reader_read_data(self->asn1_reader, kdf_len);
    }

    vscf_impl_t *key_encryption_alg_info =
            vscf_alg_info_der_deserializer_deserialize_inplace(self->alg_info_deserializer, error);
    vsc_data_t encrypted_key = vscf_asn1_reader_read_octet_str(self->asn1_reader);

    if (key_encryption_alg_info == NULL) {
        return;
    }

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        vscf_impl_destroy(&key_encryption_alg_info);
        return;
    }

    vscf_password_recipient_info_t *password_recipient_info =
            vscf_password_recipient_info_new_with_members(&key_encryption_alg_info, encrypted_key);

    vscf_message_info_add_password_recipient(message_info, &password_recipient_info);
}

//
//  RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
//
//  RecipientInfo ::= CHOICE {
//      ktri KeyTransRecipientInfo,
//      kari [1] KeyAgreeRecipientInfo, -- not supported
//      kekri [2] KEKRecipientInfo, -- not supported
//      pwri [3] PasswordRecipientInfo,
//      ori [4] OtherRecipientInfo -- not supported
//  }
//
static void
vscf_message_info_der_serializer_deserialize_recipient_infos(
        vscf_message_info_der_serializer_t *self, vscf_message_info_t *message_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    size_t recipient_infos_len = vscf_asn1_reader_read_set(self->asn1_reader);
    if (recipient_infos_len == 0) {
        return;
    }

    while (recipient_infos_len != 0) {
        const size_t recipient_len = vscf_asn1_reader_get_data_len(self->asn1_reader);
        const size_t pwri_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 3);

        if (recipient_infos_len >= recipient_len) {
            recipient_infos_len -= recipient_len;
        } else {
            VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
            return;
        }

        if (pwri_len > 0) {
            //
            //  Read: PasswordRecipientInfo.
            //
            vscf_message_info_der_serializer_deserialize_password_recipient_info(self, message_info, error);
        } else {
            //
            //  Read: KeyTransRecipientInfo.
            //
            vscf_message_info_der_serializer_deserialize_key_recipient_info(self, message_info, error);
        }

        if (vscf_asn1_reader_has_error(self->asn1_reader)) {
            return;
        }
    }
}

//
//  EncryptedContentInfo ::= SEQUENCE {
//      contentType ContentType, -- always PKCS#7 'data' OID
//      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
//  }
//
//  ContentType ::= OBJECT IDENTIFIER
//  ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
//  EncryptedContent ::= OCTET STRING
//
static void
vscf_message_info_der_serializer_deserialize_encrypted_content_info(
        vscf_message_info_der_serializer_t *self, vscf_message_info_t *message_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT_PTR(message_info);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    vscf_asn1_reader_read_sequence(self->asn1_reader);
    vsc_data_t content_type_oid = vscf_asn1_reader_read_oid(self->asn1_reader);

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_asn1_reader_status(self->asn1_reader));
        return;
    }

    const vscf_oid_id_t content_type = vscf_oid_to_id(content_type_oid);
    VSCF_ASSERT(content_type == vscf_oid_id_CMS_DATA);

    vscf_impl_t *content_encryption_algorithm =
            vscf_alg_info_der_deserializer_deserialize_inplace(self->alg_info_deserializer, error);


    if (content_encryption_algorithm == NULL) {
        return;
    }

    vscf_message_info_set_data_encryption_alg_info(message_info, &content_encryption_algorithm);
}

//
//  EnvelopedData ::= SEQUENCE {
//      version CMSVersion,
//      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
//      recipientInfos RecipientInfos,
//      encryptedContentInfo EncryptedContentInfo,
//      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
//  }
//
//  CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
static void
vscf_message_info_der_serializer_deserialize_enveloped_data(
        vscf_message_info_der_serializer_t *self, vscf_message_info_t *message_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    vscf_asn1_reader_read_sequence(self->asn1_reader);

    //
    //  Check version range.
    //
    const int version = vscf_asn1_reader_read_int(self->asn1_reader);

    if (vscf_asn1_reader_has_error(self->asn1_reader) || (version != 2 && version != 3)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
        return;
    }

    vscf_message_info_der_serializer_deserialize_recipient_infos(self, message_info, error);
    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_asn1_reader_status(self->asn1_reader));
        return;
    }

    //
    //  Precise version check.
    //
    int expected_version = 2;
    const vscf_password_recipient_info_list_t *pwri_list = vscf_message_info_password_recipient_info_list(message_info);
    if ((pwri_list != NULL) && vscf_password_recipient_info_list_has_item(pwri_list)) {
        expected_version = 3;
    }

    if (version != expected_version) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
        return;
    }

    //
    //  Read: encryptedContentInfo.
    //
    vscf_message_info_der_serializer_deserialize_encrypted_content_info(self, message_info, error);
}

//
//  ContentInfo ::= SEQUENCE {
//      contentType ContentType,
//      content [0] EXPLICIT ANY DEFINED BY contentType
//  }
//
//  ContentType ::= OBJECT IDENTIFIER
//
static void
vscf_message_info_der_serializer_deserialize_cms_content_info(
        vscf_message_info_der_serializer_t *self, vscf_message_info_t *message_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT_PTR(message_info);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    vscf_asn1_reader_read_sequence(self->asn1_reader);

    vsc_data_t content_type_oid = vscf_asn1_reader_read_oid(self->asn1_reader);
    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    const vscf_oid_id_t content_type = vscf_oid_to_id(content_type_oid);
    VSCF_ASSERT(content_type == vscf_oid_id_CMS_ENVELOPED_DATA);

    const size_t content_tag_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 0);
    if (vscf_asn1_reader_has_error(self->asn1_reader) || content_tag_len == 0) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_ASN1);
        return;
    }

    vscf_message_info_der_serializer_deserialize_enveloped_data(self, message_info, error);
}

//
//  VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo
//
static void
vscf_message_info_der_serializer_deserialize_signer_infos(vscf_message_info_der_serializer_t *self,
        vscf_message_info_footer_t *message_info_footer, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT_PTR(message_info_footer);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    const size_t signer_infos_tag_len = vscf_asn1_reader_read_context_tag(self->asn1_reader, 0);
    if (signer_infos_tag_len == 0) {
        return;
    }

    size_t signer_infos_len = vscf_asn1_reader_read_set(self->asn1_reader);
    while (signer_infos_len != 0) {
        const size_t signer_info_len = vscf_asn1_reader_get_data_len(self->asn1_reader);

        if (signer_infos_len >= signer_info_len) {
            signer_infos_len -= signer_info_len;
        } else {
            VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER);
            return;
        }

        vscf_message_info_der_serializer_deserialize_signer_info(self, message_info_footer, error);

        if (vscf_asn1_reader_has_error(self->asn1_reader)) {
            return;
        }
    }
}

//
//  VirgilSignerInfo ::= SEQUENCE {
//      version INTEGER { v0(0) } DEFAULT v0,
//      signerIdentifier VirgilSignerIdentifier,
//      signerAlgorithm VirgilSignerAlgorithm,
//      signature VirgilSignatureValue
//  }
//
//  VirgilSignerIdentifier ::= OCTET STRING
//
//  VirgilSignerAlgorithm ::= AlgorithmIdentifier
//
//  VirgilSignatureValue ::= OCTET STRING
//
static void
vscf_message_info_der_serializer_deserialize_signer_info(vscf_message_info_der_serializer_t *self,
        vscf_message_info_footer_t *message_info_footer, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT_PTR(message_info_footer);

    if (vscf_error_has_error(error) || vscf_asn1_reader_has_error(self->asn1_reader)) {
        return;
    }

    //
    //  Read: VirgilSignerInfo
    //
    vscf_asn1_reader_read_sequence(self->asn1_reader);

    //
    //  Read: version
    //
    const int version = vscf_asn1_reader_read_int(self->asn1_reader);
    if (version != 0 || vscf_asn1_reader_has_error(self->asn1_reader)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER);
        return;
    }

    //
    //  Read: signerIdentifier
    //
    vsc_data_t signer_id = vscf_asn1_reader_read_octet_str(self->asn1_reader);

    //
    //  Read: signerAlgorithm
    //
    vscf_impl_t *signer_alg_info =
            vscf_alg_info_der_deserializer_deserialize_inplace(self->alg_info_deserializer, error);

    //
    //  Read: signature
    //
    vsc_data_t signature = vscf_asn1_reader_read_octet_str(self->asn1_reader);

    //
    //  Check errors
    //
    if (NULL == signer_alg_info) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER);
        return;
    }

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        //  TODO: Log underlying error
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER);
        vscf_impl_destroy(&signer_alg_info);
        return;
    }

    //
    //  Add signerInfo
    //
    vsc_buffer_t *signature_buf = vsc_buffer_new_with_data(signature);
    vscf_signer_info_t *signer_info = vscf_signer_info_new_with_members(signer_id, &signer_alg_info, &signature_buf);

    vscf_message_info_footer_add_signer_info(message_info_footer, &signer_info);
}

//
//  Return buffer size enough to hold serialized message info.
//
VSCF_PUBLIC size_t
vscf_message_info_der_serializer_serialized_len(
        vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);

    size_t cms_content_info_len = vscf_message_info_der_serializer_serialized_cms_content_info_len(self, message_info);

    size_t custom_params_len = 0;
    if (vscf_message_info_has_custom_params(message_info)) {
        const vscf_message_info_custom_params_t *custom_params =
                vscf_message_info_custom_params((vscf_message_info_t *)message_info);
        custom_params_len = vscf_message_info_der_serializer_serialized_custom_params_len(self, custom_params);
    }

    size_t signed_data_info_len = 0;
    if (vscf_message_info_has_signed_data_info(message_info)) {
        const vscf_signed_data_info_t *signed_data_info =
                vscf_message_info_signed_data_info((vscf_message_info_t *)message_info);
        signed_data_info_len = vscf_message_info_der_serializer_serialized_signed_data_info_len(self, signed_data_info);
    }

    size_t len = 1 + 1 + 8 +            //  VirgilMessageInfo ::= SEQUENCE {
                 1 + 1 + 1 +            //      version INTEGER { v0(0) },
                 cms_content_info_len + //      cmsContent ContentInfo, -- Imports from RFC 5652
                 custom_params_len +    //      customParams [0] EXPLICIT VirgilCustomParams OPTIONAL,
                 signed_data_info_len;  //      signedDataInfo [1] EXPLICIT VirgilSignedDataInfo OPTIONAL }

    return len;
}

//
//  Serialize class "message info".
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_serialize(
        vscf_message_info_der_serializer_t *self, const vscf_message_info_t *message_info, vsc_buffer_t *out) {

    //  VirgilMessageInfo ::= SEQUENCE {
    //      version INTEGER { v0(0) } DEFAULT v0,
    //      cmsContent ContentInfo, -- Imports from RFC 5652
    //      customParams [0] EXPLICIT VirgilCustomParams OPTIONAL,
    //      signedDataInfo [1] EXPLICIT VirgilSignedDataInfo OPTIONAL
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(out));
    VSCF_ASSERT_PTR(self->asn1_writer);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_message_info_der_serializer_serialized_len(self, message_info));

    bool stored_out_mode = vsc_buffer_is_reverse(out);
    vsc_buffer_switch_reverse_mode(out, true);
    vscf_asn1_writer_reset(self->asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    const vscf_message_info_custom_params_t *custom_params =
            vscf_message_info_custom_params((vscf_message_info_t *)message_info);

    size_t message_info_len = 0;
    if (vscf_message_info_has_signed_data_info(message_info)) {
        const vscf_signed_data_info_t *signed_data_info =
                vscf_message_info_signed_data_info((vscf_message_info_t *)message_info);
        message_info_len += vscf_message_info_der_serializer_serialize_signed_data_info_inplace(self, signed_data_info);
    }
    message_info_len += vscf_message_info_der_serializer_serialize_custom_params(self, custom_params);
    message_info_len += vscf_message_info_der_serializer_serialize_cms_content_info(self, message_info);
    message_info_len += vscf_asn1_writer_write_int(self->asn1_writer, 0);
    message_info_len += vscf_asn1_writer_write_sequence(self->asn1_writer, message_info_len);
    vsc_buffer_inc_used(out, message_info_len);

    vsc_buffer_switch_reverse_mode(out, stored_out_mode);
}

//
//  Read message info prefix from the given data, and if it is valid,
//  return a length of bytes of the whole message info.
//
//  Zero returned if length can not be determined from the given data,
//  and this means that there is no message info at the data beginning.
//
VSCF_PUBLIC size_t
vscf_message_info_der_serializer_read_prefix(vscf_message_info_der_serializer_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(data.len >= vscf_message_info_der_serializer_PREFIX_LEN);


    unsigned char *p = (unsigned char *)data.bytes;
    const unsigned char *end = data.bytes + data.len;

    if (*p != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return 0;
    }

    ++p; // skip tag

    size_t length_len = 1;
    if ((*p & 0x80) > 0) {
        length_len += *p & 0x7F;
    }

    size_t len = 0;
    int status = mbedtls_asn1_get_len(&p, end, &len);

    if (status == 0 || status == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
        return len + length_len + 1 /* tag */;
    }

    return 0;
}

//
//  Deserialize class "message info".
//
VSCF_PUBLIC vscf_message_info_t *
vscf_message_info_der_serializer_deserialize(
        vscf_message_info_der_serializer_t *self, vsc_data_t data, vscf_error_t *error) {

    //  VirgilMessageInfo ::= SEQUENCE {
    //      version INTEGER { v0(0) } DEFAULT v0,
    //      cmsContent ContentInfo, -- Imports from RFC 5652
    //      customParams [0] EXPLICIT VirgilCustomParams OPTIONAL,
    //      signedDataInfo [1] EXPLICIT VirgilSignedDataInfo OPTIONAL
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(vsc_data_is_valid(data));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    vscf_message_info_t *message_info = vscf_message_info_new();

    vscf_asn1_reader_reset(self->asn1_reader, data);
    vscf_asn1_reader_read_sequence(self->asn1_reader);
    const int version = vscf_asn1_reader_read_int(self->asn1_reader);

    if (vscf_asn1_reader_has_error(self->asn1_reader) || version != 0) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO);
        goto error;
    }

    vscf_message_info_custom_params_t *custom_params = vscf_message_info_custom_params(message_info);

    vscf_message_info_der_serializer_deserialize_cms_content_info(self, message_info, &error_ctx);
    vscf_message_info_der_serializer_deserialize_custom_params(self, custom_params, &error_ctx);
    vscf_message_info_der_serializer_deserialize_signed_data_info(self, message_info, &error_ctx);

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        //  TODO: Log underlying error
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO);
        goto error;
    }

    if (vscf_error_has_error(&error_ctx)) {
        //  TODO: Log underlying error
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO);
        goto error;
    }

    return message_info;

error:
    vscf_message_info_destroy(&message_info);
    return NULL;
}

//
//  Return buffer size enough to hold serialized message info footer.
//
VSCF_PUBLIC size_t
vscf_message_info_der_serializer_serialized_footer_len(
        vscf_message_info_der_serializer_t *self, const vscf_message_info_footer_t *message_info_footer) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info_footer);

    const size_t signer_infos_len =
            vscf_message_info_der_serializer_serialized_signer_infos_len(self, message_info_footer);

    const size_t len = 1 + 1 + 8 +       //  VirgilMessageInfoFooter ::= SEQUENCE {
                       1 + 1 + 1 +       //      version INTEGER { v0(0) } DEFAULT v0,
                       signer_infos_len; //      signerInfos [0] EXPLICIT VirgilSignerInfos OPTIONAL }

    return len;
}

//
//  Serialize class "message info footer".
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_serialize_footer(vscf_message_info_der_serializer_t *self,
        const vscf_message_info_footer_t *message_info_footer, vsc_buffer_t *out) {

    //  VirgilMessageInfoFooter ::= SEQUENCE {
    //      version INTEGER { v0(0) } DEFAULT v0,
    //      signerInfos [0] EXPLICIT VirgilSignerInfos OPTIONAL
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message_info_footer);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(out));
    VSCF_ASSERT_PTR(self->asn1_writer);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_message_info_der_serializer_serialized_footer_len(self, message_info_footer));

    vscf_asn1_writer_reset(self->asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));

    size_t len = 0;
    len += vscf_message_info_der_serializer_serialize_signer_infos(self, message_info_footer);
    len += vscf_asn1_writer_write_int(self->asn1_writer, 0);
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    vscf_asn1_writer_finish(self->asn1_writer, vsc_buffer_is_reverse(out));
    vsc_buffer_inc_used(out, len);
}

//
//  Deserialize class "message info footer".
//
VSCF_PUBLIC vscf_message_info_footer_t *
vscf_message_info_der_serializer_deserialize_footer(
        vscf_message_info_der_serializer_t *self, vsc_data_t data, vscf_error_t *error) {

    //  VirgilMessageInfoFooter ::= SEQUENCE {
    //      version INTEGER { v0(0) } DEFAULT v0,
    //      signerInfos [0] EXPLICIT VirgilSignerInfos OPTIONAL
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1_reader);
    VSCF_ASSERT(vsc_data_is_valid(data));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    vscf_asn1_reader_reset(self->asn1_reader, data);

    vscf_asn1_reader_read_sequence(self->asn1_reader);
    const int version = vscf_asn1_reader_read_int(self->asn1_reader);

    if (vscf_asn1_reader_has_error(self->asn1_reader) || version != 0) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER);
        goto error;
    }

    vscf_message_info_footer_t *footer = vscf_message_info_footer_new();

    vscf_message_info_der_serializer_deserialize_signer_infos(self, footer, &error_ctx);

    if (vscf_asn1_reader_has_error(self->asn1_reader)) {
        //  TODO: Log underlying error
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER);
        goto error;
    }

    if (vscf_error_has_error(&error_ctx)) {
        //  TODO: Log underlying error
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER);
        goto error;
    }

    return footer;

error:
    vscf_message_info_footer_destroy(&footer);
    return NULL;
}
