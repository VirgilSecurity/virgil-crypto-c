# Copyright (C) 2015-2026 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


from ctypes import *
from ._c_bridge import VscfMessageInfoDerSerializer
from ._c_bridge import VscfStatus
from virgil_crypto_lib.common._c_bridge import Data
from virgil_crypto_lib.common._c_bridge import Buffer
from ._c_bridge._vscf_error import vscf_error_t
from .message_info import MessageInfo
from .message_info_footer import MessageInfoFooter
from .message_info_serializer import MessageInfoSerializer
from .message_info_footer_serializer import MessageInfoFooterSerializer


class MessageInfoDerSerializer(MessageInfoSerializer, MessageInfoFooterSerializer):
    """CMS based serialization of the class "message info"."""

    PREFIX_LEN = 32

    def __init__(self):
        """Create underlying C context."""
        self._lib_vscf_message_info_der_serializer = VscfMessageInfoDerSerializer()
        self._c_impl = None
        self._ctx = None
        self.ctx = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_new()

    def __delete__(self, instance):
        """Destroy underlying C context."""
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_delete(self.ctx)

    def set_asn1_reader(self, asn1_reader):
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_use_asn1_reader(self.ctx, asn1_reader.c_impl)

    def set_asn1_writer(self, asn1_writer):
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_use_asn1_writer(self.ctx, asn1_writer.c_impl)

    def setup_defaults(self):
        """Setup predefined values to the uninitialized class dependencies."""
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_setup_defaults(self.ctx)

    def serialized_custom_params_len(self, custom_params):
        """Return size in bytes enough to hold serialized custom params."""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_custom_params_len(self.ctx, custom_params.ctx)
        return result

    def serialize_custom_params(self, custom_params):
        """VirgilCustomParams ::= SET SIZE (1..MAX) OF KeyValue

KeyValue ::= SEQUENCE {
    key Key,
    val Value
}

Key ::= UTF8String

Value ::= CHOICE {
    int [0] EXPLICIT INTEGER,
    str [1] EXPLICIT UTF8String,
    data [2] EXPLICIT OCTET STRING
}"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_custom_params(self.ctx, custom_params.ctx)
        return result

    def serialized_footer_info_len(self, footer_info):
        """Return size in bytes enough to hold serialized footer info.

VirgilFooterInfo ::= SEQUENCE {
    version INTEGER { v0(0) },
    dataSize INTEGER,
    signedDataInfo [0] EXPLICIT VirgilSignedDataInfo OPTIONAL
}"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_footer_info_len(self.ctx, footer_info.ctx)
        return result

    def serialize_footer_info(self, footer_info):
        """Serialize footer info.

VirgilFooterInfo ::= SEQUENCE {
    version INTEGER { v0(0) },
    dataSize INTEGER,
    signedDataInfo [0] EXPLICIT VirgilSignedDataInfo OPTIONAL
}"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_footer_info(self.ctx, footer_info.ctx)
        return result

    def serialize_signed_data_info_internal(self, signed_data_info):
        """Serialized signed data info.

VirgilSignedDataInfo ::= SEQUENCE {
    version INTEGER { v0(0) } DEFAULT v0,
    digestAlgorithm AlgorithmIdentifier
}"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_signed_data_info_internal(self.ctx, signed_data_info.ctx)
        return result

    def serialized_key_recipient_info_len(self, key_recipient_info):
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_key_recipient_info_len(self.ctx, key_recipient_info.ctx)
        return result

    def serialize_key_recipient_info(self, key_recipient_info):
        """KeyTransRecipientInfo ::= SEQUENCE {
    version CMSVersion, -- always set to 0 or 2
    rid RecipientIdentifier,
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey }

RecipientIdentifier ::= CHOICE {
    issuerAndSerialNumber IssuerAndSerialNumber,
    subjectKeyIdentifier [0] SubjectKeyIdentifier }

SubjectKeyIdentifier ::= OCTET STRING

EncryptedKey ::= OCTET STRING"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_key_recipient_info(self.ctx, key_recipient_info.ctx)
        return result

    def serialized_password_recipient_info_len(self, password_recipient_info):
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_password_recipient_info_len(self.ctx, password_recipient_info.ctx)
        return result

    def serialize_password_recipient_info(self, password_recipient_info):
        """PasswordRecipientInfo ::= SEQUENCE {
    version CMSVersion, -- Always set to 0
    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                               OPTIONAL, -- not used
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey
}"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_password_recipient_info(self.ctx, password_recipient_info.ctx)
        return result

    def serialized_recipient_infos_len(self, message_info):
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_recipient_infos_len(self.ctx, message_info.ctx)
        return result

    def serialize_recipient_infos(self, message_info):
        """RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

RecipientInfo ::= CHOICE {
    ktri KeyTransRecipientInfo,
    kari [1] KeyAgreeRecipientInfo, -- not supported
    kekri [2] KEKRecipientInfo,
    pwri [3] PasswordRecipientInfo,
    ori [4] OtherRecipientInfo -- not supported
}"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_recipient_infos(self.ctx, message_info.ctx)
        return result

    def serialized_encrypted_content_info_len(self, message_info):
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_encrypted_content_info_len(self.ctx, message_info.ctx)
        return result

    def serialize_encrypted_content_info(self, message_info):
        """EncryptedContentInfo ::= SEQUENCE {
    contentType ContentType, -- always PKCS#7 'data' OID
    contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
}

ContentType ::= OBJECT IDENTIFIER
ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
EncryptedContent ::= OCTET STRING"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_encrypted_content_info(self.ctx, message_info.ctx)
        return result

    def serialized_enveloped_data_len(self, message_info):
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_enveloped_data_len(self.ctx, message_info.ctx)
        return result

    def serialize_enveloped_data(self, message_info):
        """EnvelopedData ::= SEQUENCE {
    version CMSVersion,
    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo,
    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
}

CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_enveloped_data(self.ctx, message_info.ctx)
        return result

    def serialized_cms_content_info_len(self, message_info):
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_cms_content_info_len(self.ctx, message_info.ctx)
        return result

    def serialize_cms_content_info_(self, message_info):
        """ContentInfo ::= SEQUENCE {
    contentType ContentType,
    content [0] EXPLICIT ANY DEFINED BY contentType
}

ContentType ::= OBJECT IDENTIFIER"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_cms_content_info_(self.ctx, message_info.ctx)
        return result

    def serialized_signer_infos_len(self, message_info_footer):
        """VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_signer_infos_len(self.ctx, message_info_footer.ctx)
        return result

    def serialize_signer_infos(self, message_info_footer):
        """VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_signer_infos(self.ctx, message_info_footer.ctx)
        return result

    def serialized_signer_info_len(self, signer_info):
        """VirgilSignerInfo ::= SEQUENCE {
    version INTEGER { v0(0) } DEFAULT v0,
    signerIdentifier VirgilSignerIdentifier,
    signerAlgorithm VirgilSignerAlgorithm,
    signature VirgilSignatureValue
}

VirgilSignerIdentifier ::= OCTET STRING

VirgilSignerAlgorithm ::= AlgorithmIdentifier

VirgilSignatureValue ::= OCTET STRING"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_signer_info_len(self.ctx, signer_info.ctx)
        return result

    def serialize_signer_info(self, signer_info):
        """VirgilSignerInfo ::= SEQUENCE {
    version INTEGER { v0(0) } DEFAULT v0,
    signerIdentifier VirgilSignerIdentifier,
    signerAlgorithm VirgilSignerAlgorithm,
    signature VirgilSignatureValue
}

VirgilSignerIdentifier ::= OCTET STRING

VirgilSignerAlgorithm ::= AlgorithmIdentifier

VirgilSignatureValue ::= OCTET STRING"""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_signer_info(self.ctx, signer_info.ctx)
        return result

    def deserialize_custom_params(self, custom_params):
        """VirgilCustomParams ::= SET SIZE (1..MAX) OF KeyValue

KeyValue ::= SEQUENCE {
    key Key,
    val Value
}

Key ::= UTF8String

Value ::= CHOICE {
    int [0] EXPLICIT INTEGER,
    str [1] EXPLICIT UTF8String,
    data [2] EXPLICIT OCTET STRING
}"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_custom_params(self.ctx, custom_params.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_cipher_kdf(self, message_info):
        """AlgorithmIdentifier"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_cipher_kdf(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_cipher_padding(self, message_info):
        """AlgorithmIdentifier"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_cipher_padding(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_footer_info(self, message_info):
        """VirgilFooterInfo ::= SEQUENCE {
    version INTEGER { v0(0) },
    dataSize INTEGER,
    signedDataInfo [0] EXPLICIT VirgilSignedDataInfo OPTIONAL
}"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_footer_info(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_signed_data_info(self, message_info):
        """VirgilSignedDataInfo ::= SEQUENCE {
    version INTEGER { v0(0) },
    digestAlgorithm AlgorithmIdentifier
}"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_signed_data_info(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_key_recipient_info(self, message_info):
        """KeyTransRecipientInfo ::= SEQUENCE {
    version CMSVersion, -- always set to 0 or 2
    rid RecipientIdentifier,
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey }

RecipientIdentifier ::= CHOICE {
    issuerAndSerialNumber IssuerAndSerialNumber,
    subjectKeyIdentifier [0] SubjectKeyIdentifier }

SubjectKeyIdentifier ::= OCTET STRING

EncryptedKey ::= OCTET STRING"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_key_recipient_info(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_password_recipient_info(self, message_info):
        """PasswordRecipientInfo ::= SEQUENCE {
    version CMSVersion, -- Always set to 0
    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                               OPTIONAL, -- not used
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey
}"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_password_recipient_info(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_recipient_infos(self, message_info):
        """RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

RecipientInfo ::= CHOICE {
    ktri KeyTransRecipientInfo,
    kari [1] KeyAgreeRecipientInfo, -- not supported
    kekri [2] KEKRecipientInfo,
    pwri [3] PasswordRecipientInfo,
    ori [4] OtherRecipientInfo -- not supported
}"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_recipient_infos(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_encrypted_content_info(self, message_info):
        """EncryptedContentInfo ::= SEQUENCE {
    contentType ContentType, -- always PKCS#7 'data' OID
    contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
}

ContentType ::= OBJECT IDENTIFIER
ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
EncryptedContent ::= OCTET STRING"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_encrypted_content_info(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_enveloped_data(self, message_info):
        """EnvelopedData ::= SEQUENCE {
    version CMSVersion,
    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo,
    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
}

CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_enveloped_data(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_cms_content_info(self, message_info):
        """ContentInfo ::= SEQUENCE {
    contentType ContentType,
    content [0] EXPLICIT ANY DEFINED BY contentType
}

ContentType ::= OBJECT IDENTIFIER"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_cms_content_info(self.ctx, message_info.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_signer_infos(self, message_info_footer):
        """VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_signer_infos(self.ctx, message_info_footer.ctx, error)
        VscfStatus.handle_status(error.status)

    def deserialize_signer_info(self, message_info_footer):
        """VirgilSignerInfo ::= SEQUENCE {
    version INTEGER { v0(0) } DEFAULT v0,
    signerIdentifier VirgilSignerIdentifier,
    signerAlgorithm VirgilSignerAlgorithm,
    signature VirgilSignatureValue
}

VirgilSignerIdentifier ::= OCTET STRING

VirgilSignerAlgorithm ::= AlgorithmIdentifier

VirgilSignatureValue ::= OCTET STRING"""
        error = vscf_error_t()
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_signer_info(self.ctx, message_info_footer.ctx, error)
        VscfStatus.handle_status(error.status)

    def serialized_len(self, message_info):
        """Return buffer size enough to hold serialized message info."""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_len(self.ctx, message_info.ctx)
        return result

    def serialize(self, message_info):
        """Serialize class "message info"."""
        out = Buffer(self.serialized_len(message_info=message_info))
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize(self.ctx, message_info.ctx, out.c_buffer)
        return out.get_bytes()

    def read_prefix(self, data):
        """Read message info prefix from the given data, and if it is valid,
return a length of bytes of the whole message info.

Zero returned if length can not be determined from the given data,
and this means that there is no message info at the data beginning."""
        d_data = Data(data)
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_read_prefix(self.ctx, d_data.data)
        return result

    def deserialize(self, data):
        """Deserialize class "message info"."""
        d_data = Data(data)
        error = vscf_error_t()
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize(self.ctx, d_data.data, error)
        VscfStatus.handle_status(error.status)
        return MessageInfo.take_c_ctx(result)

    def serialized_footer_len(self, message_info_footer):
        """Return buffer size enough to hold serialized message info footer."""
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialized_footer_len(self.ctx, message_info_footer.ctx)
        return result

    def serialize_footer(self, message_info_footer):
        """Serialize class "message info footer"."""
        out = Buffer(self.serialized_footer_len(message_info_footer=message_info_footer))
        self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_serialize_footer(self.ctx, message_info_footer.ctx, out.c_buffer)
        return out.get_bytes()

    def deserialize_footer(self, data):
        """Deserialize class "message info footer"."""
        d_data = Data(data)
        error = vscf_error_t()
        result = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_deserialize_footer(self.ctx, d_data.data, error)
        VscfStatus.handle_status(error.status)
        return MessageInfoFooter.take_c_ctx(result)

    @classmethod
    def take_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_der_serializer = VscfMessageInfoDerSerializer()
        inst.ctx = c_ctx
        return inst

    @classmethod
    def use_c_ctx(cls, c_ctx):
        inst = cls.__new__(cls)
        inst._lib_vscf_message_info_der_serializer = VscfMessageInfoDerSerializer()
        inst.ctx = inst._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_shallow_copy(c_ctx)
        return inst

    @property
    def c_impl(self):
        return self._c_impl

    @property
    def ctx(self):
        return self._ctx

    @ctx.setter
    def ctx(self, value):
        self._ctx = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_shallow_copy(value)
        self._c_impl = self._lib_vscf_message_info_der_serializer.vscf_message_info_der_serializer_impl(self.ctx)
