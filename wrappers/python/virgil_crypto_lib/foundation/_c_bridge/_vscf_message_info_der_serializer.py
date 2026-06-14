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


from virgil_crypto_lib._libs import *
from ctypes import *
from ._vscf_impl import vscf_impl_t
from virgil_crypto_lib.common._c_bridge import vsc_data_t
from virgil_crypto_lib.common._c_bridge import vsc_buffer_t
from ._vscf_error import vscf_error_t
from ._vscf_footer_info import vscf_footer_info_t
from ._vscf_key_recipient_info import vscf_key_recipient_info_t
from ._vscf_message_info import vscf_message_info_t
from ._vscf_message_info_custom_params import vscf_message_info_custom_params_t
from ._vscf_message_info_footer import vscf_message_info_footer_t
from ._vscf_password_recipient_info import vscf_password_recipient_info_t
from ._vscf_signed_data_info import vscf_signed_data_info_t
from ._vscf_signer_info import vscf_signer_info_t


class vscf_message_info_der_serializer_t(Structure):
    pass


class VscfMessageInfoDerSerializer(object):
    """CMS based serialization of the class "message info"."""


    def __init__(self):
        """Create underlying C context."""
        self._ll = LowLevelLibs()
        self._lib = self._ll.foundation

    def vscf_message_info_der_serializer_new(self):
        vscf_message_info_der_serializer_new = self._lib.vscf_message_info_der_serializer_new
        vscf_message_info_der_serializer_new.argtypes = []
        vscf_message_info_der_serializer_new.restype = POINTER(vscf_message_info_der_serializer_t)
        return vscf_message_info_der_serializer_new()

    def vscf_message_info_der_serializer_delete(self, ctx):
        vscf_message_info_der_serializer_delete = self._lib.vscf_message_info_der_serializer_delete
        vscf_message_info_der_serializer_delete.argtypes = [POINTER(vscf_message_info_der_serializer_t)]
        vscf_message_info_der_serializer_delete.restype = None
        return vscf_message_info_der_serializer_delete(ctx)

    def vscf_message_info_der_serializer_use_asn1_reader(self, ctx, asn1_reader):
        vscf_message_info_der_serializer_use_asn1_reader = self._lib.vscf_message_info_der_serializer_use_asn1_reader
        vscf_message_info_der_serializer_use_asn1_reader.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_impl_t)]
        vscf_message_info_der_serializer_use_asn1_reader.restype = None
        return vscf_message_info_der_serializer_use_asn1_reader(ctx, asn1_reader)

    def vscf_message_info_der_serializer_use_asn1_writer(self, ctx, asn1_writer):
        vscf_message_info_der_serializer_use_asn1_writer = self._lib.vscf_message_info_der_serializer_use_asn1_writer
        vscf_message_info_der_serializer_use_asn1_writer.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_impl_t)]
        vscf_message_info_der_serializer_use_asn1_writer.restype = None
        return vscf_message_info_der_serializer_use_asn1_writer(ctx, asn1_writer)

    def vscf_message_info_der_serializer_setup_defaults(self, ctx):
        """Setup predefined values to the uninitialized class dependencies."""
        vscf_message_info_der_serializer_setup_defaults = self._lib.vscf_message_info_der_serializer_setup_defaults
        vscf_message_info_der_serializer_setup_defaults.argtypes = [POINTER(vscf_message_info_der_serializer_t)]
        vscf_message_info_der_serializer_setup_defaults.restype = None
        return vscf_message_info_der_serializer_setup_defaults(ctx)

    def vscf_message_info_der_serializer_serialized_custom_params_len(self, ctx, custom_params):
        """Return size in bytes enough to hold serialized custom params."""
        vscf_message_info_der_serializer_serialized_custom_params_len = self._lib.vscf_message_info_der_serializer_serialized_custom_params_len
        vscf_message_info_der_serializer_serialized_custom_params_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_custom_params_t)]
        vscf_message_info_der_serializer_serialized_custom_params_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_custom_params_len(ctx, custom_params)

    def vscf_message_info_der_serializer_serialize_custom_params(self, ctx, custom_params):
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
        vscf_message_info_der_serializer_serialize_custom_params = self._lib.vscf_message_info_der_serializer_serialize_custom_params
        vscf_message_info_der_serializer_serialize_custom_params.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_custom_params_t)]
        vscf_message_info_der_serializer_serialize_custom_params.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_custom_params(ctx, custom_params)

    def vscf_message_info_der_serializer_serialized_footer_info_len(self, ctx, footer_info):
        """Return size in bytes enough to hold serialized footer info.

VirgilFooterInfo ::= SEQUENCE {
    version INTEGER { v0(0) },
    dataSize INTEGER,
    signedDataInfo [0] EXPLICIT VirgilSignedDataInfo OPTIONAL
}"""
        vscf_message_info_der_serializer_serialized_footer_info_len = self._lib.vscf_message_info_der_serializer_serialized_footer_info_len
        vscf_message_info_der_serializer_serialized_footer_info_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_footer_info_t)]
        vscf_message_info_der_serializer_serialized_footer_info_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_footer_info_len(ctx, footer_info)

    def vscf_message_info_der_serializer_serialize_footer_info(self, ctx, footer_info):
        """Serialize footer info.

VirgilFooterInfo ::= SEQUENCE {
    version INTEGER { v0(0) },
    dataSize INTEGER,
    signedDataInfo [0] EXPLICIT VirgilSignedDataInfo OPTIONAL
}"""
        vscf_message_info_der_serializer_serialize_footer_info = self._lib.vscf_message_info_der_serializer_serialize_footer_info
        vscf_message_info_der_serializer_serialize_footer_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_footer_info_t)]
        vscf_message_info_der_serializer_serialize_footer_info.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_footer_info(ctx, footer_info)

    def vscf_message_info_der_serializer_serialize_signed_data_info_internal(self, ctx, signed_data_info):
        """Serialized signed data info.

VirgilSignedDataInfo ::= SEQUENCE {
    version INTEGER { v0(0) } DEFAULT v0,
    digestAlgorithm AlgorithmIdentifier
}"""
        vscf_message_info_der_serializer_serialize_signed_data_info_internal = self._lib.vscf_message_info_der_serializer_serialize_signed_data_info_internal
        vscf_message_info_der_serializer_serialize_signed_data_info_internal.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_signed_data_info_t)]
        vscf_message_info_der_serializer_serialize_signed_data_info_internal.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_signed_data_info_internal(ctx, signed_data_info)

    def vscf_message_info_der_serializer_serialized_key_recipient_info_len(self, ctx, key_recipient_info):
        vscf_message_info_der_serializer_serialized_key_recipient_info_len = self._lib.vscf_message_info_der_serializer_serialized_key_recipient_info_len
        vscf_message_info_der_serializer_serialized_key_recipient_info_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_key_recipient_info_t)]
        vscf_message_info_der_serializer_serialized_key_recipient_info_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_key_recipient_info_len(ctx, key_recipient_info)

    def vscf_message_info_der_serializer_serialize_key_recipient_info(self, ctx, key_recipient_info):
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
        vscf_message_info_der_serializer_serialize_key_recipient_info = self._lib.vscf_message_info_der_serializer_serialize_key_recipient_info
        vscf_message_info_der_serializer_serialize_key_recipient_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_key_recipient_info_t)]
        vscf_message_info_der_serializer_serialize_key_recipient_info.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_key_recipient_info(ctx, key_recipient_info)

    def vscf_message_info_der_serializer_serialized_password_recipient_info_len(self, ctx, password_recipient_info):
        vscf_message_info_der_serializer_serialized_password_recipient_info_len = self._lib.vscf_message_info_der_serializer_serialized_password_recipient_info_len
        vscf_message_info_der_serializer_serialized_password_recipient_info_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_password_recipient_info_t)]
        vscf_message_info_der_serializer_serialized_password_recipient_info_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_password_recipient_info_len(ctx, password_recipient_info)

    def vscf_message_info_der_serializer_serialize_password_recipient_info(self, ctx, password_recipient_info):
        """PasswordRecipientInfo ::= SEQUENCE {
    version CMSVersion, -- Always set to 0
    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                               OPTIONAL, -- not used
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey
}"""
        vscf_message_info_der_serializer_serialize_password_recipient_info = self._lib.vscf_message_info_der_serializer_serialize_password_recipient_info
        vscf_message_info_der_serializer_serialize_password_recipient_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_password_recipient_info_t)]
        vscf_message_info_der_serializer_serialize_password_recipient_info.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_password_recipient_info(ctx, password_recipient_info)

    def vscf_message_info_der_serializer_serialized_recipient_infos_len(self, ctx, message_info):
        vscf_message_info_der_serializer_serialized_recipient_infos_len = self._lib.vscf_message_info_der_serializer_serialized_recipient_infos_len
        vscf_message_info_der_serializer_serialized_recipient_infos_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialized_recipient_infos_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_recipient_infos_len(ctx, message_info)

    def vscf_message_info_der_serializer_serialize_recipient_infos(self, ctx, message_info):
        """RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

RecipientInfo ::= CHOICE {
    ktri KeyTransRecipientInfo,
    kari [1] KeyAgreeRecipientInfo, -- not supported
    kekri [2] KEKRecipientInfo,
    pwri [3] PasswordRecipientInfo,
    ori [4] OtherRecipientInfo -- not supported
}"""
        vscf_message_info_der_serializer_serialize_recipient_infos = self._lib.vscf_message_info_der_serializer_serialize_recipient_infos
        vscf_message_info_der_serializer_serialize_recipient_infos.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialize_recipient_infos.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_recipient_infos(ctx, message_info)

    def vscf_message_info_der_serializer_serialized_encrypted_content_info_len(self, ctx, message_info):
        vscf_message_info_der_serializer_serialized_encrypted_content_info_len = self._lib.vscf_message_info_der_serializer_serialized_encrypted_content_info_len
        vscf_message_info_der_serializer_serialized_encrypted_content_info_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialized_encrypted_content_info_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_encrypted_content_info_len(ctx, message_info)

    def vscf_message_info_der_serializer_serialize_encrypted_content_info(self, ctx, message_info):
        """EncryptedContentInfo ::= SEQUENCE {
    contentType ContentType, -- always PKCS#7 'data' OID
    contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
}

ContentType ::= OBJECT IDENTIFIER
ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
EncryptedContent ::= OCTET STRING"""
        vscf_message_info_der_serializer_serialize_encrypted_content_info = self._lib.vscf_message_info_der_serializer_serialize_encrypted_content_info
        vscf_message_info_der_serializer_serialize_encrypted_content_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialize_encrypted_content_info.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_encrypted_content_info(ctx, message_info)

    def vscf_message_info_der_serializer_serialized_enveloped_data_len(self, ctx, message_info):
        vscf_message_info_der_serializer_serialized_enveloped_data_len = self._lib.vscf_message_info_der_serializer_serialized_enveloped_data_len
        vscf_message_info_der_serializer_serialized_enveloped_data_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialized_enveloped_data_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_enveloped_data_len(ctx, message_info)

    def vscf_message_info_der_serializer_serialize_enveloped_data(self, ctx, message_info):
        """EnvelopedData ::= SEQUENCE {
    version CMSVersion,
    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo,
    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
}

CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }"""
        vscf_message_info_der_serializer_serialize_enveloped_data = self._lib.vscf_message_info_der_serializer_serialize_enveloped_data
        vscf_message_info_der_serializer_serialize_enveloped_data.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialize_enveloped_data.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_enveloped_data(ctx, message_info)

    def vscf_message_info_der_serializer_serialized_cms_content_info_len(self, ctx, message_info):
        vscf_message_info_der_serializer_serialized_cms_content_info_len = self._lib.vscf_message_info_der_serializer_serialized_cms_content_info_len
        vscf_message_info_der_serializer_serialized_cms_content_info_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialized_cms_content_info_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_cms_content_info_len(ctx, message_info)

    def vscf_message_info_der_serializer_serialize_cms_content_info_(self, ctx, message_info):
        """ContentInfo ::= SEQUENCE {
    contentType ContentType,
    content [0] EXPLICIT ANY DEFINED BY contentType
}

ContentType ::= OBJECT IDENTIFIER"""
        vscf_message_info_der_serializer_serialize_cms_content_info_ = self._lib.vscf_message_info_der_serializer_serialize_cms_content_info_
        vscf_message_info_der_serializer_serialize_cms_content_info_.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialize_cms_content_info_.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_cms_content_info_(ctx, message_info)

    def vscf_message_info_der_serializer_serialized_signer_infos_len(self, ctx, message_info_footer):
        """VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo"""
        vscf_message_info_der_serializer_serialized_signer_infos_len = self._lib.vscf_message_info_der_serializer_serialized_signer_infos_len
        vscf_message_info_der_serializer_serialized_signer_infos_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_footer_t)]
        vscf_message_info_der_serializer_serialized_signer_infos_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_signer_infos_len(ctx, message_info_footer)

    def vscf_message_info_der_serializer_serialize_signer_infos(self, ctx, message_info_footer):
        """VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo"""
        vscf_message_info_der_serializer_serialize_signer_infos = self._lib.vscf_message_info_der_serializer_serialize_signer_infos
        vscf_message_info_der_serializer_serialize_signer_infos.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_footer_t)]
        vscf_message_info_der_serializer_serialize_signer_infos.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_signer_infos(ctx, message_info_footer)

    def vscf_message_info_der_serializer_serialized_signer_info_len(self, ctx, signer_info):
        """VirgilSignerInfo ::= SEQUENCE {
    version INTEGER { v0(0) } DEFAULT v0,
    signerIdentifier VirgilSignerIdentifier,
    signerAlgorithm VirgilSignerAlgorithm,
    signature VirgilSignatureValue
}

VirgilSignerIdentifier ::= OCTET STRING

VirgilSignerAlgorithm ::= AlgorithmIdentifier

VirgilSignatureValue ::= OCTET STRING"""
        vscf_message_info_der_serializer_serialized_signer_info_len = self._lib.vscf_message_info_der_serializer_serialized_signer_info_len
        vscf_message_info_der_serializer_serialized_signer_info_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_signer_info_t)]
        vscf_message_info_der_serializer_serialized_signer_info_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_signer_info_len(ctx, signer_info)

    def vscf_message_info_der_serializer_serialize_signer_info(self, ctx, signer_info):
        """VirgilSignerInfo ::= SEQUENCE {
    version INTEGER { v0(0) } DEFAULT v0,
    signerIdentifier VirgilSignerIdentifier,
    signerAlgorithm VirgilSignerAlgorithm,
    signature VirgilSignatureValue
}

VirgilSignerIdentifier ::= OCTET STRING

VirgilSignerAlgorithm ::= AlgorithmIdentifier

VirgilSignatureValue ::= OCTET STRING"""
        vscf_message_info_der_serializer_serialize_signer_info = self._lib.vscf_message_info_der_serializer_serialize_signer_info
        vscf_message_info_der_serializer_serialize_signer_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_signer_info_t)]
        vscf_message_info_der_serializer_serialize_signer_info.restype = c_size_t
        return vscf_message_info_der_serializer_serialize_signer_info(ctx, signer_info)

    def vscf_message_info_der_serializer_deserialize_custom_params(self, ctx, custom_params, error):
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
        vscf_message_info_der_serializer_deserialize_custom_params = self._lib.vscf_message_info_der_serializer_deserialize_custom_params
        vscf_message_info_der_serializer_deserialize_custom_params.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_custom_params_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_custom_params.restype = None
        return vscf_message_info_der_serializer_deserialize_custom_params(ctx, custom_params, error)

    def vscf_message_info_der_serializer_deserialize_cipher_kdf(self, ctx, message_info, error):
        """AlgorithmIdentifier"""
        vscf_message_info_der_serializer_deserialize_cipher_kdf = self._lib.vscf_message_info_der_serializer_deserialize_cipher_kdf
        vscf_message_info_der_serializer_deserialize_cipher_kdf.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_cipher_kdf.restype = None
        return vscf_message_info_der_serializer_deserialize_cipher_kdf(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_cipher_padding(self, ctx, message_info, error):
        """AlgorithmIdentifier"""
        vscf_message_info_der_serializer_deserialize_cipher_padding = self._lib.vscf_message_info_der_serializer_deserialize_cipher_padding
        vscf_message_info_der_serializer_deserialize_cipher_padding.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_cipher_padding.restype = None
        return vscf_message_info_der_serializer_deserialize_cipher_padding(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_footer_info(self, ctx, message_info, error):
        """VirgilFooterInfo ::= SEQUENCE {
    version INTEGER { v0(0) },
    dataSize INTEGER,
    signedDataInfo [0] EXPLICIT VirgilSignedDataInfo OPTIONAL
}"""
        vscf_message_info_der_serializer_deserialize_footer_info = self._lib.vscf_message_info_der_serializer_deserialize_footer_info
        vscf_message_info_der_serializer_deserialize_footer_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_footer_info.restype = None
        return vscf_message_info_der_serializer_deserialize_footer_info(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_signed_data_info(self, ctx, message_info, error):
        """VirgilSignedDataInfo ::= SEQUENCE {
    version INTEGER { v0(0) },
    digestAlgorithm AlgorithmIdentifier
}"""
        vscf_message_info_der_serializer_deserialize_signed_data_info = self._lib.vscf_message_info_der_serializer_deserialize_signed_data_info
        vscf_message_info_der_serializer_deserialize_signed_data_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_signed_data_info.restype = None
        return vscf_message_info_der_serializer_deserialize_signed_data_info(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_key_recipient_info(self, ctx, message_info, error):
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
        vscf_message_info_der_serializer_deserialize_key_recipient_info = self._lib.vscf_message_info_der_serializer_deserialize_key_recipient_info
        vscf_message_info_der_serializer_deserialize_key_recipient_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_key_recipient_info.restype = None
        return vscf_message_info_der_serializer_deserialize_key_recipient_info(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_password_recipient_info(self, ctx, message_info, error):
        """PasswordRecipientInfo ::= SEQUENCE {
    version CMSVersion, -- Always set to 0
    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                               OPTIONAL, -- not used
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey
}"""
        vscf_message_info_der_serializer_deserialize_password_recipient_info = self._lib.vscf_message_info_der_serializer_deserialize_password_recipient_info
        vscf_message_info_der_serializer_deserialize_password_recipient_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_password_recipient_info.restype = None
        return vscf_message_info_der_serializer_deserialize_password_recipient_info(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_recipient_infos(self, ctx, message_info, error):
        """RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

RecipientInfo ::= CHOICE {
    ktri KeyTransRecipientInfo,
    kari [1] KeyAgreeRecipientInfo, -- not supported
    kekri [2] KEKRecipientInfo,
    pwri [3] PasswordRecipientInfo,
    ori [4] OtherRecipientInfo -- not supported
}"""
        vscf_message_info_der_serializer_deserialize_recipient_infos = self._lib.vscf_message_info_der_serializer_deserialize_recipient_infos
        vscf_message_info_der_serializer_deserialize_recipient_infos.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_recipient_infos.restype = None
        return vscf_message_info_der_serializer_deserialize_recipient_infos(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_encrypted_content_info(self, ctx, message_info, error):
        """EncryptedContentInfo ::= SEQUENCE {
    contentType ContentType, -- always PKCS#7 'data' OID
    contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL -- not used
}

ContentType ::= OBJECT IDENTIFIER
ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
EncryptedContent ::= OCTET STRING"""
        vscf_message_info_der_serializer_deserialize_encrypted_content_info = self._lib.vscf_message_info_der_serializer_deserialize_encrypted_content_info
        vscf_message_info_der_serializer_deserialize_encrypted_content_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_encrypted_content_info.restype = None
        return vscf_message_info_der_serializer_deserialize_encrypted_content_info(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_enveloped_data(self, ctx, message_info, error):
        """EnvelopedData ::= SEQUENCE {
    version CMSVersion,
    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL, -- not used
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo,
    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL -- not used
}

CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }"""
        vscf_message_info_der_serializer_deserialize_enveloped_data = self._lib.vscf_message_info_der_serializer_deserialize_enveloped_data
        vscf_message_info_der_serializer_deserialize_enveloped_data.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_enveloped_data.restype = None
        return vscf_message_info_der_serializer_deserialize_enveloped_data(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_cms_content_info(self, ctx, message_info, error):
        """ContentInfo ::= SEQUENCE {
    contentType ContentType,
    content [0] EXPLICIT ANY DEFINED BY contentType
}

ContentType ::= OBJECT IDENTIFIER"""
        vscf_message_info_der_serializer_deserialize_cms_content_info = self._lib.vscf_message_info_der_serializer_deserialize_cms_content_info
        vscf_message_info_der_serializer_deserialize_cms_content_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_cms_content_info.restype = None
        return vscf_message_info_der_serializer_deserialize_cms_content_info(ctx, message_info, error)

    def vscf_message_info_der_serializer_deserialize_signer_infos(self, ctx, message_info_footer, error):
        """VirgilSignerInfos ::= SET SIZE (1..MAX) OF VirgilSignerInfo"""
        vscf_message_info_der_serializer_deserialize_signer_infos = self._lib.vscf_message_info_der_serializer_deserialize_signer_infos
        vscf_message_info_der_serializer_deserialize_signer_infos.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_footer_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_signer_infos.restype = None
        return vscf_message_info_der_serializer_deserialize_signer_infos(ctx, message_info_footer, error)

    def vscf_message_info_der_serializer_deserialize_signer_info(self, ctx, message_info_footer, error):
        """VirgilSignerInfo ::= SEQUENCE {
    version INTEGER { v0(0) } DEFAULT v0,
    signerIdentifier VirgilSignerIdentifier,
    signerAlgorithm VirgilSignerAlgorithm,
    signature VirgilSignatureValue
}

VirgilSignerIdentifier ::= OCTET STRING

VirgilSignerAlgorithm ::= AlgorithmIdentifier

VirgilSignatureValue ::= OCTET STRING"""
        vscf_message_info_der_serializer_deserialize_signer_info = self._lib.vscf_message_info_der_serializer_deserialize_signer_info
        vscf_message_info_der_serializer_deserialize_signer_info.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_footer_t), POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_signer_info.restype = None
        return vscf_message_info_der_serializer_deserialize_signer_info(ctx, message_info_footer, error)

    def vscf_message_info_der_serializer_serialized_len(self, ctx, message_info):
        """Return buffer size enough to hold serialized message info."""
        vscf_message_info_der_serializer_serialized_len = self._lib.vscf_message_info_der_serializer_serialized_len
        vscf_message_info_der_serializer_serialized_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t)]
        vscf_message_info_der_serializer_serialized_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_len(ctx, message_info)

    def vscf_message_info_der_serializer_serialize(self, ctx, message_info, out):
        """Serialize class "message info"."""
        vscf_message_info_der_serializer_serialize = self._lib.vscf_message_info_der_serializer_serialize
        vscf_message_info_der_serializer_serialize.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_t), POINTER(vsc_buffer_t)]
        vscf_message_info_der_serializer_serialize.restype = None
        return vscf_message_info_der_serializer_serialize(ctx, message_info, out)

    def vscf_message_info_der_serializer_read_prefix(self, ctx, data):
        """Read message info prefix from the given data, and if it is valid,
return a length of bytes of the whole message info.

Zero returned if length can not be determined from the given data,
and this means that there is no message info at the data beginning."""
        vscf_message_info_der_serializer_read_prefix = self._lib.vscf_message_info_der_serializer_read_prefix
        vscf_message_info_der_serializer_read_prefix.argtypes = [POINTER(vscf_message_info_der_serializer_t), vsc_data_t]
        vscf_message_info_der_serializer_read_prefix.restype = c_size_t
        return vscf_message_info_der_serializer_read_prefix(ctx, data)

    def vscf_message_info_der_serializer_deserialize(self, ctx, data, error):
        """Deserialize class "message info"."""
        vscf_message_info_der_serializer_deserialize = self._lib.vscf_message_info_der_serializer_deserialize
        vscf_message_info_der_serializer_deserialize.argtypes = [POINTER(vscf_message_info_der_serializer_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize.restype = POINTER(vscf_message_info_t)
        return vscf_message_info_der_serializer_deserialize(ctx, data, error)

    def vscf_message_info_der_serializer_serialized_footer_len(self, ctx, message_info_footer):
        """Return buffer size enough to hold serialized message info footer."""
        vscf_message_info_der_serializer_serialized_footer_len = self._lib.vscf_message_info_der_serializer_serialized_footer_len
        vscf_message_info_der_serializer_serialized_footer_len.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_footer_t)]
        vscf_message_info_der_serializer_serialized_footer_len.restype = c_size_t
        return vscf_message_info_der_serializer_serialized_footer_len(ctx, message_info_footer)

    def vscf_message_info_der_serializer_serialize_footer(self, ctx, message_info_footer, out):
        """Serialize class "message info footer"."""
        vscf_message_info_der_serializer_serialize_footer = self._lib.vscf_message_info_der_serializer_serialize_footer
        vscf_message_info_der_serializer_serialize_footer.argtypes = [POINTER(vscf_message_info_der_serializer_t), POINTER(vscf_message_info_footer_t), POINTER(vsc_buffer_t)]
        vscf_message_info_der_serializer_serialize_footer.restype = None
        return vscf_message_info_der_serializer_serialize_footer(ctx, message_info_footer, out)

    def vscf_message_info_der_serializer_deserialize_footer(self, ctx, data, error):
        """Deserialize class "message info footer"."""
        vscf_message_info_der_serializer_deserialize_footer = self._lib.vscf_message_info_der_serializer_deserialize_footer
        vscf_message_info_der_serializer_deserialize_footer.argtypes = [POINTER(vscf_message_info_der_serializer_t), vsc_data_t, POINTER(vscf_error_t)]
        vscf_message_info_der_serializer_deserialize_footer.restype = POINTER(vscf_message_info_footer_t)
        return vscf_message_info_der_serializer_deserialize_footer(ctx, data, error)

    def vscf_message_info_der_serializer_shallow_copy(self, ctx):
        vscf_message_info_der_serializer_shallow_copy = self._lib.vscf_message_info_der_serializer_shallow_copy
        vscf_message_info_der_serializer_shallow_copy.argtypes = [POINTER(vscf_message_info_der_serializer_t)]
        vscf_message_info_der_serializer_shallow_copy.restype = POINTER(vscf_message_info_der_serializer_t)
        return vscf_message_info_der_serializer_shallow_copy(ctx)

    def vscf_message_info_der_serializer_impl(self, ctx):
        vscf_message_info_der_serializer_impl = self._lib.vscf_message_info_der_serializer_impl
        vscf_message_info_der_serializer_impl.argtypes = [POINTER(vscf_message_info_der_serializer_t)]
        vscf_message_info_der_serializer_impl.restype = POINTER(vscf_impl_t)
        return vscf_message_info_der_serializer_impl(ctx)
