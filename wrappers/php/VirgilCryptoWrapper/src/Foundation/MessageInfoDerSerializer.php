<?php
/**
* Copyright (C) 2015-2026 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     (1) Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*     (2) Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*
*     (3) Neither the name of the copyright holder nor the names of its
*     contributors may be used to endorse or promote products derived from
*     this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
*/

namespace Virgil\CryptoWrapper\Foundation;

class MessageInfoDerSerializer implements MessageInfoSerializer, MessageInfoFooterSerializer
{

    /**
    * @var
    */
    private $ctx;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_message_info_der_serializer_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_message_info_der_serializer_delete_php($this->ctx);
    }

    /**
    *
    * @param Asn1Reader $$asn1Reader
    * @return void
    */
    public function useAsn1Reader(Asn1Reader $$asn1Reader): void
    {
        vscf_message_info_der_serializer_use_asn1_reader_php($this->ctx, $$asn1Reader);
    }

    /**
    *
    * @param Asn1Writer $$asn1Writer
    * @return void
    */
    public function useAsn1Writer(Asn1Writer $$asn1Writer): void
    {
        vscf_message_info_der_serializer_use_asn1_writer_php($this->ctx, $$asn1Writer);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return int
    */
    public function serializedLen(MessageInfo $$messageInfo): int
    {
        return vscf_message_info_der_serializer_serialized_len_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return string
    */
    public function serialize(MessageInfo $$messageInfo): string
    {
        return vscf_message_info_der_serializer_serialize_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param string $$data
    * @return int
    */
    public function readPrefix(string $$data): int
    {
        return vscf_message_info_der_serializer_read_prefix_php($this->ctx, $$data);
    }

    /**
    *
    * @param string $$data
    * @return MessageInfo
    * @throws \Exception
    */
    public function deserialize(string $$data): MessageInfo
    {
        $ctx = vscf_message_info_der_serializer_deserialize_php($this->ctx, $$data);
        return new MessageInfo($ctx);
    }

    /**
    *
    * @param MessageInfoFooter $$messageInfoFooter
    * @return int
    */
    public function serializedFooterLen(MessageInfoFooter $$messageInfoFooter): int
    {
        return vscf_message_info_der_serializer_serialized_footer_len_php($this->ctx, $$messageInfoFooter);
    }

    /**
    *
    * @param MessageInfoFooter $$messageInfoFooter
    * @return string
    */
    public function serializeFooter(MessageInfoFooter $$messageInfoFooter): string
    {
        return vscf_message_info_der_serializer_serialize_footer_php($this->ctx, $$messageInfoFooter);
    }

    /**
    *
    * @param string $$data
    * @return MessageInfoFooter
    * @throws \Exception
    */
    public function deserializeFooter(string $$data): MessageInfoFooter
    {
        $ctx = vscf_message_info_der_serializer_deserialize_footer_php($this->ctx, $$data);
        return new MessageInfoFooter($ctx);
    }

    /**
    *
    * @return void
    */
    public function setupDefaults(): void
    {
        vscf_message_info_der_serializer_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @param MessageInfoCustomParams $$customParams
    * @return int
    */
    public function serializedCustomParamsLen(MessageInfoCustomParams $$customParams): int
    {
        return vscf_message_info_der_serializer_serialized_custom_params_len_php($this->ctx, $$customParams);
    }

    /**
    *
    * @param MessageInfoCustomParams $$customParams
    * @return int
    */
    public function serializeCustomParams(MessageInfoCustomParams $$customParams): int
    {
        return vscf_message_info_der_serializer_serialize_custom_params_php($this->ctx, $$customParams);
    }

    /**
    *
    * @param FooterInfo $$footerInfo
    * @return int
    */
    public function serializedFooterInfoLen(FooterInfo $$footerInfo): int
    {
        return vscf_message_info_der_serializer_serialized_footer_info_len_php($this->ctx, $$footerInfo);
    }

    /**
    *
    * @param FooterInfo $$footerInfo
    * @return int
    */
    public function serializeFooterInfo(FooterInfo $$footerInfo): int
    {
        return vscf_message_info_der_serializer_serialize_footer_info_php($this->ctx, $$footerInfo);
    }

    /**
    *
    * @param SignedDataInfo $$signedDataInfo
    * @return int
    */
    public function serializeSignedDataInfoInternal(SignedDataInfo $$signedDataInfo): int
    {
        return vscf_message_info_der_serializer_serialize_signed_data_info_internal_php($this->ctx, $$signedDataInfo);
    }

    /**
    *
    * @param KeyRecipientInfo $$keyRecipientInfo
    * @return int
    */
    public function serializedKeyRecipientInfoLen(KeyRecipientInfo $$keyRecipientInfo): int
    {
        return vscf_message_info_der_serializer_serialized_key_recipient_info_len_php($this->ctx, $$keyRecipientInfo);
    }

    /**
    *
    * @param KeyRecipientInfo $$keyRecipientInfo
    * @return int
    */
    public function serializeKeyRecipientInfo(KeyRecipientInfo $$keyRecipientInfo): int
    {
        return vscf_message_info_der_serializer_serialize_key_recipient_info_php($this->ctx, $$keyRecipientInfo);
    }

    /**
    *
    * @param PasswordRecipientInfo $$passwordRecipientInfo
    * @return int
    */
    public function serializedPasswordRecipientInfoLen(PasswordRecipientInfo $$passwordRecipientInfo): int
    {
        return vscf_message_info_der_serializer_serialized_password_recipient_info_len_php($this->ctx, $$passwordRecipientInfo);
    }

    /**
    *
    * @param PasswordRecipientInfo $$passwordRecipientInfo
    * @return int
    */
    public function serializePasswordRecipientInfo(PasswordRecipientInfo $$passwordRecipientInfo): int
    {
        return vscf_message_info_der_serializer_serialize_password_recipient_info_php($this->ctx, $$passwordRecipientInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return int
    */
    public function serializedRecipientInfosLen(MessageInfo $$messageInfo): int
    {
        return vscf_message_info_der_serializer_serialized_recipient_infos_len_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return int
    */
    public function serializeRecipientInfos(MessageInfo $$messageInfo): int
    {
        return vscf_message_info_der_serializer_serialize_recipient_infos_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return int
    */
    public function serializedEncryptedContentInfoLen(MessageInfo $$messageInfo): int
    {
        return vscf_message_info_der_serializer_serialized_encrypted_content_info_len_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return int
    */
    public function serializeEncryptedContentInfo(MessageInfo $$messageInfo): int
    {
        return vscf_message_info_der_serializer_serialize_encrypted_content_info_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return int
    */
    public function serializedEnvelopedDataLen(MessageInfo $$messageInfo): int
    {
        return vscf_message_info_der_serializer_serialized_enveloped_data_len_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return int
    */
    public function serializeEnvelopedData(MessageInfo $$messageInfo): int
    {
        return vscf_message_info_der_serializer_serialize_enveloped_data_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return int
    */
    public function serializedCmsContentInfoLen(MessageInfo $$messageInfo): int
    {
        return vscf_message_info_der_serializer_serialized_cms_content_info_len_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return int
    */
    public function serializeCmsContentInfo(MessageInfo $$messageInfo): int
    {
        return vscf_message_info_der_serializer_serialize_cms_content_info__php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfoFooter $$messageInfoFooter
    * @return int
    */
    public function serializedSignerInfosLen(MessageInfoFooter $$messageInfoFooter): int
    {
        return vscf_message_info_der_serializer_serialized_signer_infos_len_php($this->ctx, $$messageInfoFooter);
    }

    /**
    *
    * @param MessageInfoFooter $$messageInfoFooter
    * @return int
    */
    public function serializeSignerInfos(MessageInfoFooter $$messageInfoFooter): int
    {
        return vscf_message_info_der_serializer_serialize_signer_infos_php($this->ctx, $$messageInfoFooter);
    }

    /**
    *
    * @param SignerInfo $$signerInfo
    * @return int
    */
    public function serializedSignerInfoLen(SignerInfo $$signerInfo): int
    {
        return vscf_message_info_der_serializer_serialized_signer_info_len_php($this->ctx, $$signerInfo);
    }

    /**
    *
    * @param SignerInfo $$signerInfo
    * @return int
    */
    public function serializeSignerInfo(SignerInfo $$signerInfo): int
    {
        return vscf_message_info_der_serializer_serialize_signer_info_php($this->ctx, $$signerInfo);
    }

    /**
    *
    * @param MessageInfoCustomParams $$customParams
    * @return void
    * @throws \Exception
    */
    public function deserializeCustomParams(MessageInfoCustomParams $$customParams): void
    {
        vscf_message_info_der_serializer_deserialize_custom_params_php($this->ctx, $$customParams);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializeCipherKdf(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_cipher_kdf_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializeCipherPadding(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_cipher_padding_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializeFooterInfo(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_footer_info_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializeSignedDataInfo(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_signed_data_info_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializeKeyRecipientInfo(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_key_recipient_info_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializePasswordRecipientInfo(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_password_recipient_info_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializeRecipientInfos(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_recipient_infos_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializeEncryptedContentInfo(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_encrypted_content_info_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializeEnvelopedData(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_enveloped_data_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfo $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function deserializeCmsContentInfo(MessageInfo $$messageInfo): void
    {
        vscf_message_info_der_serializer_deserialize_cms_content_info_php($this->ctx, $$messageInfo);
    }

    /**
    *
    * @param MessageInfoFooter $$messageInfoFooter
    * @return void
    * @throws \Exception
    */
    public function deserializeSignerInfos(MessageInfoFooter $$messageInfoFooter): void
    {
        vscf_message_info_der_serializer_deserialize_signer_infos_php($this->ctx, $$messageInfoFooter);
    }

    /**
    *
    * @param MessageInfoFooter $$messageInfoFooter
    * @return void
    * @throws \Exception
    */
    public function deserializeSignerInfo(MessageInfoFooter $$messageInfoFooter): void
    {
        vscf_message_info_der_serializer_deserialize_signer_info_php($this->ctx, $$messageInfoFooter);
    }

    /**
    * Get C context.
    *
    * @return resource
    */
    public function getCtx()
    {
        return $this->ctx;
    }
}
