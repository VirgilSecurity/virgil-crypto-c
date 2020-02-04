<?php
/**
* Copyright (C) 2015-2020 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
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

/**
* CMS based serialization of the class "message info".
*/
class MessageInfoDerSerializer implements MessageInfoSerializer, MessageInfoFooterSerializer
{

    /**
    * @var
    */
    private $ctx;

    const PREFIX_LEN = 32;

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
    * @param Asn1Reader $asn1Reader
    * @return void
    */
    public function useAsn1Reader(Asn1Reader $asn1Reader): void
    {
        vscf_message_info_der_serializer_use_asn1_reader_php($this->ctx, $asn1Reader->getCtx());
    }

    /**
    * @param Asn1Writer $asn1Writer
    * @return void
    */
    public function useAsn1Writer(Asn1Writer $asn1Writer): void
    {
        vscf_message_info_der_serializer_use_asn1_writer_php($this->ctx, $asn1Writer->getCtx());
    }

    /**
    * Setup predefined values to the uninitialized class dependencies.
    *
    * @return void
    */
    public function setupDefaults(): void
    {
        vscf_message_info_der_serializer_setup_defaults_php($this->ctx);
    }

    /**
    * Return buffer size enough to hold serialized message info.
    *
    * @param MessageInfo $messageInfo
    * @return int
    */
    public function serializedLen(MessageInfo $messageInfo): int
    {
        return vscf_message_info_der_serializer_serialized_len_php($this->ctx, $messageInfo->getCtx());
    }

    /**
    * Serialize class "message info".
    *
    * @param MessageInfo $messageInfo
    * @return string
    */
    public function serialize(MessageInfo $messageInfo): string
    {
        return vscf_message_info_der_serializer_serialize_php($this->ctx, $messageInfo->getCtx());
    }

    /**
    * Read message info prefix from the given data, and if it is valid,
    * return a length of bytes of the whole message info.
    *
    * Zero returned if length can not be determined from the given data,
    * and this means that there is no message info at the data beginning.
    *
    * @param string $data
    * @return int
    */
    public function readPrefix(string $data): int
    {
        return vscf_message_info_der_serializer_read_prefix_php($this->ctx, $data);
    }

    /**
    * Deserialize class "message info".
    *
    * @param string $data
    * @return MessageInfo
    */
    public function deserialize(string $data): MessageInfo
    {
        $ctx = vscf_message_info_der_serializer_deserialize_php($this->ctx, $data);
        return new MessageInfo($ctx);
    }

    /**
    * Return buffer size enough to hold serialized message info footer.
    *
    * @param MessageInfoFooter $messageInfoFooter
    * @return int
    */
    public function serializedFooterLen(MessageInfoFooter $messageInfoFooter): int
    {
        return vscf_message_info_der_serializer_serialized_footer_len_php($this->ctx, $messageInfoFooter->getCtx());
    }

    /**
    * Serialize class "message info footer".
    *
    * @param MessageInfoFooter $messageInfoFooter
    * @return string
    */
    public function serializeFooter(MessageInfoFooter $messageInfoFooter): string
    {
        return vscf_message_info_der_serializer_serialize_footer_php($this->ctx, $messageInfoFooter->getCtx());
    }

    /**
    * Deserialize class "message info footer".
    *
    * @param string $data
    * @return MessageInfoFooter
    */
    public function deserializeFooter(string $data): MessageInfoFooter
    {
        $ctx = vscf_message_info_der_serializer_deserialize_footer_php($this->ctx, $data);
        return new MessageInfoFooter($ctx);
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
