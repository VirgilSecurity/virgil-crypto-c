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
* Handle information about an encrypted message and algorithms
* that was used for encryption.
*/
class MessageInfo
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
        $this->ctx = is_null($ctx) ? vscf_message_info_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_message_info_delete_php($this->ctx);
    }

    /**
    * Return information about algorithm that was used for the data encryption.
    *
    * @return AlgInfo
    * @throws \Exception
    */
    public function dataEncryptionAlgInfo(): AlgInfo
    {
        $ctx = vscf_message_info_data_encryption_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    * Return list with a "key recipient info" elements.
    *
    * @return KeyRecipientInfoList
    */
    public function keyRecipientInfoList(): KeyRecipientInfoList
    {
        $ctx = vscf_message_info_key_recipient_info_list_php($this->ctx);
        return new KeyRecipientInfoList($ctx);
    }

    /**
    * Return list with a "password recipient info" elements.
    *
    * @return PasswordRecipientInfoList
    */
    public function passwordRecipientInfoList(): PasswordRecipientInfoList
    {
        $ctx = vscf_message_info_password_recipient_info_list_php($this->ctx);
        return new PasswordRecipientInfoList($ctx);
    }

    /**
    * Return true if message info contains at least one custom param.
    *
    * @return bool
    */
    public function hasCustomParams(): bool
    {
        return vscf_message_info_has_custom_params_php($this->ctx);
    }

    /**
    * Provide access to the custom params object.
    * The returned object can be used to add custom params or read it.
    * If custom params object was not set then new empty object is created.
    *
    * @return MessageInfoCustomParams
    */
    public function customParams(): MessageInfoCustomParams
    {
        $ctx = vscf_message_info_custom_params_php($this->ctx);
        return new MessageInfoCustomParams($ctx);
    }

    /**
    * Return true if cipher kdf alg info exists.
    *
    * @return bool
    */
    public function hasCipherKdfAlgInfo(): bool
    {
        return vscf_message_info_has_cipher_kdf_alg_info_php($this->ctx);
    }

    /**
    * Return cipher kdf alg info.
    *
    * @return AlgInfo
    * @throws \Exception
    */
    public function cipherKdfAlgInfo(): AlgInfo
    {
        $ctx = vscf_message_info_cipher_kdf_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    * Return true if cipher padding alg info exists.
    *
    * @return bool
    */
    public function hasCipherPaddingAlgInfo(): bool
    {
        return vscf_message_info_has_cipher_padding_alg_info_php($this->ctx);
    }

    /**
    * Return cipher padding alg info.
    *
    * @return AlgInfo
    * @throws \Exception
    */
    public function cipherPaddingAlgInfo(): AlgInfo
    {
        $ctx = vscf_message_info_cipher_padding_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    * Return true if footer info exists.
    *
    * @return bool
    */
    public function hasFooterInfo(): bool
    {
        return vscf_message_info_has_footer_info_php($this->ctx);
    }

    /**
    * Return footer info.
    *
    * @return FooterInfo
    */
    public function footerInfo(): FooterInfo
    {
        $ctx = vscf_message_info_footer_info_php($this->ctx);
        return new FooterInfo($ctx);
    }

    /**
    * Remove all infos.
    *
    * @return void
    */
    public function clear(): void
    {
        vscf_message_info_clear_php($this->ctx);
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
