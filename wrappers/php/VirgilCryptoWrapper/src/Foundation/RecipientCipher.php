<?php
/**
* Copyright (C) 2015-2022 Virgil Security, Inc.
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

class RecipientCipher
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
        $this->ctx = is_null($ctx) ? vscf_recipient_cipher_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_recipient_cipher_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$random
    * @return void
    */
    public function useRandom(Random $$random): void
    {
        vscf_recipient_cipher_use_random_php($this->ctx, $$random);
    }

    /**
    *
    * @param Cipher $$encryptionCipher
    * @return void
    */
    public function useEncryptionCipher(Cipher $$encryptionCipher): void
    {
        vscf_recipient_cipher_use_encryption_cipher_php($this->ctx, $$encryptionCipher);
    }

    /**
    *
    * @param Padding $$encryptionPadding
    * @return void
    */
    public function useEncryptionPadding(Padding $$encryptionPadding): void
    {
        vscf_recipient_cipher_use_encryption_padding_php($this->ctx, $$encryptionPadding);
    }

    /**
    *
    * @param PaddingParams $$paddingParams
    * @return void
    */
    public function usePaddingParams(PaddingParams $$paddingParams): void
    {
        vscf_recipient_cipher_use_padding_params_php($this->ctx, $$paddingParams);
    }

    /**
    *
    * @param Hash $$signerHash
    * @return void
    */
    public function useSignerHash(Hash $$signerHash): void
    {
        vscf_recipient_cipher_use_signer_hash_php($this->ctx, $$signerHash);
    }

    /**
    *
    * @param string $$recipientId
    * @return bool
    */
    public function hasKeyRecipient(string $$recipientId): bool
    {
        return vscf_recipient_cipher_has_key_recipient_php($this->ctx, $$recipientId);
    }

    /**
    *
    * @param string $$recipientId
    * @param PublicKey $$publicKey
    * @return void
    */
    public function addKeyRecipient(string $$recipientId, PublicKey $$publicKey): void
    {
        vscf_recipient_cipher_add_key_recipient_php($this->ctx, $$recipientId, $$publicKey);
    }

    /**
    *
    * @return void
    */
    public function clearRecipients(): void
    {
        vscf_recipient_cipher_clear_recipients_php($this->ctx);
    }

    /**
    *
    * @param string $$signerId
    * @param PrivateKey $$privateKey
    * @return void
    * @throws \Exception
    */
    public function addSigner(string $$signerId, PrivateKey $$privateKey): void
    {
        vscf_recipient_cipher_add_signer_php($this->ctx, $$signerId, $$privateKey);
    }

    /**
    *
    * @return void
    */
    public function clearSigners(): void
    {
        vscf_recipient_cipher_clear_signers_php($this->ctx);
    }

    /**
    *
    * @return MessageInfoCustomParams
    */
    public function customParams(): MessageInfoCustomParams
    {
        $ctx = vscf_recipient_cipher_custom_params_php($this->ctx);
        return new MessageInfoCustomParams($ctx);
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function startEncryption(): void
    {
        vscf_recipient_cipher_start_encryption_php($this->ctx);
    }

    /**
    *
    * @param int $$dataSize
    * @return void
    * @throws \Exception
    */
    public function startSignedEncryption(int $$dataSize): void
    {
        vscf_recipient_cipher_start_signed_encryption_php($this->ctx, $$dataSize);
    }

    /**
    *
    * @return int
    */
    public function messageInfoLen(): int
    {
        return vscf_recipient_cipher_message_info_len_php($this->ctx);
    }

    /**
    *
    * @return string
    */
    public function packMessageInfo(): string
    {
        return vscf_recipient_cipher_pack_message_info_php($this->ctx);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function encryptionOutLen(int $$dataLen): int
    {
        return vscf_recipient_cipher_encryption_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function processEncryption(string $$data): string
    {
        return vscf_recipient_cipher_process_encryption_php($this->ctx, $$data);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function finishEncryption(): string
    {
        return vscf_recipient_cipher_finish_encryption_php($this->ctx);
    }

    /**
    *
    * @param string $$recipientId
    * @param PrivateKey $$privateKey
    * @param string $$messageInfo
    * @return void
    * @throws \Exception
    */
    public function startDecryptionWithKey(string $$recipientId, PrivateKey $$privateKey, string $$messageInfo): void
    {
        vscf_recipient_cipher_start_decryption_with_key_php($this->ctx, $$recipientId, $$privateKey, $$messageInfo);
    }

    /**
    *
    * @param string $$recipientId
    * @param PrivateKey $$privateKey
    * @param string $$messageInfo
    * @param string $$messageInfoFooter
    * @return void
    * @throws \Exception
    */
    public function startVerifiedDecryptionWithKey(string $$recipientId, PrivateKey $$privateKey, string $$messageInfo, string $$messageInfoFooter): void
    {
        vscf_recipient_cipher_start_verified_decryption_with_key_php($this->ctx, $$recipientId, $$privateKey, $$messageInfo, $$messageInfoFooter);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function decryptionOutLen(int $$dataLen): int
    {
        return vscf_recipient_cipher_decryption_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function processDecryption(string $$data): string
    {
        return vscf_recipient_cipher_process_decryption_php($this->ctx, $$data);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function finishDecryption(): string
    {
        return vscf_recipient_cipher_finish_decryption_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function isDataSigned(): bool
    {
        return vscf_recipient_cipher_is_data_signed_php($this->ctx);
    }

    /**
    *
    * @return SignerInfoList
    */
    public function signerInfos(): SignerInfoList
    {
        $ctx = vscf_recipient_cipher_signer_infos_php($this->ctx);
        return new SignerInfoList($ctx);
    }

    /**
    *
    * @param SignerInfo $$signerInfo
    * @param PublicKey $$publicKey
    * @return bool
    */
    public function verifySignerInfo(SignerInfo $$signerInfo, PublicKey $$publicKey): bool
    {
        return vscf_recipient_cipher_verify_signer_info_php($this->ctx, $$signerInfo, $$publicKey);
    }

    /**
    *
    * @return int
    */
    public function messageInfoFooterLen(): int
    {
        return vscf_recipient_cipher_message_info_footer_len_php($this->ctx);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function packMessageInfoFooter(): string
    {
        return vscf_recipient_cipher_pack_message_info_footer_php($this->ctx);
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
