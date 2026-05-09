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

class Aes256Gcm implements Alg, Encrypt, Decrypt, CipherInfo, Cipher, CipherAuthInfo, AuthEncrypt, AuthDecrypt, CipherAuth
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
        $this->ctx = is_null($ctx) ? vscf_aes256_gcm_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_aes256_gcm_delete_php($this->ctx);
    }

    /**
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_aes256_gcm_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgInfo
    */
    public function produceAlgInfo(): AlgInfo
    {
        $ctx = vscf_aes256_gcm_produce_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return void
    * @throws \Exception
    */
    public function restoreAlgInfo(AlgInfo $$algInfo): void
    {
        vscf_aes256_gcm_restore_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function encrypt(string $$data): string
    {
        return vscf_aes256_gcm_encrypt_php($this->ctx, $$data);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function encryptedLen(int $$dataLen): int
    {
        return vscf_aes256_gcm_encrypted_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function preciseEncryptedLen(int $$dataLen): int
    {
        return vscf_aes256_gcm_precise_encrypted_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function decrypt(string $$data): string
    {
        return vscf_aes256_gcm_decrypt_php($this->ctx, $$data);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function decryptedLen(int $$dataLen): int
    {
        return vscf_aes256_gcm_decrypted_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$nonce
    * @return void
    */
    public function setNonce(string $$nonce): void
    {
        vscf_aes256_gcm_set_nonce_php($this->ctx, $$nonce);
    }

    /**
    *
    * @param string $$key
    * @return void
    */
    public function setKey(string $$key): void
    {
        vscf_aes256_gcm_set_key_php($this->ctx, $$key);
    }

    /**
    *
    * @return void
    */
    public function startEncryption(): void
    {
        vscf_aes256_gcm_start_encryption_php($this->ctx);
    }

    /**
    *
    * @return void
    */
    public function startDecryption(): void
    {
        vscf_aes256_gcm_start_decryption_php($this->ctx);
    }

    /**
    *
    * @param string $$data
    * @return string
    */
    public function update(string $$data): string
    {
        return vscf_aes256_gcm_update_php($this->ctx, $$data);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function outLen(int $$dataLen): int
    {
        return vscf_aes256_gcm_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function encryptedOutLen(int $$dataLen): int
    {
        return vscf_aes256_gcm_encrypted_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function decryptedOutLen(int $$dataLen): int
    {
        return vscf_aes256_gcm_decrypted_out_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function finish(): string
    {
        return vscf_aes256_gcm_finish_php($this->ctx);
    }

    /**
    *
    * @param string $$data
    * @param string $$authData
    * @return array
    * @throws \Exception
    */
    public function authEncrypt(string $$data, string $$authData)
    {
        return vscf_aes256_gcm_auth_encrypt_php($this->ctx, $$data, $$authData);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function authEncryptedLen(int $$dataLen): int
    {
        return vscf_aes256_gcm_auth_encrypted_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$data
    * @param string $$authData
    * @param string $$tag
    * @return string
    * @throws \Exception
    */
    public function authDecrypt(string $$data, string $$authData, string $$tag): string
    {
        return vscf_aes256_gcm_auth_decrypt_php($this->ctx, $$data, $$authData, $$tag);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function authDecryptedLen(int $$dataLen): int
    {
        return vscf_aes256_gcm_auth_decrypted_len_php($this->ctx, $$dataLen);
    }

    /**
    *
    * @param string $$authData
    * @return void
    */
    public function setAuthData(string $$authData): void
    {
        vscf_aes256_gcm_set_auth_data_php($this->ctx, $$authData);
    }

    /**
    *
    * @return array
    * @throws \Exception
    */
    public function finishAuthEncryption()
    {
        return vscf_aes256_gcm_finish_auth_encryption_php($this->ctx);
    }

    /**
    *
    * @param string $$tag
    * @return string
    * @throws \Exception
    */
    public function finishAuthDecryption(string $$tag): string
    {
        return vscf_aes256_gcm_finish_auth_decryption_php($this->ctx, $$tag);
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
