<?php
/**
* Copyright (C) 2015-2019 Virgil Security, Inc.
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

namespace VirgilCrypto\Phe;

/**
* Class for encryption using PHE account key
* This class is thread-safe.
*/
class PheCipher
{

    /**
    * @var
    */
    private $ctx;

    const SALT_LEN = 32;
    const KEY_LEN = 32;
    const NONCE_LEN = 12;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vsce_phe_cipher_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vsce_phe_cipher_delete_php($this->ctx);
    }

    /**
    * @param VirgilCrypto\Foundation\Random $random
    * @return void
    */
    public function useRandom(VirgilCrypto\Foundation\Random $random): void
    {
        vsce_phe_cipher_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * Setups dependencies with default values.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vsce_phe_cipher_setup_defaults_php($this->ctx);
    }

    /**
    * Returns buffer capacity needed to fit cipher text
    *
    * @param int $plainTextLen
    * @return int
    */
    public function encryptLen(int $plainTextLen): int
    {
        return vsce_phe_cipher_encrypt_len_php($this->ctx, $plainTextLen);
    }

    /**
    * Returns buffer capacity needed to fit plain text
    *
    * @param int $cipherTextLen
    * @return int
    */
    public function decryptLen(int $cipherTextLen): int
    {
        return vsce_phe_cipher_decrypt_len_php($this->ctx, $cipherTextLen);
    }

    /**
    * Encrypts data using account key
    *
    * @param string $plainText
    * @param string $accountKey
    * @return string
    * @throws \Exception
    */
    public function encrypt(string $plainText, string $accountKey): string
    {
        return vsce_phe_cipher_encrypt_php($this->ctx, $plainText, $accountKey);
    }

    /**
    * Decrypts data using account key
    *
    * @param string $cipherText
    * @param string $accountKey
    * @return string
    * @throws \Exception
    */
    public function decrypt(string $cipherText, string $accountKey): string
    {
        return vsce_phe_cipher_decrypt_php($this->ctx, $cipherText, $accountKey);
    }

    /**
    * Encrypts data (and authenticates additional data) using account key
    *
    * @param string $plainText
    * @param string $additionalData
    * @param string $accountKey
    * @return string
    * @throws \Exception
    */
    public function authEncrypt(string $plainText, string $additionalData, string $accountKey): string
    {
        return vsce_phe_cipher_auth_encrypt_php($this->ctx, $plainText, $additionalData, $accountKey);
    }

    /**
    * Decrypts data (and verifies additional data) using account key
    *
    * @param string $cipherText
    * @param string $additionalData
    * @param string $accountKey
    * @return string
    * @throws \Exception
    */
    public function authDecrypt(string $cipherText, string $additionalData, string $accountKey): string
    {
        return vsce_phe_cipher_auth_decrypt_php($this->ctx, $cipherText, $additionalData, $accountKey);
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
