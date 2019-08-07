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

/**
* Class for encryption using PHE account key
* This class is thread-safe.
*/
class PheCipher
{
    private $ctx;

    /**
    * Create underlying C context.
    * @return void
    */
    public function __construct()
    {
        $this->ctx = vsce_phe_cipher_new_php();
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destruct()
    {
        vsce_phe_cipher_delete_php($this->ctx);
    }

    /**
    * Setups dependencies with default values.
    *
    * @throws Exception
    * @return void
    */
    public function setupDefaults(): void
    {
        return vsce_phe_cipher_setup_defaults_php($this->ctx);
    }

    /**
    * Returns buffer capacity needed to fit cipher text
    *
    * @return void
    */
    public function encryptLen(): void
    {
        return vsce_phe_cipher_encrypt_len_php($this->ctx);
    }

    /**
    * Returns buffer capacity needed to fit plain text
    *
    * @return void
    */
    public function decryptLen(): void
    {
        return vsce_phe_cipher_decrypt_len_php($this->ctx);
    }

    /**
    * Encrypts data using account key
    *
    * @param string $plainText
    * @param string $accountKey
    * @throws Exception
    * @return string
    */
    public function encrypt(string $plainText, string $accountKey): string // cipher_text
    {
        return vsce_phe_cipher_encrypt_php($this->ctx, $plainText, $accountKey);
    }

    /**
    * Decrypts data using account key
    *
    * @param string $cipherText
    * @param string $accountKey
    * @throws Exception
    * @return string
    */
    public function decrypt(string $cipherText, string $accountKey): string // plain_text
    {
        return vsce_phe_cipher_decrypt_php($this->ctx, $cipherText, $accountKey);
    }
}
