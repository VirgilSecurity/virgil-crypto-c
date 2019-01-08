<?php
/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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

/**
 * Class PHECipher
 */
class PHECipher
{
    /**
     * @var
     */
    private $c_ctx;

    /**
     * PHECipher constructor.
     * @return void
     */
    public function __construct()
    {
        $this->c_ctx = vsce_phe_cipher_new_php();
    }

    /**
     * PHECipher destructor.
     * @return void
     */
    public function __destruct()
    {
        vsce_phe_cipher_delete_php($this->c_ctx);
    }

    /**
     * @return void
     */
    public function setupDefaults()
    {
        vsce_phe_cipher_setup_defaults_php($this->c_ctx);
    }

    /**
     * @param string $plainText
     * @param string $accountKey
     * @return string
     */
    public function encrypt(string $plainText, string $accountKey): string
    {
        return vsce_phe_cipher_encrypt_php($this->c_ctx, $plainText, $accountKey);
    }

    /**
     * @param string $cipherText
     * @param string $accountKey
     * @return string
     */
    public function decrypt(string $cipherText, string $accountKey): string
    {
        return vsce_phe_cipher_decrypt_php($this->c_ctx, $cipherText, $accountKey);
    }
}