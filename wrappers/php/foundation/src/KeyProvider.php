<?php
/**
 * Copyright (C) 2015-2019 Virgil Security Inc.
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
 * Class KeyProvider
 * Provide functionality for private key generation and importing that relies on the software default implementations.
 */
class KeyProvider
{
    /**
     * @var
     */
    private $c_ctx;

    /**
     * Allocate context and perform it's initialization.
     * KeyProvider constructor.
     */
    public function __construct()
    {
        $this->c_ctx = vscf_key_provider_new_php();
    }

    public function __destruct()
    {
        vscf_key_provider_delete_php($this->c_ctx);
    }

    /**
     * Setup predefined values to the uninitialized class dependencies.
     * @throws Exception
     * @return void
     */
    public function setupDefaults(): void
    {
        vscf_key_provider_setup_defaults_php($this->c_ctx);
    }

    /**
     * Setup parameters that is used during RSA key generation.
     * @param int $bitlen
     * @return void
     */
    public function setRsaParams(int $bitlen): void
    {
        vscf_key_provider_set_rsa_params_php($this->c_ctx, $bitlen);
    }

    /**
     * Import public key from the PKCS#8 format.
     * @param string $keyData
     * @return PublicKey
     */
    public function importPublicKey(string $keyData): PublicKey
    {
        return vscf_key_provider_import_public_key_php($this->c_ctx, $keyData);
    }
}