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

namespace Virgil\CryptoWrapper\Phe;

/**
* Class implements UOKMS for client-side.
*/
class UokmsClient
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
        $this->ctx = is_null($ctx) ? vsce_uokms_client_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vsce_uokms_client_delete_php($this->ctx);
    }

    /**
    * @param Virgil\CryptoWrapper\Foundation\Random $random
    * @return void
    */
    public function useRandom(Virgil\CryptoWrapper\Foundation\Random $random): void
    {
        vsce_uokms_client_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * @param Virgil\CryptoWrapper\Foundation\Random $operationRandom
    * @return void
    */
    public function useOperationRandom(Virgil\CryptoWrapper\Foundation\Random $operationRandom): void
    {
        vsce_uokms_client_use_operation_random_php($this->ctx, $operationRandom->getCtx());
    }

    /**
    * Setups dependencies with default values.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vsce_uokms_client_setup_defaults_php($this->ctx);
    }

    /**
    * Sets client private and server public key
    * Call this method before any other methods
    * This function should be called only once
    *
    * @param string $clientPrivateKey
    * @param string $serverPublicKey
    * @return void
    * @throws \Exception
    */
    public function setKeys(string $clientPrivateKey, string $serverPublicKey): void
    {
        vsce_uokms_client_set_keys_php($this->ctx, $clientPrivateKey, $serverPublicKey);
    }

    /**
    * Generates client private key
    *
    * @return string
    * @throws \Exception
    */
    public function generateClientPrivateKey(): string
    {
        return vsce_uokms_client_generate_client_private_key_php($this->ctx);
    }

    /**
    * Generates new encrypt wrap (which should be stored and then used for decryption) + encryption key
    * of "encryption key len" that can be used for symmetric encryption
    *
    * @param int $encryptionKeyLen
    * @return array
    * @throws \Exception
    */
    public function generateEncryptWrap(int $encryptionKeyLen): array // [wrap, encryption_key]
    {
        return vsce_uokms_client_generate_encrypt_wrap_php($this->ctx, $encryptionKeyLen);
    }

    /**
    * Generates request to decrypt data, this request should be sent to the server.
    * Server response is then passed to "process decrypt response" where encryption key can be decapsulated
    *
    * @param string $wrap
    * @return array
    * @throws \Exception
    */
    public function generateDecryptRequest(string $wrap): array // [deblind_factor, decrypt_request]
    {
        return vsce_uokms_client_generate_decrypt_request_php($this->ctx, $wrap);
    }

    /**
    * Processed server response, checks server proof and decapsulates encryption key
    *
    * @param string $wrap
    * @param string $decryptRequest
    * @param string $decryptResponse
    * @param string $deblindFactor
    * @param int $encryptionKeyLen
    * @return string
    * @throws \Exception
    */
    public function processDecryptResponse(string $wrap, string $decryptRequest, string $decryptResponse, string $deblindFactor, int $encryptionKeyLen): string
    {
        return vsce_uokms_client_process_decrypt_response_php($this->ctx, $wrap, $decryptRequest, $decryptResponse, $deblindFactor, $encryptionKeyLen);
    }

    /**
    * Rotates client and server keys using given update token obtained from server
    *
    * @param string $updateToken
    * @return array
    * @throws \Exception
    */
    public function rotateKeys(string $updateToken): array // [new_client_private_key, new_server_public_key]
    {
        return vsce_uokms_client_rotate_keys_php($this->ctx, $updateToken);
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
