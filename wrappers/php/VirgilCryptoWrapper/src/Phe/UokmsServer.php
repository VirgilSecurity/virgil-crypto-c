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
* Class implements UOKMS for server-side.
*/
class UokmsServer
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
        $this->ctx = is_null($ctx) ? vsce_uokms_server_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vsce_uokms_server_delete_php($this->ctx);
    }

    /**
    * @param Virgil\CryptoWrapper\Foundation\Random $random
    * @return void
    */
    public function useRandom(Virgil\CryptoWrapper\Foundation\Random $random): void
    {
        vsce_uokms_server_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * @param Virgil\CryptoWrapper\Foundation\Random $operationRandom
    * @return void
    */
    public function useOperationRandom(Virgil\CryptoWrapper\Foundation\Random $operationRandom): void
    {
        vsce_uokms_server_use_operation_random_php($this->ctx, $operationRandom->getCtx());
    }

    /**
    * Setups dependencies with default values.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vsce_uokms_server_setup_defaults_php($this->ctx);
    }

    /**
    * Generates new NIST P-256 server key pair for some client
    *
    * @return array
    * @throws \Exception
    */
    public function generateServerKeyPair(): array // [server_private_key, server_public_key]
    {
        return vsce_uokms_server_generate_server_key_pair_php($this->ctx);
    }

    /**
    * Buffer size needed to fit DecryptResponse
    *
    * @return int
    */
    public function decryptResponseLen(): int
    {
        return vsce_uokms_server_decrypt_response_len_php($this->ctx);
    }

    /**
    * Processed client's decrypt request
    *
    * @param string $serverPrivateKey
    * @param string $decryptRequest
    * @return string
    * @throws \Exception
    */
    public function processDecryptRequest(string $serverPrivateKey, string $decryptRequest): string
    {
        return vsce_uokms_server_process_decrypt_request_php($this->ctx, $serverPrivateKey, $decryptRequest);
    }

    /**
    * Updates server's private and public keys and issues an update token for use on client's side
    *
    * @param string $serverPrivateKey
    * @return array
    * @throws \Exception
    */
    public function rotateKeys(string $serverPrivateKey): array // [new_server_private_key, new_server_public_key, update_token]
    {
        return vsce_uokms_server_rotate_keys_php($this->ctx, $serverPrivateKey);
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
