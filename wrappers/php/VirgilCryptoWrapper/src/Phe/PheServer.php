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

namespace Virgil\CryptoWrapper\Phe;

/**
* Class for server-side PHE crypto operations.
* This class is thread-safe in case if VSCE_MULTI_THREADING defined.
*/
class PheServer
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
        $this->ctx = is_null($ctx) ? vsce_phe_server_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vsce_phe_server_delete_php($this->ctx);
    }

    /**
    * @param \Virgil\CryptoWrapper\Foundation\Random $random
    * @return void
    */
    public function useRandom(\Virgil\CryptoWrapper\Foundation\Random $random): void
    {
        vsce_phe_server_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * @param \Virgil\CryptoWrapper\Foundation\Random $operationRandom
    * @return void
    */
    public function useOperationRandom(\Virgil\CryptoWrapper\Foundation\Random $operationRandom): void
    {
        vsce_phe_server_use_operation_random_php($this->ctx, $operationRandom->getCtx());
    }

    /**
    * Setups dependencies with default values.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vsce_phe_server_setup_defaults_php($this->ctx);
    }

    /**
    * Generates new NIST P-256 server key pair for some client
    *
    * @return array
    * @throws \Exception
    */
    public function generateServerKeyPair(): array // [server_private_key, server_public_key]
    {
        return vsce_phe_server_generate_server_key_pair_php($this->ctx);
    }

    /**
    * Buffer size needed to fit EnrollmentResponse
    *
    * @return int
    */
    public function enrollmentResponseLen(): int
    {
        return vsce_phe_server_enrollment_response_len_php($this->ctx);
    }

    /**
    * Generates a new random enrollment and proof for a new user
    *
    * @param string $serverPrivateKey
    * @param string $serverPublicKey
    * @return string
    * @throws \Exception
    */
    public function getEnrollment(string $serverPrivateKey, string $serverPublicKey): string
    {
        return vsce_phe_server_get_enrollment_php($this->ctx, $serverPrivateKey, $serverPublicKey);
    }

    /**
    * Buffer size needed to fit VerifyPasswordResponse
    *
    * @return int
    */
    public function verifyPasswordResponseLen(): int
    {
        return vsce_phe_server_verify_password_response_len_php($this->ctx);
    }

    /**
    * Verifies existing user's password and generates response with proof
    *
    * @param string $serverPrivateKey
    * @param string $serverPublicKey
    * @param string $verifyPasswordRequest
    * @return string
    * @throws \Exception
    */
    public function verifyPassword(string $serverPrivateKey, string $serverPublicKey, string $verifyPasswordRequest): string
    {
        return vsce_phe_server_verify_password_php($this->ctx, $serverPrivateKey, $serverPublicKey, $verifyPasswordRequest);
    }

    /**
    * Buffer size needed to fit UpdateToken
    *
    * @return int
    */
    public function updateTokenLen(): int
    {
        return vsce_phe_server_update_token_len_php($this->ctx);
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
        return vsce_phe_server_rotate_keys_php($this->ctx, $serverPrivateKey);
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
