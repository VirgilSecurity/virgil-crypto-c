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
* Class for client-side PHE crypto operations.
* This class is thread-safe in case if VSCE_MULTI_THREADING defined.
*/
class PheClient
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
        $this->ctx = is_null($ctx) ? vsce_phe_client_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vsce_phe_client_delete_php($this->ctx);
    }

    /**
    * @param VirgilCryptoWrapper\Foundation\Random $random
    * @return void
    */
    public function useRandom(VirgilCryptoWrapper\Foundation\Random $random): void
    {
        vsce_phe_client_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * @param VirgilCryptoWrapper\Foundation\Random $operationRandom
    * @return void
    */
    public function useOperationRandom(VirgilCryptoWrapper\Foundation\Random $operationRandom): void
    {
        vsce_phe_client_use_operation_random_php($this->ctx, $operationRandom->getCtx());
    }

    /**
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vsce_phe_client_setup_defaults_php($this->ctx);
    }

    /**
    * Sets client private and server public key
    * Call this method before any other methods except `update enrollment record` and `generate client private key`
    * This function should be called only once
    *
    * @param string $clientPrivateKey
    * @param string $serverPublicKey
    * @return void
    * @throws \Exception
    */
    public function setKeys(string $clientPrivateKey, string $serverPublicKey): void
    {
        vsce_phe_client_set_keys_php($this->ctx, $clientPrivateKey, $serverPublicKey);
    }

    /**
    * Generates client private key
    *
    * @return string
    * @throws \Exception
    */
    public function generateClientPrivateKey(): string
    {
        return vsce_phe_client_generate_client_private_key_php($this->ctx);
    }

    /**
    * Buffer size needed to fit EnrollmentRecord
    *
    * @return int
    */
    public function enrollmentRecordLen(): int
    {
        return vsce_phe_client_enrollment_record_len_php($this->ctx);
    }

    /**
    * Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
    * a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
    * Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
    *
    * @param string $enrollmentResponse
    * @param string $password
    * @return array
    * @throws \Exception
    */
    public function enrollAccount(string $enrollmentResponse, string $password): array // [enrollment_record, account_key]
    {
        return vsce_phe_client_enroll_account_php($this->ctx, $enrollmentResponse, $password);
    }

    /**
    * Buffer size needed to fit VerifyPasswordRequest
    *
    * @return int
    */
    public function verifyPasswordRequestLen(): int
    {
        return vsce_phe_client_verify_password_request_len_php($this->ctx);
    }

    /**
    * Creates a request for further password verification at the PHE server side.
    *
    * @param string $password
    * @param string $enrollmentRecord
    * @return string
    * @throws \Exception
    */
    public function createVerifyPasswordRequest(string $password, string $enrollmentRecord): string
    {
        return vsce_phe_client_create_verify_password_request_php($this->ctx, $password, $enrollmentRecord);
    }

    /**
    * Verifies PHE server's answer
    * If login succeeded, extracts account key
    * If login failed account key will be empty
    *
    * @param string $password
    * @param string $enrollmentRecord
    * @param string $verifyPasswordResponse
    * @return string
    * @throws \Exception
    */
    public function checkResponseAndDecrypt(string $password, string $enrollmentRecord, string $verifyPasswordResponse): string
    {
        return vsce_phe_client_check_response_and_decrypt_php($this->ctx, $password, $enrollmentRecord, $verifyPasswordResponse);
    }

    /**
    * Updates client's private key and server's public key using server's update token
    * Use output values to instantiate new client instance with new keys
    *
    * @param string $updateToken
    * @return array
    * @throws \Exception
    */
    public function rotateKeys(string $updateToken): array // [new_client_private_key, new_server_public_key]
    {
        return vsce_phe_client_rotate_keys_php($this->ctx, $updateToken);
    }

    /**
    * Updates EnrollmentRecord using server's update token
    *
    * @param string $enrollmentRecord
    * @param string $updateToken
    * @return string
    * @throws \Exception
    */
    public function updateEnrollmentRecord(string $enrollmentRecord, string $updateToken): string
    {
        return vsce_phe_client_update_enrollment_record_php($this->ctx, $enrollmentRecord, $updateToken);
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
