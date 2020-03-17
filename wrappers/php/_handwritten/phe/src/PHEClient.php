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
 * Class PHEClient
 */
class PHEClient
{
    /**
     * @var
     */
    private $c_ctx;

    /**
     * PHEClient constructor.
     * @return void
     */
    public function __construct()
    {
        $this->c_ctx = vsce_phe_client_new_php();
    }

    /**
     * PHEClient destructor.
     * @return void
     */
    public function __destruct()
    {
        vsce_phe_client_delete_php($this->c_ctx);
    }

    /**
     * @return void
     * @throws Exception
     */
    public function setupDefaults()
    {
        vsce_phe_client_setup_defaults_php($this->c_ctx);
    }

    /**
     * @param string $clientPrivateKey
     * @param string $serverPublicKey
     * @return void
     * @throws Exception
     */
    public function setKeys(string $clientPrivateKey, string $serverPublicKey): void
    {
        vsce_phe_client_set_keys_php($this->c_ctx, $clientPrivateKey, $serverPublicKey);
    }

   /**
    * @return string
    * @throws Exception
    */
   public function generateClientPrivateKey(): string
   {
       return vsce_phe_client_generate_client_private_key_php($this->c_ctx);
   }

    /**
     * @param string $enrollmentResponse
     * @param string $password
     * @return array
     * @throws Exception
     */
    public function enrollAccount(string $enrollmentResponse, string $password): array
    {
        return vsce_phe_client_enroll_account_php($this->c_ctx, $enrollmentResponse, $password);
    }

    /**
     * @param string $password
     * @param string $enrollmentRecord
     * @return string
     * @throws Exception
     */
    public function createVerifyPasswordRequest(string $password, string $enrollmentRecord): string
    {
        return vsce_phe_client_create_verify_password_request_php($this->c_ctx, $password, $enrollmentRecord);
    }

    /**
     * @param string $password
     * @param string $enrollmentRecord
     * @param string $verifyPasswordResponse
     * @return string
     * @throws Exception
     */
    public function checkResponseAndDecrypt(string $password, string $enrollmentRecord, string
    $verifyPasswordResponse): string
    {
        return vsce_phe_client_check_response_and_decrypt_php($this->c_ctx, $password, $enrollmentRecord,
            $verifyPasswordResponse);
    }

    /**
     * @param string $updateToken
     * @return array
     * @throws Exception
     */
    public function rotateKeys(string $updateToken): array
    {
        return vsce_phe_client_rotate_keys_php($this->c_ctx, $updateToken);
    }

    /**
     * @param string $enrollmentRecord
     * @param string $updateToken
     * @return string
     * @throws Exception
     */
    public function updateEnrollmentRecord(string $enrollmentRecord, string $updateToken): string
    {
        return vsce_phe_client_update_enrollment_record_php($this->c_ctx, $enrollmentRecord, $updateToken);
    }
}
