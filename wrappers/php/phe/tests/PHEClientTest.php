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

class PHEClientTest extends \PHPUnit\Framework\TestCase
{
    protected $client;
    protected $server;

    protected function setUp()
    {
        $this->client = vsce_phe_client_new_php();
        $this->server = vsce_phe_server_new_php();
    }

    public function testFullFlowRandomCorrectPwdShouldSucceed()
    {
        $password = "password";

        $serverKeyPair = vsce_phe_server_generate_server_key_pair_php($this->server); // [{privateKey}, {publicKey}]
        $this->assertInternalType('array', $serverKeyPair);
        $this->assertCount(2, $serverKeyPair);

        $serverPrivateKey = $serverKeyPair[0];
        $serverPublicKey = $serverKeyPair[1];

        $this->assertInternalType('string', $serverPrivateKey);
        $this->assertInternalType('string', $serverPublicKey);

        $this->assertEquals(65, strlen($serverPublicKey));
        $this->assertEquals(32, strlen($serverPrivateKey));

        $clientPrivateKey = vsce_phe_client_generate_client_private_key_php($this->client); // {privateKey}
        $this->assertInternalType('string', $clientPrivateKey);

        vsce_phe_client_set_keys_php($this->client, $clientPrivateKey, $serverPublicKey); // void

        $serverEnrollmentResponseLen = vsce_phe_server_enrollment_response_len_php($this->server);
        $this->assertInternalType('int', $serverEnrollmentResponseLen);

//        $serverEnrollment = vsce_phe_server_get_enrollment_php($this->server, $serverPrivateKey, $serverPublicKey);
//        $this->assertNotEmpty($serverEnrollment);
//        $this->assertInternalType('string', $serverEnrollment);

        $clientEnrollmentRecordLen = vsce_phe_client_enrollment_record_len_php($this->client);
        $this->assertInternalType('int', $clientEnrollmentRecordLen);

//        $clientEnrollAccount = vsce_phe_client_enroll_account_php($this->client, $serverEnrollment, $password);

        $clientVerifyPasswordRequestLen = vsce_phe_client_verify_password_request_len_php($this->client);
        $this->assertInternalType('int', $clientVerifyPasswordRequestLen);

//        $clientCreateVerifyPasswordRequest = vsce_phe_client_create_verify_password_request_php($this->client,
//            $password, $clientEnrollmentRecordLen);
//        $this->assertNotEmpty($clientCreateVerifyPasswordRequest);
//        $this->assertInternalType('string', $clientCreateVerifyPasswordRequest);

        $serverVerifyPasswordResponseLen = vsce_phe_server_verify_password_response_len_php($this->server);
        $this->assertInternalType('int', $serverVerifyPasswordResponseLen);

//        $serverVerifyPassword = vsce_phe_server_verify_password_php($this->server, $serverPrivateKey, $serverPublicKey,
//            $clientVerifyPasswordRequestLen);

//        $clientCheckResponseAndDecrypt = vsce_phe_client_check_response_and_decrypt_php($this->client, $password,
//            $clientEnrollmentRecordLen, $serverVerifyPasswordResponseLen);
    }

    public function testRotationRandomRotationServerPublicKeysMatch()
    {
        $serverUpdateTokenLen = vsce_phe_server_update_token_len_php($this->server);
        $this->assertInternalType('int', $serverUpdateTokenLen);

        $serverKeyPair = vsce_phe_server_generate_server_key_pair_php($this->server); // [{privateKey}, {publicKey}]
        $this->assertInternalType('array', $serverKeyPair);
        $this->assertCount(2, $serverKeyPair);
        $serverPrivateKey = $serverKeyPair[0];
        $serverPublicKey = $serverKeyPair[1];
        $this->assertInternalType('string', $serverPrivateKey);
        $this->assertInternalType('string', $serverPublicKey);

        $serverRotateKeys = vsce_phe_server_rotate_keys_php($this->server, $serverPrivateKey);
        $this->assertInternalType('array', $serverRotateKeys);
        $serverRotatedPrivateKey = $serverRotateKeys[0];
        $serverRotatedPublicKey = $serverRotateKeys[1];
        $serverUpdateToken = $serverRotateKeys[2];
        $this->assertInternalType('string', $serverRotatedPrivateKey);
        $this->assertInternalType('string', $serverRotatedPublicKey);
        $this->assertInternalType('string', $serverUpdateToken);
        $this->assertNotEmpty($serverUpdateToken);

        $clientPrivateKey = vsce_phe_client_generate_client_private_key_php($this->client); // {privateKey}
        $this->assertInternalType('string', $clientPrivateKey);
        $this->assertNotEmpty($clientPrivateKey);

        vsce_phe_client_set_keys_php($this->client, $clientPrivateKey, $serverRotatedPublicKey); // void

        $clientRotateKeys = vsce_phe_client_rotate_keys_php($this->client, $serverUpdateToken);
        $this->assertInternalType('array', $clientRotateKeys);
        $clientNewPrivateKey = $clientRotateKeys[0];
        $serverNewPublicKey = $clientRotateKeys[1];
        $this->assertInternalType('string', $clientNewPrivateKey);
        $this->assertInternalType('string', $serverNewPublicKey);

        $this->assertEquals(strlen($serverPublicKey), strlen($serverNewPublicKey));
        $this->assertEquals(strlen($clientPrivateKey), strlen($clientNewPrivateKey));
    }

//    public function testRotationRandomRotationEnrollmentRecordUpdatedSuccessfully()
//    {
//        $password = "password";
//
//        $serverKeyPair = vsce_phe_server_generate_server_key_pair_php($this->server); // [{privateKey}, {publicKey}]
//        $this->assertInternalType('array', $serverKeyPair);
//        $this->assertCount(2, $serverKeyPair);
//        $serverPrivateKey = $serverKeyPair[0];
//        $serverPublicKey = $serverKeyPair[1];
//        $this->assertInternalType('string', $serverPrivateKey);
//        $this->assertInternalType('string', $serverPublicKey);
//
//        $enrollmentResponse = vsce_phe_server_enrollment_response_len_php($this->server);
//        $serverGetEnrollment = vsce_phe_server_get_enrollment_php($this->server, $serverPrivateKey, $serverPublicKey);
//
//        $this->assertNotEmpty($serverGetEnrollment);
//    }

    protected function tearDown()
    {
        vsce_phe_client_delete_php($this->client);
        vsce_phe_server_delete_php($this->server);
    }
}
