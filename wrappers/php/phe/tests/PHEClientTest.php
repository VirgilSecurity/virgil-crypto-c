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

require_once 'PHEClient.php';
require_once 'PHEServer.php';

class PHEClientTest extends \PHPUnit\Framework\TestCase
{
    protected $client;
    protected $server;

    protected function setUp()
    {
        $this->client = new PHEClient();
        $this->client->setupDefaults();

        $this->server = new PHEServer();
        $this->server->setupDefaults();
    }

    protected function tearDown()
    {
        unset($this->client);
        unset($this->server);
    }

    public function testFullFlowRandomCorrectPwdShouldSucceed()
    {
        $password = "password";

        $serverKeyPair = $this->server->generateServerKeyPair(); // [{privateKey}, {publicKey}]
        $this->assertInternalType('array', $serverKeyPair);
        $this->assertCount(2, $serverKeyPair);

        $serverPrivateKey = $serverKeyPair[0];
        $serverPublicKey = $serverKeyPair[1];

        $this->assertInternalType('string', $serverPrivateKey);
        $this->assertInternalType('string', $serverPublicKey);

        $this->assertEquals(65, strlen($serverPublicKey));
        $this->assertEquals(32, strlen($serverPrivateKey));

        $clientPrivateKey = $this->client->generateClientPrivateKey(); // {privateKey}
        $this->assertInternalType('string', $clientPrivateKey);

        $this->client->setKeys($clientPrivateKey, $serverPublicKey); // void

        $serverEnrollment = $this->server->getEnrollment($serverPrivateKey, $serverPublicKey);
        $this->assertNotEmpty($serverEnrollment);
        $this->assertInternalType('string', $serverEnrollment);

        $clientEnrollAccount = $this->client->enrollAccount($serverEnrollment, $password);
        $this->assertInternalType('array', $clientEnrollAccount);
        $this->assertCount(2, $clientEnrollAccount);

        $clientEnrollmentRecord = $clientEnrollAccount[0];
        $clientAccountKey = $clientEnrollAccount[1];
        $this->assertInternalType('string', $clientEnrollmentRecord);
        $this->assertInternalType('string', $clientAccountKey);

        $clientCreateVerifyPasswordRequest = $this->client->createVerifyPasswordRequest($password,
            $clientEnrollmentRecord);
        $this->assertNotEmpty($clientCreateVerifyPasswordRequest);
        $this->assertInternalType('string', $clientCreateVerifyPasswordRequest);

        $serverVerifyPassword = $this->server->verifyPassword($serverPrivateKey, $serverPublicKey,
            $clientCreateVerifyPasswordRequest);
        $this->assertInternalType('string', $serverVerifyPassword);

        $clientCheckResponseAndDecrypt = $this->client->checkResponseAndDecrypt($password,
            $clientEnrollmentRecord, $serverVerifyPassword);
        $this->assertInternalType('string', $clientCheckResponseAndDecrypt);
        $this->assertEquals(32, strlen($clientAccountKey));
        $this->assertEquals(32, strlen($clientCheckResponseAndDecrypt));
        $this->assertEquals($clientAccountKey, $clientCheckResponseAndDecrypt);
    }

    public function testRotationRandomRotationServerPublicKeysMatch()
    {
        $serverKeyPair = $this->server->generateServerKeyPair(); // [{privateKey}, {publicKey}]
        $this->assertInternalType('array', $serverKeyPair);
        $this->assertCount(2, $serverKeyPair);
        $serverPrivateKey = $serverKeyPair[0];
        $serverPublicKey = $serverKeyPair[1];
        $this->assertInternalType('string', $serverPrivateKey);
        $this->assertInternalType('string', $serverPublicKey);

        $serverRotateKeys = $this->server->rotateKeys($serverPrivateKey);
        $this->assertInternalType('array', $serverRotateKeys);
        $serverRotatedPrivateKey = $serverRotateKeys[0];
        $serverRotatedPublicKey = $serverRotateKeys[1];
        $serverUpdateToken = $serverRotateKeys[2];
        $this->assertInternalType('string', $serverRotatedPrivateKey);
        $this->assertInternalType('string', $serverRotatedPublicKey);
        $this->assertInternalType('string', $serverUpdateToken);
        $this->assertNotEmpty($serverUpdateToken);

        $clientPrivateKey = $this->client->generateClientPrivateKey(); // {privateKey}
        $this->assertInternalType('string', $clientPrivateKey);
        $this->assertNotEmpty($clientPrivateKey);

        $this->client->setKeys($clientPrivateKey, $serverRotatedPublicKey);

        $clientRotateKeys = $this->client->rotateKeys($serverUpdateToken);
        $this->assertInternalType('array', $clientRotateKeys);
        $clientNewPrivateKey = $clientRotateKeys[0];
        $serverNewPublicKey = $clientRotateKeys[1];
        $this->assertInternalType('string', $clientNewPrivateKey);
        $this->assertInternalType('string', $serverNewPublicKey);

        $this->assertEquals(strlen($serverPublicKey), strlen($serverNewPublicKey));
        $this->assertEquals(strlen($clientPrivateKey), strlen($clientNewPrivateKey));
    }
}
