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

namespace VirgilCrypto\Phe\Tests;

use VirgilCrypto\Phe\PheClient;
use VirgilCrypto\Phe\PheServer;

class PheClientTest extends \PHPUnit\Framework\TestCase
{
    private $client;
    private $server;

    protected function setUp()
    {
        $this->server = new PheServer();
        $this->client = new PheClient();
    }

    protected function tearDown()
    {
        unset($this->client);
        unset($this->server);
    }

    public function test_PheClient_enrollAccount()
    {
        $server = $this->server;
        $client = $this->client;
        $server->setupDefault();
        $client->setupDefaults();
        list($serverPrivateKey, $serverPublicKey) = $server->generateServerKeyPair();
        list($clientPrivateKey, $clientPublicKey) = $server->generateServerKeyPair();
        $client->setKeys($clientPrivateKey, $serverPublicKey);
        $enrollmentResponse = $server->getEnrollment($serverPrivateKey, $serverPublicKey);
        list($enrollRecord, $enrollKey) = $client->enrollAccount($enrollmentResponse, "passw0rd");
        $this->assertNotNull($enrollRecord);
        $this->assertNotNull($enrollKey);
        $this->assertTrue(is_string($enrollRecord));
        $this->assertTrue(is_string($enrollKey));
    }

    public function test_PheClient_password_verify_request()
    {
        $server = $this->server;
        $client = $this->client;
        $server->setupDefault();
        $client->setupDefaults();
        list($serverPrivateKey, $serverPublicKey) = $server->generateServerKeyPair();
        list($clientPrivateKey, $clientPublicKey) = $server->generateServerKeyPair();
        $client->setKeys($clientPrivateKey, $serverPublicKey);
        $enrollmentResponse = $server->getEnrollment($serverPrivateKey, $serverPublicKey);
        list($record, $enrollKey) = $client->enrollAccount($enrollmentResponse, "passw0rd");
        $request = $client->createVerifyPasswordRequest("passw0rd", $record);
        $this->assertNotNull($request);
        $this->assertTrue(is_string($request));
    }

    public function test_PheClient_verifyPasswordResponse()
    {
        $server = $this->server;
        $client = $this->client;
        $server->setupDefault();
        $client->setupDefaults();
        list($serverPrivateKey, $serverPublicKey) = $server->generateServerKeyPair();
        list($clientPrivateKey, $clientPublicKey) = $server->generateServerKeyPair();
        $client->setKeys($clientPrivateKey, $serverPublicKey);
        $enrollmentResponse = $server->getEnrollment($serverPrivateKey, $serverPublicKey);
        list($record, $enrollKey) = $client->enrollAccount($enrollmentResponse, "passw0rd");
        $request = $client->createVerifyPasswordRequest("passw0rd", $record);
        $response = $server->verifyPassword($serverPrivateKey, $serverPublicKey, $request);
        $verifiedResponse = $client->checkResponseAndDecrypt("passw0rd", $record, $response);
        $this->assertNotNull($verifiedResponse);
        $this->isTrue(is_string($verifiedResponse));
    }
}
