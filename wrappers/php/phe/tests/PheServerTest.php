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

class PheServerTest extends \PHPUnit\Framework\TestCase
{
    private $client;
    private $server;

    protected function setUp()
    {
        $this->server = new PheServer();
        $this->server->setupDefaults();
        $this->client = new PheClient();
        $this->client->setupDefaults();
    }

    protected function tearDown()
    {
        unset($this->client);
        unset($this->server);
    }

    public function test_PheServer_generateKeyPair()
    {
        list($privateKey, $publicKey) = $this->server->generateServerKeyPair();
        $this->assertNotNull($privateKey);
        $this->assertNotNull($publicKey);
        $this->assertTrue(is_string($privateKey));
        $this->assertTrue(is_string($publicKey));
    }

    public function test_PheServer_getEnrollment()
    {
        list($privateKey, $publicKey) = $this->server->generateServerKeyPair();
        $enroll = $this->server->getEnrollment($privateKey, $publicKey);
        $this->assertNotNull($enroll);
        $this->assertTrue(is_string($enroll));
    }

    public function test_PheServer_verifyPassword()
    {
        list($serverPrivateKey, $serverPublicKey) = $this->server->generateServerKeyPair();
        list($clientPrivateKey, $clientPublicKey) = $this->server->generateServerKeyPair();
        $this->client->setKeys($clientPrivateKey, $serverPublicKey);
        $enrollmentResponse = $this->server->getEnrollment($serverPrivateKey, $serverPublicKey);
        list($record, $enrollKey) = $this->client->enrollAccount($enrollmentResponse, "passw0rd");
        $request = $this->client->createVerifyPasswordRequest("passw0rd", $record);
        $response = $this->server->verifyPassword($serverPrivateKey, $serverPublicKey, $request);
        $this->assertNotNull($response);
        $this->assertTrue(is_string($response));
    }
}
