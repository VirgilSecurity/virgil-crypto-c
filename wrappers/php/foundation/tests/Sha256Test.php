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

require_once 'Sha256.php';

class Sha256Test extends \PHPUnit\Framework\TestCase
{
    private $SHA256;
    private $testVector1;
    private $testVector2;
    private $testVector1Base64EncodedResult;
    private $testVector2Base64EncodedResult;

    protected function setUp()
    {
        $this->SHA256 = new Sha256();
        $this->testVector1 = "";
        $this->testVector1Base64EncodedResult = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        $this->testVector2 = "abc";
        $this->testVector2Base64EncodedResult = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
    }

    protected function tearDown()
    {
        unset($this->SHA256);
    }

    public function testValidReturnsNotNull()
    {
        $this->assertNotNull($this->SHA256);
    }

    public function testDigestLenAlwaysEquals32()
    {
        $this->assertEquals(32, Sha256::DIGEST_LEN);
    }

    public function testBlockLenAlwaysEquals64()
    {
        $this->assertEquals(64, Sha256::BLOCK_LEN);
    }

    public function testHashVector1Success()
    {
        $res = $this->SHA256->hash($this->testVector1);

        $this->assertEquals(32, strlen($res));
        $this->assertEquals(base64_decode($this->testVector1Base64EncodedResult), $res);
    }

    public function testHashVector2Success()
    {
        $res = $this->SHA256->hash($this->testVector2);

        $this->assertEquals(32, strlen($res));
        $this->assertEquals(base64_decode($this->testVector2Base64EncodedResult), $res);
    }

    public function testHashSteamVector1Success()
    {
        $this->SHA256->start();
        $this->SHA256->update($this->testVector1);
        $res = $this->SHA256->finish();

        $this->assertEquals(32, strlen($res));
        $this->assertEquals(base64_decode($this->testVector1Base64EncodedResult), $res);
    }

    public function testHashSteamVector2Success()
    {
        $this->SHA256->start();
        $this->SHA256->update($this->testVector2);
        $res = $this->SHA256->finish();

        $this->assertEquals(32, strlen($res));
        $this->assertEquals(base64_decode($this->testVector2Base64EncodedResult), $res);
    }
}