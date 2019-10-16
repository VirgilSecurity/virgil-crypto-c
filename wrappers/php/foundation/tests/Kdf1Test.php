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

namespace VirgilCrypto\Foundation;

require_once 'Kdf1.php';
require_once 'Sha256.php';

class Kdf1Test extends \PHPUnit\Framework\TestCase
{
    private $kdf1;
    private $sha256;
    private $testVector1;
    private $testVector2;
    private $testVector1KeyBase64Encoded;
    private $testVector2KeyBase64Encoded;
    private $keyLen1;
    private $keyLen2;

    protected function setUp()
    {
        $this->kdf1 = new KDF1();
        $this->sha256 = new Sha256();
        $this->testVector1 = "";
        $this->testVector2 = "abc";
        $this->keyLen1 = 32;
        $this->keyLen2 = 64;
        $this->testVector1KeyBase64Encoded = "07/pjo8c6JFhSFRWmiD19FCNarQCW4crezqCgu91sSo=";
        $this->testVector2KeyBase64Encoded = "fJu7Nt0wRqF+qvXPV4sJstqLd69OYIdTOZD4JmxENNTPcbRcHS1TXNgGiDXbeyIsXazG1XmtpW5PWq2k4sYRJw==";
    }

    protected function tearDown()
    {
        unset($this->sha256);
        unset($this->kdf1);
    }

    public function test_Derive_WithSha256AndKeyLength32Vector1_DerivedLength32()
    {
        $this->kdf1->useHash($this->sha256);
        $hash = $this->sha256->hash($this->testVector1);
        $key = $this->kdf1->derive($hash, $this->keyLen1);
        $this->assertEquals($this->keyLen1, strlen($key));
        $this->assertEquals(base64_decode($this->testVector1KeyBase64Encoded), $key);
    }

    public function test_Derive_WithSha256AndKeyLength32Vector2_DerivedLength64()
    {
        $this->kdf1->useHash($this->sha256);
        $hash = $this->sha256->hash($this->testVector2);
        $key = $this->kdf1->derive($hash, $this->keyLen2);
        $this->assertEquals($this->keyLen2, strlen($key));
        $this->assertEquals(base64_decode($this->testVector2KeyBase64Encoded), $key);
    }
}