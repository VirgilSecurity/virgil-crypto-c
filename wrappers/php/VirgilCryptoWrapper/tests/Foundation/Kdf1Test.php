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

namespace Virgil\CryptoWrapperTests\Foundation;

use Virgil\CryptoWrapper\Foundation\Kdf1;
use Virgil\CryptoWrapper\Foundation\Sha256;

class Kdf1Test extends \PHPUnit\Framework\TestCase
{
    private $kdf1;
    private $sha256;

    protected function setUp()
    {
        $this->kdf1 = new KDF1();
        $this->sha256 = new Sha256();
    }

    protected function tearDown()
    {
        unset($this->sha256);
        unset($this->kdf1);
    }

    public function test_Kdf1_deriveKeyFromEmptyString()
    {
        $kdf1 = $this->kdf1;
        $kdf1->useHash($this->sha256);
        $vector1Data = "";
        $vector1Key = "DF3F619804A92FDB4057192DC43DD748EA778ADC52BC498CE80524C014B81119B40711A88C703975";
        $vector1KeyBytes = self::unhexlify($vector1Key);
        $key = $kdf1->derive($vector1Data, strlen($vector1KeyBytes));

        $this->assertEquals(strlen($vector1KeyBytes), strlen($key));
        $this->assertEquals($vector1KeyBytes, $key);
    }

    public function test_Kdf1_deriveVector2()
    {
        $kdf1 = $this->kdf1;
        $kdf1->useHash($this->sha256);
        $vector2Data = self::unhexlify("BD");
        $vector2Key = "A759B860B37FE77847406F266B7D7F1E838D814ADDF2716ECF4D824DC8B56F71823BFAE3B6E7CD29";
        $vector2KeyBytes = self::unhexlify($vector2Key);
        $key = $kdf1->derive($vector2Data, strlen($vector2KeyBytes));

        $this->assertEquals(strlen($vector2KeyBytes), strlen($key));
        $this->assertEquals($vector2KeyBytes, $key);
    }

    public function test_Kdf1_deriveVector3()
    {
        $kdf1 = $this->kdf1;
        $kdf1->useHash($this->sha256);
        $vector3Data = self::unhexlify("5FD4");
        $vector3Key = "C6067722EE5661131D53437E649ED1220858F88164819BB867D6478714F8F3C8002422AFDD96BF48";
        $vector3KeyBytes = self::unhexlify($vector3Key);
        $key = $kdf1->derive($vector3Data, strlen($vector3KeyBytes));

        $this->assertEquals(strlen($vector3KeyBytes), strlen($key));
        $this->assertEquals($vector3KeyBytes, $key);
    }

    /**
     * @param string $string
     * @return string
     */
    private static function unhexlify(string $string): string
    {
        return pack("H*", $string);
    }
}