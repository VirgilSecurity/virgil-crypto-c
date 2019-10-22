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

namespace VirgilCrypto\Foundation\Tests;

use VirgilCrypto\Foundation\Sha256;

class Sha256Test extends \PHPUnit\Framework\TestCase
{
    private $sha256;

    const SHA256_VECTOR_1_INPUT_BYTES = "";
    const SHA256_VECTOR_1_DIGEST_BYTES = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    const SHA256_VECTOR_2_INPUT_BYTES = "BD";
    const SHA256_VECTOR_2_DIGEST_BYTES = "68325720AABD7C82F30F554B313D0570C95ACCBB7DC4B5AAE11204C08FFE732B";
    const SHA256_VECTOR_3_INPUT_BYTES = "5FD4";
    const SHA256_VECTOR_3_DIGEST_BYTES = "7C4FBF484498D21B487B9D61DE8914B2EADAF2698712936D47C3ADA2558F6788";

    protected function setUp()
    {
        $this->sha256 = new Sha256();
    }

    protected function tearDown()
    {
        unset($this->sha256);
    }

    public function test_Sha256_hashEmptyString()
    {
        $res = $this->sha256::hash(self::SHA256_VECTOR_1_INPUT_BYTES);
        $this->assertEquals(base64_decode("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="), $res);
    }

    public function test_Sha256_hashEmptyBytes()
    {
        $res = $this->sha256::hash(self::SHA256_VECTOR_1_INPUT_BYTES);
        $this->assertEquals($res, self::unhexlify(self::SHA256_VECTOR_1_DIGEST_BYTES));
    }

    public function test_Sha256_hashVector2()
    {
        $res = $this->sha256::hash(self::unhexlify(self::SHA256_VECTOR_2_INPUT_BYTES));
        $this->assertEquals($res, self::unhexlify(self::SHA256_VECTOR_2_DIGEST_BYTES));
    }

    public function test_Sha256_hasgVector3Success()
    {
        $res = $this->sha256::hash(self::unhexlify(self::SHA256_VECTOR_3_INPUT_BYTES));
        $this->assertEquals($res, self::unhexlify(self::SHA256_VECTOR_3_DIGEST_BYTES));
    }

    public function test_Sha256_hashStreamVector1()
    {
        $sha256 = $this->sha256;
        $sha256->start();
        $sha256->update(self::SHA256_VECTOR_1_INPUT_BYTES);

        $digest = $sha256->finish();

        $this->assertEquals(strlen(self::unhexlify(self::SHA256_VECTOR_1_DIGEST_BYTES)), strlen($digest));
        $this->assertEquals(self::unhexlify(self::SHA256_VECTOR_1_DIGEST_BYTES), $digest);
    }

    public function test_Sha256_hashStreamVector2()
    {
        $sha256 = $this->sha256;
        $sha256->start();
        $sha256->update(self::unhexlify(self::SHA256_VECTOR_2_INPUT_BYTES));

        $digest = $sha256->finish();

        $this->assertEquals(strlen(self::unhexlify(self::SHA256_VECTOR_2_DIGEST_BYTES)), strlen($digest));
        $this->assertEquals(self::unhexlify(self::SHA256_VECTOR_2_DIGEST_BYTES), $digest);
    }

    public function test_Sha256_hashStreamVector3()
    {
        $sha256 = $this->sha256;
        $sha256->start();
        $sha256->update(self::unhexlify(self::SHA256_VECTOR_3_INPUT_BYTES));

        $digest = $sha256->finish();

        $this->assertEquals(strlen(self::unhexlify(self::SHA256_VECTOR_3_DIGEST_BYTES)), strlen($digest));
        $this->assertEquals(self::unhexlify(self::SHA256_VECTOR_3_DIGEST_BYTES), $digest);
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