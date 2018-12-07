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

require_once 'PHEClient.php';

class PHEClientTest extends \PHPUnit\Framework\TestCase
{
    private $pheClient;
    private $pheClientNewPHPFunc;

    public function setUp()
    {
        $this->pheClient = new PHEClient();
        $this->pheClientNewPHPFunc = vsce_phe_client_new_php();
    }

    public function test_correct_return_types()
    {
        $this->assertInternalType('string', $this->pheClient->generateClientPrivateKey());// done
        $this->assertInternalType('int', $this->pheClient->enrollmentRecordLen());// done
//        $this->assertInternalType('array', $this->pheclient->enrollAccount(self::STRING, self::STRING));// done
        $this->assertInternalType('int', $this->pheClient->verifyPasswordRequestLen()); // done
//        $this->assertInternalType('string', $this->pheclient->createVerifyPasswordRequest(self::STRING, self::STRING));
//        $this->assertInternalType('string', $this->pheclient->checkResponseAndDecrypt(self::STRING, self::STRING, self::STRING));
//        $this->assertInternalType('array', $this->pheclient->rotateKeys(self::STRING));// done
//        $this->assertInternalType('string', $this->pheclient->updateEnrollmentRecord(self::STRING, self::STRING));//done
    }

    public function testEnrollmentRecordLenFunction() {
        $enrollmentRecordLenFunction = vsce_phe_client_enrollment_record_len_php($this->pheClientNewPHPFunc);
        $this->assertGreaterThan(0, $enrollmentRecordLenFunction);
    }

    public function testVerifyPasswordRequestLenFunction() {
        $verifyPasswordRequestLenFunction = vsce_phe_client_verify_password_request_len_php($this->pheClientNewPHPFunc);
        $this->assertGreaterThan(0, $verifyPasswordRequestLenFunction);
    }

    public function testGenerateClientPrivateKeyFunction() {
        $generateClientPrivateKeyFunction = vsce_phe_client_verify_password_request_len_php($this->pheClientNewPHPFunc);
        $this->assertNotEmpty($generateClientPrivateKeyFunction);
    }

//    public function testEnrollAccountFunction()
//    {
//        $enrollAccountFunction = vsce_phe_client_enroll_account_php($this->pheClientNewPHPFunc, self::STRING,
//            self::STRING);
//        $this->assertNotEmpty($enrollAccountFunction);
//    }
}
