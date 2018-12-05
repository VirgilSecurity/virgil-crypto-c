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

class PHEClient
{
    //<method name="set keys">
    //<argument name="client private key" class="data"/>
    //<argument name="server public key" class="data"/>
    //</method>
    /**
     * @param string $clientPrivateKey
     * @param string $serverPublicKey
     * @return void
     */
    public function setKeys(string $clientPrivateKey, string $serverPublicKey): void
    {

    }

    //<method name="generate client private key">
    //<argument name="client private key" class="buffer" access="writeonly">
    //<length constant=".(class_phe_common_constant_phe_private_key_length)"/>
    //</argument>
    //
    //<return enum="error"/>
    //</method>
    /**
     * @return string | Exception
     */
    public function generateClientPrivateKey():string
    {
        $clientPrivateKey = "";
        return $clientPrivateKey;
    }

    //<method name="enrollment record len">
    //<return type="size"/>
    //</method>
    /**
     * @return int
     */
    public function enrollmentRecordLen(): int
    {
        $int = 5;
        return $int;
    }

    //<method name="enroll account">
    //<argument name="enrollment response" class="data"/>
    //<argument name="password" class="data"/>
    //<argument name="enrollment record" class="buffer" access="writeonly">
    //<length method="enrollment record len"/>
    //</argument>
    //<argument name="account key" class="buffer" access="writeonly">
    //<length constant=".(class_phe_common_constant_phe_secret_message_length)"/>
    //</argument>
    //
    //<return enum="error"/>
    //</method>
    /**
     * @param string $enrollmentResponse
     * @param string $password
     * @return array | Exception
     */
    public function enrollAccount(string $enrollmentResponse, string $password): array
    {
        $enrollmentRecord = "";
        $accountKey = "";

        return [$enrollmentRecord, $accountKey];
    }

    //<method name="verify password request len">
    //<return type="size"/>
    //</method>
    /**
     * @return int
     */
    public function verifyPasswordRequestLen(): int
    {
        $int = 5;
        return $int;
    }

    //<method name="create verify password request">
    //<argument name="password" class="data"/>
    //<argument name="enrollment record" class="data"/>
    //<argument name="verify password request" class="buffer" access="writeonly">
    //<length method="verify password request len"/>
    //</argument>
    //
    //<return enum="error"/>
    //</method>
    /**
     * @param string $data
     * @param string $enrollmentRecord
     * @return string | Exception
     */
    public function createVerifyPasswordRequest(string $data, string $enrollmentRecord): string
    {
        $verifyPasswordRequest = "";
        return $verifyPasswordRequest;
    }


    //<method name="check response and decrypt">
    //<argument name="password" class="data"/>
    //<argument name="enrollment record" class="data"/>
    //<argument name="verify password response" class="data"/>
    //<argument name="account key" class="buffer" access="writeonly">
    //<length constant=".(class_phe_common_constant_phe_secret_message_length)"/>
    //</argument>
    //
    //<return enum="error"/>
    //</method>
    /**
     * @param string $password
     * @param string $enrollmentRecord
     * @param string $verifyPasswordResponse
     * @return string | Exception
     */
    public function checkResponseAndDecrypt(string $password, string $enrollmentRecord, string
    $verifyPasswordResponse): string
    {
        $accountKey = "";
        return $accountKey;
    }

    //<method name="rotate keys">
    //<argument name="update token" class="data"/>
    //
    //<argument name="new client private key" class="buffer" access="writeonly">
    //<length constant=".(class_phe_common_constant_phe_private_key_length)"/>
    //</argument>
    //<argument name="new server public key" class="buffer" access="writeonly">
    //<length constant=".(class_phe_common_constant_phe_public_key_length)"/>
    //</argument>
    //
    //<return enum="error"/>
    //</method>
    /**
     * @param string $updateToken
     * @return array | Exception
     */
    public function rotateKeys(string $updateToken): array
    {
        $newClientPrivateKey = "";
        $newServerPrivateKey = "";

        return [$newClientPrivateKey, $newServerPrivateKey];
    }

    //<method name="update enrollment record">
    //<argument name="enrollment record" class="data"/>
    //<argument name="update token" class="data"/>
    //<argument name="new enrollment record" class="buffer" access="writeonly">
    //<length method="enrollment record len"/>
    //</argument>
    //
    //<return enum="error"/>
    //</method>
    /**
     * @param string $enrollmentRecord
     * @param string $updateToken
     * @return array | Exception
     */
    public function updateEnrollmentRecord(string $enrollmentRecord, string $updateToken): string
    {
        $newEnrollmentRecord = "";
        return $newEnrollmentRecord;
    }
}