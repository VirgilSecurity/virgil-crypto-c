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

class PHEServer
{
    /**
     * @var
     */
    private $c_ctx;

    /**
     * PHEServer constructor.
     * @return void
     */
    public function __construct()
    {
        $this->c_ctx = vsce_phe_server_new_php();
    }

    /**
     * PHEServer destructor.
     * @return void
     */
    public function __destruct()
    {
        vsce_phe_server_delete_php($this->c_ctx);
    }

    /**
     * @return void
     * @throws Exception
     */
    public function setupDefaults()
    {
        vsce_phe_server_setup_defaults_php($this->c_ctx);
    }

    /**
     * @return array
     * @throws Exception
     */
    public function generateServerKeyPair(): array
    {
        return vsce_phe_server_generate_server_key_pair_php($this->c_ctx);
    }

    /**
     * @param string $serverPrivateKey
     * @param string $serverPublicKey
     * @return string
     * @throws Exception
     */
    public function getEnrollment(string $serverPrivateKey, string $serverPublicKey): string
    {
        return vsce_phe_server_get_enrollment_php($this->c_ctx, $serverPrivateKey, $serverPublicKey);
    }

    /**
     * @param string $serverPrivateKey
     * @param string $serverPublicKey
     * @param $verifyPasswordRequest
     * @return string
     * @throws Exception
     */
    public function verifyPassword(string $serverPrivateKey, string $serverPublicKey, $verifyPasswordRequest): string
    {
        return vsce_phe_server_verify_password_php($this->c_ctx, $serverPrivateKey, $serverPublicKey, $verifyPasswordRequest);
    }

    /**
     * @param string $serverPrivateKey
     * @return array
     * @throws Exception
     */
    public function rotateKeys(string $serverPrivateKey): array
    {
        return vsce_phe_server_rotate_keys_php($this->c_ctx, $serverPrivateKey);
    }
}
