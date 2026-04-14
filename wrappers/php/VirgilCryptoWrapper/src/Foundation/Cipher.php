<?php
/**
* Copyright (C) 2015-2022 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
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

namespace Virgil\CryptoWrapper\Foundation;

interface Cipher extends Ctx
{

    /**
    *
    * @param string $$nonce
    * @return void
    */
    public function setNonce(string $$nonce): void
    {
        ($this->ctx, $$nonce);
    }

    /**
    *
    * @param string $$key
    * @return void
    */
    public function setKey(string $$key): void
    {
        ($this->ctx, $$key);
    }

    /**
    *
    * @return void
    */
    public function startEncryption(): void
    {
        ($this->ctx);
    }

    /**
    *
    * @return void
    */
    public function startDecryption(): void
    {
        ($this->ctx);
    }

    /**
    *
    * @param string $$data
    * @return string
    */
    public function update(string $$data): string
    {
        return ($this->ctx, $$data);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function outLen(int $$dataLen): int
    {
        return ($this->ctx, $$dataLen);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function encryptedOutLen(int $$dataLen): int
    {
        return ($this->ctx, $$dataLen);
    }

    /**
    *
    * @param int $$dataLen
    * @return int
    */
    public function decryptedOutLen(int $$dataLen): int
    {
        return ($this->ctx, $$dataLen);
    }

    /**
    *
    * @return string
    * @throws \Exception
    */
    public function finish(): string
    {
        return ($this->ctx);
    }

}
