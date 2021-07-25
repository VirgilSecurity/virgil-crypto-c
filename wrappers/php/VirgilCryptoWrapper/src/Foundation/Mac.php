<?php
/**
* Copyright (C) 2015-2021 Virgil Security, Inc.
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

/**
* Provides interface to the stateless MAC (message authentication code) algorithms.
*/
interface Mac extends Ctx
{

    /**
    * Size of the digest (mac output) in bytes.
    *
    * @return int
    */
    public function digestLen(): int;

    /**
    * Calculate MAC over given data.
    *
    * @param string $key
    * @param string $data
    * @return string
    */
    public function mac(string $key, string $data): string;

    /**
    * Start a new MAC.
    *
    * @param string $key
    * @return void
    */
    public function start(string $key): void;

    /**
    * Add given data to the MAC.
    *
    * @param string $data
    * @return void
    */
    public function update(string $data): void;

    /**
    * Accomplish MAC and return it's result (a message digest).
    *
    * @return string
    */
    public function finish(): string;

    /**
    * Prepare to authenticate a new message with the same key
    * as the previous MAC operation.
    *
    * @return void
    */
    public function reset(): void;
}
