<?php
/**
* Copyright (C) 2015-2020 Virgil Security, Inc.
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
* Random number generator that is used for test purposes only.
*/
class FakeRandom implements Random, EntropySource
{

    /**
    * @var
    */
    private $ctx;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_fake_random_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_fake_random_delete_php($this->ctx);
    }

    /**
    * Configure random number generator to generate sequence filled with given byte.
    *
    * @param int $byteSource
    * @return void
    */
    public function setupSourceByte(int $byteSource): void
    {
        vscf_fake_random_setup_source_byte_php($this->ctx, $byteSource);
    }

    /**
    * Configure random number generator to generate random sequence from given data.
    * Note, that given data is used as circular source.
    *
    * @param string $dataSource
    * @return void
    */
    public function setupSourceData(string $dataSource): void
    {
        vscf_fake_random_setup_source_data_php($this->ctx, $dataSource);
    }

    /**
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    *
    * @param int $dataLen
    * @return string
    * @throws \Exception
    */
    public function random(int $dataLen): string
    {
        return vscf_fake_random_random_php($this->ctx, $dataLen);
    }

    /**
    * Retrieve new seed data from the entropy sources.
    *
    * @return void
    * @throws \Exception
    */
    public function reseed(): void
    {
        vscf_fake_random_reseed_php($this->ctx);
    }

    /**
    * Defines that implemented source is strong.
    *
    * @return bool
    */
    public function isStrong(): bool
    {
        return vscf_fake_random_is_strong_php($this->ctx);
    }

    /**
    * Gather entropy of the requested length.
    *
    * @param int $len
    * @return string
    * @throws \Exception
    */
    public function gather(int $len): string
    {
        return vscf_fake_random_gather_php($this->ctx, $len);
    }

    /**
    * Get C context.
    *
    * @return resource
    */
    public function getCtx()
    {
        return $this->ctx;
    }
}
