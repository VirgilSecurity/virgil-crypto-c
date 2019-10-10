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

namespace VirgilCrypto\Foundation;

/**
* Implementation based on a simple entropy accumulator.
*/
class EntropyAccumulator implements EntropySource
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
        $this->ctx = is_null($ctx) ? vscf_entropy_accumulator_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_entropy_accumulator_delete_php($this->ctx);
    }

    /**
    * Setup predefined values to the uninitialized class dependencies.
    *
    * @return void
    */
    public function setupDefaults(): void
    {
        vscf_entropy_accumulator_setup_defaults_php($this->ctx);
    }

    /**
    * Add given entropy source to the accumulator.
    * Threshold defines minimum number of bytes that must be gathered
    * from the source during accumulation.
    *
    * @param EntropySource $source
    * @param int $threshold
    * @return void
    */
    public function addSource(EntropySource $source, int $threshold): void
    {
        vscf_entropy_accumulator_add_source_php($this->ctx, $source->getCtx(), $threshold);
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

    /**
    * Defines that implemented source is strong.
    *
    * @return bool
    */
    public function isStrong(): bool
    {
        return vscf_entropy_accumulator_is_strong_php($this->ctx);
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
        return vscf_entropy_accumulator_gather_php($this->ctx, $len);
    }
}
