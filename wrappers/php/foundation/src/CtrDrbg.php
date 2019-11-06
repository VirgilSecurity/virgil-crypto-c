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
* Implementation of the RNG using deterministic random bit generators
* based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
* This class is thread-safe if the build option VSCF_MULTI_THREADING was enabled.
*/
class CtrDrbg implements Random
{

    /**
    * @var
    */
    private $ctx;

    const RESEED_INTERVAL = 10000;
    const ENTROPY_LEN = 48;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_ctr_drbg_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_ctr_drbg_delete_php($this->ctx);
    }

    /**
    * @param EntropySource $entropySource
    * @return void
    * @throws \Exception
    */
    public function useEntropySource(EntropySource $entropySource): void
    {
        vscf_ctr_drbg_use_entropy_source_php($this->ctx, $entropySource->getCtx());
    }

    /**
    * Setup predefined values to the uninitialized class dependencies.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_ctr_drbg_setup_defaults_php($this->ctx);
    }

    /**
    * Force entropy to be gathered at the beginning of every call to
    * the random() method.
    * Note, use this if your entropy source has sufficient throughput.
    *
    * @return void
    */
    public function enablePredictionResistance(): void
    {
        vscf_ctr_drbg_enable_prediction_resistance_php($this->ctx);
    }

    /**
    * Sets the reseed interval.
    * Default value is reseed interval.
    *
    * @param int $interval
    * @return void
    */
    public function setReseedInterval(int $interval): void
    {
        vscf_ctr_drbg_set_reseed_interval_php($this->ctx, $interval);
    }

    /**
    * Sets the amount of entropy grabbed on each seed or reseed.
    * The default value is entropy len.
    *
    * @param int $len
    * @return void
    */
    public function setEntropyLen(int $len): void
    {
        vscf_ctr_drbg_set_entropy_len_php($this->ctx, $len);
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
        return vscf_ctr_drbg_random_php($this->ctx, $dataLen);
    }

    /**
    * Retrieve new seed data from the entropy sources.
    *
    * @return void
    * @throws \Exception
    */
    public function reseed(): void
    {
        vscf_ctr_drbg_reseed_php($this->ctx);
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
