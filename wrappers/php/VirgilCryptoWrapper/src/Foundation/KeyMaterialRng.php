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
* Random number generator that generate deterministic sequence based
* on a given seed.
* This RNG can be used to transform key material rial to the private key.
*/
class KeyMaterialRng implements Random
{

    /**
    * @var
    */
    private $ctx;

    const KEY_MATERIAL_LEN_MIN = 32;
    const KEY_MATERIAL_LEN_MAX = 512;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_key_material_rng_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_key_material_rng_delete_php($this->ctx);
    }

    /**
    * Set a new key material.
    *
    * @param string $keyMaterial
    * @return void
    */
    public function resetKeyMaterial(string $keyMaterial): void
    {
        vscf_key_material_rng_reset_key_material_php($this->ctx, $keyMaterial);
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
        return vscf_key_material_rng_random_php($this->ctx, $dataLen);
    }

    /**
    * Retrieve new seed data from the entropy sources.
    *
    * @return void
    * @throws \Exception
    */
    public function reseed(): void
    {
        vscf_key_material_rng_reseed_php($this->ctx);
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
