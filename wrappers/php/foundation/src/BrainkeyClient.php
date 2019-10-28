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

class BrainkeyClient
{

    /**
    * @var
    */
    private $ctx;

    const POINT_LEN = 65;
    const MPI_LEN = 32;
    const SEED_LEN = 32;
    const MAX_PASSWORD_LEN = 128;
    const MAX_KEY_NAME_LEN = 128;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_brainkey_client_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_brainkey_client_delete_php($this->ctx);
    }

    /**
    * @param Random $random
    * @return void
    */
    public function useRandom(Random $random): void
    {
        vscf_brainkey_client_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * @param Random $operationRandom
    * @return void
    */
    public function useOperationRandom(Random $operationRandom): void
    {
        vscf_brainkey_client_use_operation_random_php($this->ctx, $operationRandom->getCtx());
    }

    /**
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_brainkey_client_setup_defaults_php($this->ctx);
    }

    /**
    * @param string $password
    * @return array
    * @throws \Exception
    */
    public function blind(string $password): array // [deblind_factor, blinded_point]
    {
        return vscf_brainkey_client_blind_php($this->ctx, $password);
    }

    /**
    * @param string $password
    * @param string $hardenedPoint
    * @param string $deblindFactor
    * @param string $keyName
    * @return string
    * @throws \Exception
    */
    public function deblind(string $password, string $hardenedPoint, string $deblindFactor, string $keyName): string
    {
        return vscf_brainkey_client_deblind_php($this->ctx, $password, $hardenedPoint, $deblindFactor, $keyName);
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
