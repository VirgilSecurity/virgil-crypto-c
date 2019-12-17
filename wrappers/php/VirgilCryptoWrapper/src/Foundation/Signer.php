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

namespace Virgil\CryptoWrapper\Foundation;

/**
* Sign data of any size.
*/
class Signer
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
        $this->ctx = is_null($ctx) ? vscf_signer_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_signer_delete_php($this->ctx);
    }

    /**
    * @param Hash $hash
    * @return void
    */
    public function useHash(Hash $hash): void
    {
        vscf_signer_use_hash_php($this->ctx, $hash->getCtx());
    }

    /**
    * @param Random $random
    * @return void
    */
    public function useRandom(Random $random): void
    {
        vscf_signer_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * Start a processing a new signature.
    *
    * @return void
    */
    public function reset(): void
    {
        vscf_signer_reset_php($this->ctx);
    }

    /**
    * Add given data to the signed data.
    *
    * @param string $data
    * @return void
    */
    public function appendData(string $data): void
    {
        vscf_signer_append_data_php($this->ctx, $data);
    }

    /**
    * Return length of the signature.
    *
    * @param PrivateKey $privateKey
    * @return int
    */
    public function signatureLen(PrivateKey $privateKey): int
    {
        return vscf_signer_signature_len_php($this->ctx, $privateKey->getCtx());
    }

    /**
    * Accomplish signing and return signature.
    *
    * @param PrivateKey $privateKey
    * @return string
    * @throws \Exception
    */
    public function sign(PrivateKey $privateKey): string
    {
        return vscf_signer_sign_php($this->ctx, $privateKey->getCtx());
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
