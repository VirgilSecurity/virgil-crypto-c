<?php
/**
* Copyright (C) 2015-2026 Virgil Security, Inc.
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

namespace Virgil\CryptoWrapper\Foundation;

class Shamir
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
        $this->ctx = is_null($ctx) ? vscf_shamir_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_shamir_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$random
    * @return void
    */
    public function useRandom(Random $$random): void
    {
        vscf_shamir_use_random_php($this->ctx, $$random);
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_shamir_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @param int $$secretLen
    * @return int
    */
    public static function shareLen(int $$secretLen): int
    {
        return vscf_shamir_share_len_php($$secretLen);
    }

    /**
    *
    * @param int $$secretLen
    * @param int $$shareCount
    * @return int
    */
    public static function sharesLen(int $$secretLen, int $$shareCount): int
    {
        return vscf_shamir_shares_len_php($$secretLen, $$shareCount);
    }

    /**
    *
    * @param int $$sharesLen
    * @param int $$shareCount
    * @return int
    */
    public static function recoveredSecretLen(int $$sharesLen, int $$shareCount): int
    {
        return vscf_shamir_recovered_secret_len_php($$sharesLen, $$shareCount);
    }

    /**
    *
    * @param string $$secret
    * @param int $$threshold
    * @param int $$shareCount
    * @return string
    * @throws \Exception
    */
    public function split(string $$secret, int $$threshold, int $$shareCount): string
    {
        return vscf_shamir_split_php($this->ctx, $$secret, $$threshold, $$shareCount);
    }

    /**
    *
    * @param string $$shares
    * @param int $$shareCount
    * @return string
    * @throws \Exception
    */
    public function combine(string $$shares, int $$shareCount): string
    {
        return vscf_shamir_combine_php($this->ctx, $$shares, $$shareCount);
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
