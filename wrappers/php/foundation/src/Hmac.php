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
* Virgil Security implementation of HMAC algorithm (RFC 2104) (FIPS PUB 198-1).
*/
class Hmac implements Alg, Mac
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
        $this->ctx = is_null($ctx) ? vscf_hmac_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_hmac_delete_php($this->ctx);
    }

    /**
    * @param Hash $hash
    * @return void
    */
    public function useHash(Hash $hash): void
    {
        vscf_hmac_use_hash_php($this->ctx, $hash->getCtx());
    }

    /**
    * Provide algorithm identificator.
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_hmac_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Produce object with algorithm information and configuration parameters.
    *
    * @return AlgInfo
    * @throws \Exception
    */
    public function produceAlgInfo(): AlgInfo
    {
        $ctx = vscf_hmac_produce_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    * Restore algorithm configuration from the given object.
    *
    * @param AlgInfo $algInfo
    * @return void
    * @throws \Exception
    */
    public function restoreAlgInfo(AlgInfo $algInfo): void
    {
        vscf_hmac_restore_alg_info_php($this->ctx, $algInfo->getCtx());
    }

    /**
    * Size of the digest (mac output) in bytes.
    *
    * @return int
    */
    public function digestLen(): int
    {
        return vscf_hmac_digest_len_php($this->ctx);
    }

    /**
    * Calculate MAC over given data.
    *
    * @param string $key
    * @param string $data
    * @return string
    */
    public function mac(string $key, string $data): string
    {
        return vscf_hmac_mac_php($this->ctx, $key, $data);
    }

    /**
    * Start a new MAC.
    *
    * @param string $key
    * @return void
    */
    public function start(string $key): void
    {
        vscf_hmac_start_php($this->ctx, $key);
    }

    /**
    * Add given data to the MAC.
    *
    * @param string $data
    * @return void
    */
    public function update(string $data): void
    {
        vscf_hmac_update_php($this->ctx, $data);
    }

    /**
    * Accomplish MAC and return it's result (a message digest).
    *
    * @return string
    */
    public function finish(): string
    {
        return vscf_hmac_finish_php($this->ctx);
    }

    /**
    * Prepare to authenticate a new message with the same key
    * as the previous MAC operation.
    *
    * @return void
    */
    public function reset(): void
    {
        vscf_hmac_reset_php($this->ctx);
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
