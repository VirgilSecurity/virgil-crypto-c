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
* Virgil Security implementation of the PBKDF2 (RFC 8018) algorithm.
*/
class Pkcs5Pbkdf2 implements Alg, Kdf, SaltedKdf
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
        $this->ctx = is_null($ctx) ? vscf_pkcs5_pbkdf2_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_pkcs5_pbkdf2_delete_php($this->ctx);
    }

    /**
    * @param Mac $hmac
    * @return void
    */
    public function useHmac(Mac $hmac): void
    {
        vscf_pkcs5_pbkdf2_use_hmac_php($this->ctx, $hmac->getCtx());
    }

    /**
    * Setup predefined values to the uninitialized class dependencies.
    *
    * @return void
    */
    public function setupDefaults(): void
    {
        vscf_pkcs5_pbkdf2_setup_defaults_php($this->ctx);
    }

    /**
    * Provide algorithm identificator.
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_pkcs5_pbkdf2_alg_id_php($this->ctx);
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
        $ctx = vscf_pkcs5_pbkdf2_produce_alg_info_php($this->ctx);
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
        vscf_pkcs5_pbkdf2_restore_alg_info_php($this->ctx, $algInfo->getCtx());
    }

    /**
    * Derive key of the requested length from the given data.
    *
    * @param string $data
    * @param int $keyLen
    * @return string
    */
    public function derive(string $data, int $keyLen): string
    {
        return vscf_pkcs5_pbkdf2_derive_php($this->ctx, $data, $keyLen);
    }

    /**
    * Prepare algorithm to derive new key.
    *
    * @param string $salt
    * @param int $iterationCount
    * @return void
    */
    public function reset(string $salt, int $iterationCount): void
    {
        vscf_pkcs5_pbkdf2_reset_php($this->ctx, $salt, $iterationCount);
    }

    /**
    * Setup application specific information (optional).
    * Can be empty.
    *
    * @param string $info
    * @return void
    */
    public function setInfo(string $info): void
    {
        vscf_pkcs5_pbkdf2_set_info_php($this->ctx, $info);
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
