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
* Handles chained public key.
*
* Chained public key contains 2 public keys:
* - l1 key:
* - can be used for plain text encryption;
* - can be used to verify l1 signature;
* - l2 key:
* - can be used for l1 output encryption;
* - can be used to verify l2 signature.
*/
class ChainedPublicKey implements Key, PublicKey
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
        $this->ctx = is_null($ctx) ? vscf_chained_public_key_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_chained_public_key_delete_php($this->ctx);
    }

    /**
    * Return l1 public key.
    *
    * @return PublicKey
    * @throws \Exception
    */
    public function l1Key(): PublicKey
    {
        $ctx = vscf_chained_public_key_l1_key_php($this->ctx);
        return FoundationImplementation::wrapPublicKey($ctx);
    }

    /**
    * Return l2 public key.
    *
    * @return PublicKey
    * @throws \Exception
    */
    public function l2Key(): PublicKey
    {
        $ctx = vscf_chained_public_key_l2_key_php($this->ctx);
        return FoundationImplementation::wrapPublicKey($ctx);
    }

    /**
    * Algorithm identifier the key belongs to.
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_chained_public_key_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Return algorithm information that can be used for serialization.
    *
    * @return AlgInfo
    * @throws \Exception
    */
    public function algInfo(): AlgInfo
    {
        $ctx = vscf_chained_public_key_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    * Length of the key in bytes.
    *
    * @return int
    */
    public function len(): int
    {
        return vscf_chained_public_key_len_php($this->ctx);
    }

    /**
    * Length of the key in bits.
    *
    * @return int
    */
    public function bitlen(): int
    {
        return vscf_chained_public_key_bitlen_php($this->ctx);
    }

    /**
    * Check that key is valid.
    * Note, this operation can be slow.
    *
    * @return bool
    */
    public function isValid(): bool
    {
        return vscf_chained_public_key_is_valid_php($this->ctx);
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
