<?php
/**
* Copyright (C) 2015-2022 Virgil Security, Inc.
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

class KeyInfo
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
        $this->ctx = is_null($ctx) ? vscf_key_info_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_key_info_delete_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function isCompound(): bool
    {
        return vscf_key_info_is_compound_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function isHybrid(): bool
    {
        return vscf_key_info_is_hybrid_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function isCompoundHybrid(): bool
    {
        return vscf_key_info_is_compound_hybrid_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function isCompoundHybridCipher(): bool
    {
        return vscf_key_info_is_compound_hybrid_cipher_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function isCompoundHybridSigner(): bool
    {
        return vscf_key_info_is_compound_hybrid_signer_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function isHybridPostQuantum(): bool
    {
        return vscf_key_info_is_hybrid_post_quantum_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function isHybridPostQuantumCipher(): bool
    {
        return vscf_key_info_is_hybrid_post_quantum_cipher_php($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function isHybridPostQuantumSigner(): bool
    {
        return vscf_key_info_is_hybrid_post_quantum_signer_php($this->ctx);
    }

    /**
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_key_info_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgId
    */
    public function compoundCipherAlgId(): AlgId
    {
        $enum = vscf_key_info_compound_cipher_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgId
    */
    public function compoundSignerAlgId(): AlgId
    {
        $enum = vscf_key_info_compound_signer_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgId
    */
    public function hybridFirstKeyAlgId(): AlgId
    {
        $enum = vscf_key_info_hybrid_first_key_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgId
    */
    public function hybridSecondKeyAlgId(): AlgId
    {
        $enum = vscf_key_info_hybrid_second_key_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgId
    */
    public function compoundHybridCipherFirstKeyAlgId(): AlgId
    {
        $enum = vscf_key_info_compound_hybrid_cipher_first_key_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgId
    */
    public function compoundHybridCipherSecondKeyAlgId(): AlgId
    {
        $enum = vscf_key_info_compound_hybrid_cipher_second_key_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgId
    */
    public function compoundHybridSignerFirstKeyAlgId(): AlgId
    {
        $enum = vscf_key_info_compound_hybrid_signer_first_key_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgId
    */
    public function compoundHybridSignerSecondKeyAlgId(): AlgId
    {
        $enum = vscf_key_info_compound_hybrid_signer_second_key_alg_id_php($this->ctx);
        return new AlgId($enum);
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
