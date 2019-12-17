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

class KeyInfo
{

    /**
    * @var
    */
    private $ctx;

    /**
    * Build key information based on the generic algorithm information.
    *
    * @param AlgInfo $algInfo
    * @return KeyInfo
    */
    public static function withAlgInfo(AlgInfo $algInfo): KeyInfo
    {
        $ctx = vscf_key_info_with_alg_info_php($algInfo);
        return new KeyInfo($ctx);
    }

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
    * Return true if a key is a compound key
    *
    * @return bool
    */
    public function isCompound(): bool
    {
        return vscf_key_info_is_compound_php($this->ctx);
    }

    /**
    * Return true if a key is a chained key
    *
    * @return bool
    */
    public function isChained(): bool
    {
        return vscf_key_info_is_chained_php($this->ctx);
    }

    /**
    * Return true if a key is a compound key and compounds cipher key
    * and signer key are chained keys.
    *
    * @return bool
    */
    public function isCompoundChained(): bool
    {
        return vscf_key_info_is_compound_chained_php($this->ctx);
    }

    /**
    * Return true if a key is a compound key and compounds cipher key
    * is a chained key.
    *
    * @return bool
    */
    public function isCompoundChainedCipher(): bool
    {
        return vscf_key_info_is_compound_chained_cipher_php($this->ctx);
    }

    /**
    * Return true if a key is a compound key and compounds signer key
    * is a chained key.
    *
    * @return bool
    */
    public function isCompoundChainedSigner(): bool
    {
        return vscf_key_info_is_compound_chained_signer_php($this->ctx);
    }

    /**
    * Return true if a key is a compound key that contains chained keys
    * for encryption/decryption and signing/verifying that itself
    * contains a combination of classic keys and post-quantum keys.
    *
    * @return bool
    */
    public function isHybridPostQuantum(): bool
    {
        return vscf_key_info_is_hybrid_post_quantum_php($this->ctx);
    }

    /**
    * Return true if a key is a compound key that contains a chained key
    * for encryption/decryption that contains a classic key and
    * a post-quantum key.
    *
    * @return bool
    */
    public function isHybridPostQuantumCipher(): bool
    {
        return vscf_key_info_is_hybrid_post_quantum_cipher_php($this->ctx);
    }

    /**
    * Return true if a key is a compound key that contains a chained key
    * for signing/verifying that contains a classic key and
    * a post-quantum key.
    *
    * @return bool
    */
    public function isHybridPostQuantumSigner(): bool
    {
        return vscf_key_info_is_hybrid_post_quantum_signer_php($this->ctx);
    }

    /**
    * Return common type of the key.
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_key_info_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Return compound's cipher key id, if key is compound.
    * Return None, otherwise.
    *
    * @return AlgId
    */
    public function compoundCipherAlgId(): AlgId
    {
        $enum = vscf_key_info_compound_cipher_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Return compound's signer key id, if key is compound.
    * Return None, otherwise.
    *
    * @return AlgId
    */
    public function compoundSignerAlgId(): AlgId
    {
        $enum = vscf_key_info_compound_signer_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Return chained l1 key id, if key is chained.
    * Return None, otherwise.
    *
    * @return AlgId
    */
    public function chainedL1AlgId(): AlgId
    {
        $enum = vscf_key_info_chained_l1_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Return chained l2 key id, if key is chained.
    * Return None, otherwise.
    *
    * @return AlgId
    */
    public function chainedL2AlgId(): AlgId
    {
        $enum = vscf_key_info_chained_l2_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Return l1 key id of compound's cipher key, if key is compound(chained, ...)
    * Return None, otherwise.
    *
    * @return AlgId
    */
    public function compoundCipherL1AlgId(): AlgId
    {
        $enum = vscf_key_info_compound_cipher_l1_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Return l2 key id of compound's cipher key, if key is compound(chained, ...)
    * Return None, otherwise.
    *
    * @return AlgId
    */
    public function compoundCipherL2AlgId(): AlgId
    {
        $enum = vscf_key_info_compound_cipher_l2_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Return l1 key id of compound's signer key, if key is compound(..., chained)
    * Return None, otherwise.
    *
    * @return AlgId
    */
    public function compoundSignerL1AlgId(): AlgId
    {
        $enum = vscf_key_info_compound_signer_l1_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    * Return l2 key id of compound's signer key, if key is compound(..., chained)
    * Return None, otherwise.
    *
    * @return AlgId
    */
    public function compoundSignerL2AlgId(): AlgId
    {
        $enum = vscf_key_info_compound_signer_l2_alg_id_php($this->ctx);
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
