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

class KeyProvider
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
        $this->ctx = is_null($ctx) ? vscf_key_provider_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_key_provider_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$random
    * @return void
    */
    public function useRandom(Random $$random): void
    {
        vscf_key_provider_use_random_php($this->ctx, $$random);
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_key_provider_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @param int $$bitlen
    * @return void
    */
    public function setRsaParams(int $$bitlen): void
    {
        vscf_key_provider_set_rsa_params_php($this->ctx, $$bitlen);
    }

    /**
    *
    * @param AlgId $$algId
    * @return PrivateKey
    * @throws \Exception
    */
    public function generatePrivateKey(AlgId $$algId): PrivateKey
    {
        $ctx = vscf_key_provider_generate_private_key_php($this->ctx, $$algId);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @return PrivateKey
    * @throws \Exception
    */
    public function generatePostQuantumPrivateKey(): PrivateKey
    {
        $ctx = vscf_key_provider_generate_post_quantum_private_key_php($this->ctx);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param AlgId $$cipherAlgId
    * @param AlgId $$signerAlgId
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateCompoundPrivateKey(AlgId $$cipherAlgId, AlgId $$signerAlgId): PrivateKey
    {
        $ctx = vscf_key_provider_generate_compound_private_key_php($this->ctx, $$cipherAlgId, $$signerAlgId);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param AlgId $$firstKeyAlgId
    * @param AlgId $$secondKeyAlgId
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateHybridPrivateKey(AlgId $$firstKeyAlgId, AlgId $$secondKeyAlgId): PrivateKey
    {
        $ctx = vscf_key_provider_generate_hybrid_private_key_php($this->ctx, $$firstKeyAlgId, $$secondKeyAlgId);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param AlgId $$cipherFirstKeyAlgId
    * @param AlgId $$cipherSecondKeyAlgId
    * @param AlgId $$signerFirstKeyAlgId
    * @param AlgId $$signerSecondKeyAlgId
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateCompoundHybridPrivateKey(AlgId $$cipherFirstKeyAlgId, AlgId $$cipherSecondKeyAlgId, AlgId $$signerFirstKeyAlgId, AlgId $$signerSecondKeyAlgId): PrivateKey
    {
        $ctx = vscf_key_provider_generate_compound_hybrid_private_key_php($this->ctx, $$cipherFirstKeyAlgId, $$cipherSecondKeyAlgId, $$signerFirstKeyAlgId, $$signerSecondKeyAlgId);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param string $$keyData
    * @return PrivateKey
    * @throws \Exception
    */
    public function importPrivateKey(string $$keyData): PrivateKey
    {
        $ctx = vscf_key_provider_import_private_key_php($this->ctx, $$keyData);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param string $$keyData
    * @return PublicKey
    * @throws \Exception
    */
    public function importPublicKey(string $$keyData): PublicKey
    {
        $ctx = vscf_key_provider_import_public_key_php($this->ctx, $$keyData);
        return FoundationImplementation::wrapPublicKey($ctx);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return int
    */
    public function exportedPublicKeyLen(PublicKey $$publicKey): int
    {
        return vscf_key_provider_exported_public_key_len_php($this->ctx, $$publicKey->getCtx());
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return string
    * @throws \Exception
    */
    public function exportPublicKey(PublicKey $$publicKey): string
    {
        return vscf_key_provider_export_public_key_php($this->ctx, $$publicKey->getCtx());
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return int
    */
    public function exportedPrivateKeyLen(PrivateKey $$privateKey): int
    {
        return vscf_key_provider_exported_private_key_len_php($this->ctx, $$privateKey->getCtx());
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return string
    * @throws \Exception
    */
    public function exportPrivateKey(PrivateKey $$privateKey): string
    {
        return vscf_key_provider_export_private_key_php($this->ctx, $$privateKey->getCtx());
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
