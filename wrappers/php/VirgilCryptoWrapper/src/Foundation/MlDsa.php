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

class MlDsa implements Alg, KeyAlg, KeySigner
{

    /**
    * @var
    */
    private $ctx;

    const SEED_LEN = 32;
    const PUBLIC_KEY_LEN = 1952;
    const SECRET_KEY_LEN = 4032;
    const SIGNATURE_LEN = 3309;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_ml_dsa_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_ml_dsa_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$random
    * @return void
    */
    public function useRandom(Random $$random): void
    {
        vscf_ml_dsa_use_random_php($this->ctx, $$random);
    }

    /**
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_ml_dsa_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgInfo
    */
    public function produceAlgInfo(): AlgInfo
    {
        $ctx = vscf_ml_dsa_produce_alg_info_php($this->ctx);
        return FoundationImplementation::wrapAlgInfo($ctx);
    }

    /**
    *
    * @param AlgInfo $$algInfo
    * @return void
    * @throws \Exception
    */
    public function restoreAlgInfo(AlgInfo $$algInfo): void
    {
        vscf_ml_dsa_restore_alg_info_php($this->ctx, $$algInfo->getCtx());
    }

    /**
    *
    * @param Key $$key
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateEphemeralKey(Key $$key): PrivateKey
    {
        $ctx = vscf_ml_dsa_generate_ephemeral_key_php($this->ctx, $$key->getCtx());
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param RawPublicKey $$rawKey
    * @return PublicKey
    * @throws \Exception
    */
    public function importPublicKey(RawPublicKey $$rawKey): PublicKey
    {
        $ctx = vscf_ml_dsa_import_public_key_php($this->ctx, $$rawKey);
        return FoundationImplementation::wrapPublicKey($ctx);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return RawPublicKey
    * @throws \Exception
    */
    public function exportPublicKey(PublicKey $$publicKey): RawPublicKey
    {
        $ctx = vscf_ml_dsa_export_public_key_php($this->ctx, $$publicKey->getCtx());
        return new RawPublicKey($ctx);
    }

    /**
    *
    * @param RawPrivateKey $$rawKey
    * @return PrivateKey
    * @throws \Exception
    */
    public function importPrivateKey(RawPrivateKey $$rawKey): PrivateKey
    {
        $ctx = vscf_ml_dsa_import_private_key_php($this->ctx, $$rawKey);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return RawPrivateKey
    * @throws \Exception
    */
    public function exportPrivateKey(PrivateKey $$privateKey): RawPrivateKey
    {
        $ctx = vscf_ml_dsa_export_private_key_php($this->ctx, $$privateKey->getCtx());
        return new RawPrivateKey($ctx);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return bool
    */
    public function canSign(PrivateKey $$privateKey): bool
    {
        return vscf_ml_dsa_can_sign_php($this->ctx, $$privateKey->getCtx());
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return int
    */
    public function signatureLen(PrivateKey $$privateKey): int
    {
        return vscf_ml_dsa_signature_len_php($this->ctx, $$privateKey->getCtx());
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @param AlgId $$hashId
    * @param string $$digest
    * @return string
    * @throws \Exception
    */
    public function signHash(PrivateKey $$privateKey, AlgId $$hashId, string $$digest): string
    {
        return vscf_ml_dsa_sign_hash_php($this->ctx, $$privateKey->getCtx(), $$hashId, $$digest);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return bool
    */
    public function canVerify(PublicKey $$publicKey): bool
    {
        return vscf_ml_dsa_can_verify_php($this->ctx, $$publicKey->getCtx());
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @param AlgId $$hashId
    * @param string $$digest
    * @param string $$signature
    * @return bool
    */
    public function verifyHash(PublicKey $$publicKey, AlgId $$hashId, string $$digest, string $$signature): bool
    {
        return vscf_ml_dsa_verify_hash_php($this->ctx, $$publicKey->getCtx(), $$hashId, $$digest, $$signature);
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_ml_dsa_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateKey(): PrivateKey
    {
        $ctx = vscf_ml_dsa_generate_key_php($this->ctx);
        return FoundationImplementation::wrapPrivateKey($ctx);
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
