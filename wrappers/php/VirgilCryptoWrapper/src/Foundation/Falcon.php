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

class Falcon implements Alg, KeyAlg, KeySigner
{

    /**
    * @var
    */
    private $ctx;

    const SEED_LEN = 48;
    const LOGN_512 = 9;
    const LOGN_1024 = 10;
    const CAN_IMPORT_PUBLIC_KEY = true;
    const CAN_EXPORT_PUBLIC_KEY = true;
    const CAN_IMPORT_PRIVATE_KEY = true;
    const CAN_EXPORT_PRIVATE_KEY = true;

    /**
    * Create underlying C context.
    * @param null $ctx
    * @return void
    */
    public function __construct($ctx = null)
    {
        $this->ctx = is_null($ctx) ? vscf_falcon_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_falcon_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$random
    * @return void
    */
    public function useRandom(Random $$random): void
    {
        vscf_falcon_use_random_php($this->ctx, $$random);
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_falcon_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @return PrivateKey
    */
    public function generateKey(): PrivateKey
    {
        $ctx = vscf_falcon_generate_key_php($this->ctx);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_falcon_alg_id_php($this->ctx);
        return new AlgId($enum);
    }

    /**
    *
    * @return AlgInfo
    */
    public function produceAlgInfo(): AlgInfo
    {
        $ctx = vscf_falcon_produce_alg_info_php($this->ctx);
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
        vscf_falcon_restore_alg_info_php($this->ctx, $$algInfo);
    }

    /**
    *
    * @param Key $$key
    * @return PrivateKey
    */
    public function generateEphemeralKey(Key $$key): PrivateKey
    {
        $ctx = vscf_falcon_generate_ephemeral_key_php($this->ctx, $$key);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param RawPublicKey $$rawKey
    * @return PublicKey
    */
    public function importPublicKey(RawPublicKey $$rawKey): PublicKey
    {
        $ctx = vscf_falcon_import_public_key_php($this->ctx, $$rawKey);
        return FoundationImplementation::wrapPublicKey($ctx);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return RawPublicKey
    */
    public function exportPublicKey(PublicKey $$publicKey): RawPublicKey
    {
        $ctx = vscf_falcon_export_public_key_php($this->ctx, $$publicKey);
        return new RawPublicKey($ctx);
    }

    /**
    *
    * @param RawPrivateKey $$rawKey
    * @return PrivateKey
    */
    public function importPrivateKey(RawPrivateKey $$rawKey): PrivateKey
    {
        $ctx = vscf_falcon_import_private_key_php($this->ctx, $$rawKey);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return RawPrivateKey
    */
    public function exportPrivateKey(PrivateKey $$privateKey): RawPrivateKey
    {
        $ctx = vscf_falcon_export_private_key_php($this->ctx, $$privateKey);
        return new RawPrivateKey($ctx);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return bool
    */
    public function canSign(PrivateKey $$privateKey): bool
    {
        return vscf_falcon_can_sign_php($this->ctx, $$privateKey);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return int
    */
    public function signatureLen(PrivateKey $$privateKey): int
    {
        return vscf_falcon_signature_len_php($this->ctx, $$privateKey);
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
        return vscf_falcon_sign_hash_php($this->ctx, $$privateKey, $$hashId, $$digest);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return bool
    */
    public function canVerify(PublicKey $$publicKey): bool
    {
        return vscf_falcon_can_verify_php($this->ctx, $$publicKey);
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
        return vscf_falcon_verify_hash_php($this->ctx, $$publicKey, $$hashId, $$digest, $$signature);
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
