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
* Provide post-quantum encryption based on the round5 implementation.
* For algorithm details check https://github.com/round5/code
*/
class Round5 implements KeyAlg, Kem
{

    /**
    * @var
    */
    private $ctx;

    const SEED_LEN = 48;
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
        $this->ctx = is_null($ctx) ? vscf_round5_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_round5_delete_php($this->ctx);
    }

    /**
    * @param Random $random
    * @return void
    */
    public function useRandom(Random $random): void
    {
        vscf_round5_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * Setup predefined values to the uninitialized class dependencies.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_round5_setup_defaults_php($this->ctx);
    }

    /**
    * Generate new private key.
    * Note, this operation might be slow.
    *
    * @param AlgId $algId
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateKey(AlgId $algId): PrivateKey
    {
        $ctx = vscf_round5_generate_key_php($this->ctx, $algId->getValue());
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    * Generate ephemeral private key of the same type.
    * Note, this operation might be slow.
    *
    * @param Key $key
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateEphemeralKey(Key $key): PrivateKey
    {
        $ctx = vscf_round5_generate_ephemeral_key_php($this->ctx, $key->getCtx());
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    * Import public key from the raw binary format.
    *
    * Return public key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
    *
    * @param RawPublicKey $rawKey
    * @return PublicKey
    * @throws \Exception
    */
    public function importPublicKey(RawPublicKey $rawKey): PublicKey
    {
        $ctx = vscf_round5_import_public_key_php($this->ctx, $rawKey->getCtx());
        return FoundationImplementation::wrapPublicKey($ctx);
    }

    /**
    * Export public key to the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
    *
    * @param PublicKey $publicKey
    * @return RawPublicKey
    */
    public function exportPublicKey(PublicKey $publicKey): RawPublicKey
    {
        $ctx = vscf_round5_export_public_key_php($this->ctx, $publicKey->getCtx());
        return new RawPublicKey($ctx);
    }

    /**
    * Import private key from the raw binary format.
    *
    * Return private key that is adopted and optimized to be used
    * with this particular algorithm.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
    *
    * @param RawPrivateKey $rawKey
    * @return PrivateKey
    * @throws \Exception
    */
    public function importPrivateKey(RawPrivateKey $rawKey): PrivateKey
    {
        $ctx = vscf_round5_import_private_key_php($this->ctx, $rawKey->getCtx());
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    * Export private key in the raw binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
    *
    * @param PrivateKey $privateKey
    * @return RawPrivateKey
    */
    public function exportPrivateKey(PrivateKey $privateKey): RawPrivateKey
    {
        $ctx = vscf_round5_export_private_key_php($this->ctx, $privateKey->getCtx());
        return new RawPrivateKey($ctx);
    }

    /**
    * Return length in bytes required to hold encapsulated shared key.
    *
    * @param Key $key
    * @return int
    */
    public function kemSharedKeyLen(Key $key): int
    {
        return vscf_round5_kem_shared_key_len_php($this->ctx, $key->getCtx());
    }

    /**
    * Return length in bytes required to hold encapsulated key.
    *
    * @param PublicKey $publicKey
    * @return int
    */
    public function kemEncapsulatedKeyLen(PublicKey $publicKey): int
    {
        return vscf_round5_kem_encapsulated_key_len_php($this->ctx, $publicKey->getCtx());
    }

    /**
    * Generate a shared key and a key encapsulated message.
    *
    * @param PublicKey $publicKey
    * @return array
    * @throws \Exception
    */
    public function kemEncapsulate(PublicKey $publicKey): array // [shared_key, encapsulated_key]
    {
        return vscf_round5_kem_encapsulate_php($this->ctx, $publicKey->getCtx());
    }

    /**
    * Decapsulate the shared key.
    *
    * @param string $encapsulatedKey
    * @param PrivateKey $privateKey
    * @return string
    * @throws \Exception
    */
    public function kemDecapsulate(string $encapsulatedKey, PrivateKey $privateKey): string
    {
        return vscf_round5_kem_decapsulate_php($this->ctx, $encapsulatedKey, $privateKey->getCtx());
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
