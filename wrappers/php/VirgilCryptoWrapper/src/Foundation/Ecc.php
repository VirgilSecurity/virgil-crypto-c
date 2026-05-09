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

class Ecc implements KeyAlg, KeyCipher, KeySigner, ComputeSharedKey, Kem
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
        $this->ctx = is_null($ctx) ? vscf_ecc_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_ecc_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$random
    * @return void
    */
    public function useRandom(Random $$random): void
    {
        vscf_ecc_use_random_php($this->ctx, $$random);
    }

    /**
    *
    * @param Ecies $$ecies
    * @return void
    */
    public function useEcies(Ecies $$ecies): void
    {
        vscf_ecc_use_ecies_php($this->ctx, $$ecies);
    }

    /**
    *
    * @param Key $$key
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateEphemeralKey(Key $$key): PrivateKey
    {
        $ctx = vscf_ecc_generate_ephemeral_key_php($this->ctx, $$key->getCtx());
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
        $ctx = vscf_ecc_import_public_key_php($this->ctx, $$rawKey);
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
        $ctx = vscf_ecc_export_public_key_php($this->ctx, $$publicKey->getCtx());
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
        $ctx = vscf_ecc_import_private_key_php($this->ctx, $$rawKey);
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
        $ctx = vscf_ecc_export_private_key_php($this->ctx, $$privateKey->getCtx());
        return new RawPrivateKey($ctx);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @param int $$dataLen
    * @return bool
    */
    public function canEncrypt(PublicKey $$publicKey, int $$dataLen): bool
    {
        return vscf_ecc_can_encrypt_php($this->ctx, $$publicKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @param int $$dataLen
    * @return int
    */
    public function encryptedLen(PublicKey $$publicKey, int $$dataLen): int
    {
        return vscf_ecc_encrypted_len_php($this->ctx, $$publicKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function encrypt(PublicKey $$publicKey, string $$data): string
    {
        return vscf_ecc_encrypt_php($this->ctx, $$publicKey->getCtx(), $$data);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @param int $$dataLen
    * @return bool
    */
    public function canDecrypt(PrivateKey $$privateKey, int $$dataLen): bool
    {
        return vscf_ecc_can_decrypt_php($this->ctx, $$privateKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @param int $$dataLen
    * @return int
    */
    public function decryptedLen(PrivateKey $$privateKey, int $$dataLen): int
    {
        return vscf_ecc_decrypted_len_php($this->ctx, $$privateKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @param string $$data
    * @return string
    * @throws \Exception
    */
    public function decrypt(PrivateKey $$privateKey, string $$data): string
    {
        return vscf_ecc_decrypt_php($this->ctx, $$privateKey->getCtx(), $$data);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return bool
    */
    public function canSign(PrivateKey $$privateKey): bool
    {
        return vscf_ecc_can_sign_php($this->ctx, $$privateKey->getCtx());
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return int
    */
    public function signatureLen(PrivateKey $$privateKey): int
    {
        return vscf_ecc_signature_len_php($this->ctx, $$privateKey->getCtx());
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
        return vscf_ecc_sign_hash_php($this->ctx, $$privateKey->getCtx(), $$hashId, $$digest);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return bool
    */
    public function canVerify(PublicKey $$publicKey): bool
    {
        return vscf_ecc_can_verify_php($this->ctx, $$publicKey->getCtx());
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
        return vscf_ecc_verify_hash_php($this->ctx, $$publicKey->getCtx(), $$hashId, $$digest, $$signature);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @param PrivateKey $$privateKey
    * @return string
    * @throws \Exception
    */
    public function computeSharedKey(PublicKey $$publicKey, PrivateKey $$privateKey): string
    {
        return vscf_ecc_compute_shared_key_php($this->ctx, $$publicKey->getCtx(), $$privateKey->getCtx());
    }

    /**
    *
    * @param Key $$key
    * @return int
    */
    public function sharedKeyLen(Key $$key): int
    {
        return vscf_ecc_shared_key_len_php($this->ctx, $$key->getCtx());
    }

    /**
    *
    * @param Key $$key
    * @return int
    */
    public function kemSharedKeyLen(Key $$key): int
    {
        return vscf_ecc_kem_shared_key_len_php($this->ctx, $$key->getCtx());
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return int
    */
    public function kemEncapsulatedKeyLen(PublicKey $$publicKey): int
    {
        return vscf_ecc_kem_encapsulated_key_len_php($this->ctx, $$publicKey->getCtx());
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return array
    * @throws \Exception
    */
    public function kemEncapsulate(PublicKey $$publicKey)
    {
        return vscf_ecc_kem_encapsulate_php($this->ctx, $$publicKey->getCtx());
    }

    /**
    *
    * @param string $$encapsulatedKey
    * @param PrivateKey $$privateKey
    * @return string
    * @throws \Exception
    */
    public function kemDecapsulate(string $$encapsulatedKey, PrivateKey $$privateKey): string
    {
        return vscf_ecc_kem_decapsulate_php($this->ctx, $$encapsulatedKey, $$privateKey->getCtx());
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_ecc_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @param MbedtlsMpi $$r
    * @param MbedtlsMpi $$s
    * @return string
    */
    public static function writeSignature(MbedtlsMpi $$r, MbedtlsMpi $$s): string
    {
        return vscf_ecc_write_signature_php($$r, $$s);
    }

    /**
    *
    * @param string $$signature
    * @param MbedtlsMpi $$r
    * @param MbedtlsMpi $$s
    * @return void
    * @throws \Exception
    */
    public static function readSignature(string $$signature, MbedtlsMpi $$r, MbedtlsMpi $$s): void
    {
        vscf_ecc_read_signature_php($$signature, $$r, $$s);
    }

    /**
    *
    * @param AlgId $$algId
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateKey(AlgId $$algId): PrivateKey
    {
        $ctx = vscf_ecc_generate_key_php($this->ctx, $$algId);
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param Key $$key
    * @return AlgInfo
    */
    public function produceAlgInfoForKey(Key $$key): AlgInfo
    {
        $ctx = vscf_ecc_produce_alg_info_for_key_php($this->ctx, $$key->getCtx());
        return FoundationImplementation::wrapAlgInfo($ctx);
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
