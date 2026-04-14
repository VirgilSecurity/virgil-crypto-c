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

class HybridKeyAlg implements KeyAlg, KeyCipher, KeySigner
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
        $this->ctx = is_null($ctx) ? vscf_hybrid_key_alg_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_hybrid_key_alg_delete_php($this->ctx);
    }

    /**
    *
    * @param Random $$random
    * @return void
    */
    public function useRandom(Random $$random): void
    {
        vscf_hybrid_key_alg_use_random_php($this->ctx, $$random);
    }

    /**
    *
    * @param CipherAuth $$cipher
    * @return void
    */
    public function useCipher(CipherAuth $$cipher): void
    {
        vscf_hybrid_key_alg_use_cipher_php($this->ctx, $$cipher);
    }

    /**
    *
    * @param Hash $$hash
    * @return void
    */
    public function useHash(Hash $$hash): void
    {
        vscf_hybrid_key_alg_use_hash_php($this->ctx, $$hash);
    }

    /**
    *
    * @param Key $$key
    * @return PrivateKey
    * @throws \Exception
    */
    public function generateEphemeralKey(Key $$key): PrivateKey
    {
        $ctx = vscf_hybrid_key_alg_generate_ephemeral_key_php($this->ctx, $$key->getCtx());
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
        $ctx = vscf_hybrid_key_alg_import_public_key_php($this->ctx, $$rawKey);
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
        $ctx = vscf_hybrid_key_alg_export_public_key_php($this->ctx, $$publicKey->getCtx());
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
        $ctx = vscf_hybrid_key_alg_import_private_key_php($this->ctx, $$rawKey);
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
        $ctx = vscf_hybrid_key_alg_export_private_key_php($this->ctx, $$privateKey->getCtx());
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
        return vscf_hybrid_key_alg_can_encrypt_php($this->ctx, $$publicKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @param int $$dataLen
    * @return int
    */
    public function encryptedLen(PublicKey $$publicKey, int $$dataLen): int
    {
        return vscf_hybrid_key_alg_encrypted_len_php($this->ctx, $$publicKey->getCtx(), $$dataLen);
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
        return vscf_hybrid_key_alg_encrypt_php($this->ctx, $$publicKey->getCtx(), $$data);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @param int $$dataLen
    * @return bool
    */
    public function canDecrypt(PrivateKey $$privateKey, int $$dataLen): bool
    {
        return vscf_hybrid_key_alg_can_decrypt_php($this->ctx, $$privateKey->getCtx(), $$dataLen);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @param int $$dataLen
    * @return int
    */
    public function decryptedLen(PrivateKey $$privateKey, int $$dataLen): int
    {
        return vscf_hybrid_key_alg_decrypted_len_php($this->ctx, $$privateKey->getCtx(), $$dataLen);
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
        return vscf_hybrid_key_alg_decrypt_php($this->ctx, $$privateKey->getCtx(), $$data);
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return bool
    */
    public function canSign(PrivateKey $$privateKey): bool
    {
        return vscf_hybrid_key_alg_can_sign_php($this->ctx, $$privateKey->getCtx());
    }

    /**
    *
    * @param PrivateKey $$privateKey
    * @return int
    */
    public function signatureLen(PrivateKey $$privateKey): int
    {
        return vscf_hybrid_key_alg_signature_len_php($this->ctx, $$privateKey->getCtx());
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
        return vscf_hybrid_key_alg_sign_hash_php($this->ctx, $$privateKey->getCtx(), $$hashId, $$digest);
    }

    /**
    *
    * @param PublicKey $$publicKey
    * @return bool
    */
    public function canVerify(PublicKey $$publicKey): bool
    {
        return vscf_hybrid_key_alg_can_verify_php($this->ctx, $$publicKey->getCtx());
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
        return vscf_hybrid_key_alg_verify_hash_php($this->ctx, $$publicKey->getCtx(), $$hashId, $$digest, $$signature);
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_hybrid_key_alg_setup_defaults_php($this->ctx);
    }

    /**
    *
    * @param PrivateKey $$firstKey
    * @param PrivateKey $$secondKey
    * @return PrivateKey
    * @throws \Exception
    */
    public function makeKey(PrivateKey $$firstKey, PrivateKey $$secondKey): PrivateKey
    {
        $ctx = vscf_hybrid_key_alg_make_key_php($this->ctx, $$firstKey->getCtx(), $$secondKey->getCtx());
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    *
    * @param Cipher $$cipher
    * @param Hash $$hash
    * @param string $$sharedKey
    * @return void
    */
    public static function configCipher(Cipher $$cipher, Hash $$hash, string $$sharedKey): void
    {
        vscf_hybrid_key_alg_config_cipher_php($$cipher->getCtx(), $$hash->getCtx(), $$sharedKey);
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
