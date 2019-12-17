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
* Implements public key cryptography over compound keys.
*
* Compound key contains 2 keys - one for encryption/decryption and
* one for signing/verifying.
*/
class CompoundKeyAlg implements Alg, KeyAlg, KeyCipher, KeySigner
{

    /**
    * @var
    */
    private $ctx;

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
        $this->ctx = is_null($ctx) ? vscf_compound_key_alg_new_php() : $ctx;
    }

    /**
    * Destroy underlying C context.
    * @return void
    */
    public function __destructor()
    {
        vscf_compound_key_alg_delete_php($this->ctx);
    }

    /**
    * @param Random $random
    * @return void
    */
    public function useRandom(Random $random): void
    {
        vscf_compound_key_alg_use_random_php($this->ctx, $random->getCtx());
    }

    /**
    * Setup predefined values to the uninitialized class dependencies.
    *
    * @return void
    * @throws \Exception
    */
    public function setupDefaults(): void
    {
        vscf_compound_key_alg_setup_defaults_php($this->ctx);
    }

    /**
    * Make compound private key from given.
    *
    * Note, this operation might be slow.
    *
    * @param PrivateKey $cipherKey
    * @param PrivateKey $signerKey
    * @return PrivateKey
    * @throws \Exception
    */
    public function makeKey(PrivateKey $cipherKey, PrivateKey $signerKey): PrivateKey
    {
        $ctx = vscf_compound_key_alg_make_key_php($this->ctx, $cipherKey->getCtx(), $signerKey->getCtx());
        return FoundationImplementation::wrapPrivateKey($ctx);
    }

    /**
    * Provide algorithm identificator.
    *
    * @return AlgId
    */
    public function algId(): AlgId
    {
        $enum = vscf_compound_key_alg_alg_id_php($this->ctx);
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
        $ctx = vscf_compound_key_alg_produce_alg_info_php($this->ctx);
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
        vscf_compound_key_alg_restore_alg_info_php($this->ctx, $algInfo->getCtx());
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
        $ctx = vscf_compound_key_alg_generate_ephemeral_key_php($this->ctx, $key->getCtx());
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
        $ctx = vscf_compound_key_alg_import_public_key_php($this->ctx, $rawKey->getCtx());
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
        $ctx = vscf_compound_key_alg_export_public_key_php($this->ctx, $publicKey->getCtx());
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
        $ctx = vscf_compound_key_alg_import_private_key_php($this->ctx, $rawKey->getCtx());
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
        $ctx = vscf_compound_key_alg_export_private_key_php($this->ctx, $privateKey->getCtx());
        return new RawPrivateKey($ctx);
    }

    /**
    * Check if algorithm can encrypt data with a given key.
    *
    * @param PublicKey $publicKey
    * @param int $dataLen
    * @return bool
    */
    public function canEncrypt(PublicKey $publicKey, int $dataLen): bool
    {
        return vscf_compound_key_alg_can_encrypt_php($this->ctx, $publicKey->getCtx(), $dataLen);
    }

    /**
    * Calculate required buffer length to hold the encrypted data.
    *
    * @param PublicKey $publicKey
    * @param int $dataLen
    * @return int
    */
    public function encryptedLen(PublicKey $publicKey, int $dataLen): int
    {
        return vscf_compound_key_alg_encrypted_len_php($this->ctx, $publicKey->getCtx(), $dataLen);
    }

    /**
    * Encrypt data with a given public key.
    *
    * @param PublicKey $publicKey
    * @param string $data
    * @return string
    * @throws \Exception
    */
    public function encrypt(PublicKey $publicKey, string $data): string
    {
        return vscf_compound_key_alg_encrypt_php($this->ctx, $publicKey->getCtx(), $data);
    }

    /**
    * Check if algorithm can decrypt data with a given key.
    * However, success result of decryption is not guaranteed.
    *
    * @param PrivateKey $privateKey
    * @param int $dataLen
    * @return bool
    */
    public function canDecrypt(PrivateKey $privateKey, int $dataLen): bool
    {
        return vscf_compound_key_alg_can_decrypt_php($this->ctx, $privateKey->getCtx(), $dataLen);
    }

    /**
    * Calculate required buffer length to hold the decrypted data.
    *
    * @param PrivateKey $privateKey
    * @param int $dataLen
    * @return int
    */
    public function decryptedLen(PrivateKey $privateKey, int $dataLen): int
    {
        return vscf_compound_key_alg_decrypted_len_php($this->ctx, $privateKey->getCtx(), $dataLen);
    }

    /**
    * Decrypt given data.
    *
    * @param PrivateKey $privateKey
    * @param string $data
    * @return string
    * @throws \Exception
    */
    public function decrypt(PrivateKey $privateKey, string $data): string
    {
        return vscf_compound_key_alg_decrypt_php($this->ctx, $privateKey->getCtx(), $data);
    }

    /**
    * Check if algorithm can sign data digest with a given key.
    *
    * @param PrivateKey $privateKey
    * @return bool
    */
    public function canSign(PrivateKey $privateKey): bool
    {
        return vscf_compound_key_alg_can_sign_php($this->ctx, $privateKey->getCtx());
    }

    /**
    * Return length in bytes required to hold signature.
    * Return zero if a given private key can not produce signatures.
    *
    * @param PrivateKey $privateKey
    * @return int
    */
    public function signatureLen(PrivateKey $privateKey): int
    {
        return vscf_compound_key_alg_signature_len_php($this->ctx, $privateKey->getCtx());
    }

    /**
    * Sign data digest with a given private key.
    *
    * @param PrivateKey $privateKey
    * @param AlgId $hashId
    * @param string $digest
    * @return string
    * @throws \Exception
    */
    public function signHash(PrivateKey $privateKey, AlgId $hashId, string $digest): string
    {
        return vscf_compound_key_alg_sign_hash_php($this->ctx, $privateKey->getCtx(), $hashId->getValue(), $digest);
    }

    /**
    * Check if algorithm can verify data digest with a given key.
    *
    * @param PublicKey $publicKey
    * @return bool
    */
    public function canVerify(PublicKey $publicKey): bool
    {
        return vscf_compound_key_alg_can_verify_php($this->ctx, $publicKey->getCtx());
    }

    /**
    * Verify data digest with a given public key and signature.
    *
    * @param PublicKey $publicKey
    * @param AlgId $hashId
    * @param string $digest
    * @param string $signature
    * @return bool
    */
    public function verifyHash(PublicKey $publicKey, AlgId $hashId, string $digest, string $signature): bool
    {
        return vscf_compound_key_alg_verify_hash_php($this->ctx, $publicKey->getCtx(), $hashId->getValue(), $digest, $signature);
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
