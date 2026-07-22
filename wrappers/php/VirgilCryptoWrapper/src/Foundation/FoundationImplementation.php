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

class FoundationImplementation
{

    const AES128_KW = 1;
    const AES256_CBC = 2;
    const AES256_GCM = 3;
    const AES256_KW = 4;
    const ALG_INFO_DER_DESERIALIZER = 5;
    const ALG_INFO_DER_SERIALIZER = 6;
    const ASN1RD = 7;
    const ASN1WR = 8;
    const CHUNK_CIPHER = 9;
    const CHUNKED_ALG_INFO = 10;
    const CIPHER_ALG_INFO = 11;
    const COMPOUND_KEY_ALG = 12;
    const COMPOUND_KEY_ALG_INFO = 13;
    const COMPOUND_PRIVATE_KEY = 14;
    const COMPOUND_PUBLIC_KEY = 15;
    const CTR_DRBG = 16;
    const CURVE25519 = 17;
    const ECC = 18;
    const ECC_ALG_INFO = 19;
    const ECC_PRIVATE_KEY = 20;
    const ECC_PUBLIC_KEY = 21;
    const ED25519 = 22;
    const ENTROPY_ACCUMULATOR = 23;
    const FAKE_RANDOM = 24;
    const FALCON = 25;
    const HASH_BASED_ALG_INFO = 26;
    const HKDF = 27;
    const HMAC = 28;
    const HYBRID_KEY_ALG = 29;
    const HYBRID_KEY_ALG_INFO = 30;
    const HYBRID_PRIVATE_KEY = 31;
    const HYBRID_PUBLIC_KEY = 32;
    const KDF1 = 33;
    const KDF2 = 34;
    const KEY_ASN1_DESERIALIZER = 35;
    const KEY_ASN1_SERIALIZER = 36;
    const KEY_MATERIAL_RNG = 37;
    const MESSAGE_INFO_DER_SERIALIZER = 38;
    const ML_DSA = 39;
    const ML_KEM = 40;
    const PBE_ALG_INFO = 41;
    const PKCS5_PBES2 = 42;
    const PKCS5_PBKDF2 = 43;
    const PKCS8_SERIALIZER = 44;
    const RANDOM_PADDING = 45;
    const RAW_PRIVATE_KEY = 46;
    const RAW_PUBLIC_KEY = 47;
    const RSA = 48;
    const RSA_PRIVATE_KEY = 49;
    const RSA_PUBLIC_KEY = 50;
    const SALTED_KDF_ALG_INFO = 51;
    const SEC1_SERIALIZER = 52;
    const SEED_ENTROPY_SOURCE = 53;
    const SHA224 = 54;
    const SHA256 = 55;
    const SHA384 = 56;
    const SHA512 = 57;
    const SIMPLE_ALG_INFO = 58;

    /**
    *
    * @param  $$ctx
    * @return Cipher
    */
    public static function wrapCipher($$ctx): Cipher
    {
        return vscf_foundation_implementation_wrap_cipher_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return AuthEncrypt
    */
    public static function wrapAuthEncrypt($$ctx): AuthEncrypt
    {
        return vscf_foundation_implementation_wrap_auth_encrypt_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return AuthDecrypt
    */
    public static function wrapAuthDecrypt($$ctx): AuthDecrypt
    {
        return vscf_foundation_implementation_wrap_auth_decrypt_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return CipherAuth
    */
    public static function wrapCipherAuth($$ctx): CipherAuth
    {
        return vscf_foundation_implementation_wrap_cipher_auth_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return CipherAuthInfo
    */
    public static function wrapCipherAuthInfo($$ctx): CipherAuthInfo
    {
        return vscf_foundation_implementation_wrap_cipher_auth_info_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return CipherInfo
    */
    public static function wrapCipherInfo($$ctx): CipherInfo
    {
        return vscf_foundation_implementation_wrap_cipher_info_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Decrypt
    */
    public static function wrapDecrypt($$ctx): Decrypt
    {
        return vscf_foundation_implementation_wrap_decrypt_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Encrypt
    */
    public static function wrapEncrypt($$ctx): Encrypt
    {
        return vscf_foundation_implementation_wrap_encrypt_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return SaltedKdf
    */
    public static function wrapSaltedKdf($$ctx): SaltedKdf
    {
        return vscf_foundation_implementation_wrap_salted_kdf_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Hash
    */
    public static function wrapHash($$ctx): Hash
    {
        return vscf_foundation_implementation_wrap_hash_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Mac
    */
    public static function wrapMac($$ctx): Mac
    {
        return vscf_foundation_implementation_wrap_mac_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Kdf
    */
    public static function wrapKdf($$ctx): Kdf
    {
        return vscf_foundation_implementation_wrap_kdf_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Random
    */
    public static function wrapRandom($$ctx): Random
    {
        return vscf_foundation_implementation_wrap_random_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return EntropySource
    */
    public static function wrapEntropySource($$ctx): EntropySource
    {
        return vscf_foundation_implementation_wrap_entropy_source_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Key
    */
    public static function wrapKey($$ctx): Key
    {
        return vscf_foundation_implementation_wrap_key_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return KeyAlg
    */
    public static function wrapKeyAlg($$ctx): KeyAlg
    {
        return vscf_foundation_implementation_wrap_key_alg_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return PublicKey
    */
    public static function wrapPublicKey($$ctx): PublicKey
    {
        return vscf_foundation_implementation_wrap_public_key_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return PrivateKey
    */
    public static function wrapPrivateKey($$ctx): PrivateKey
    {
        return vscf_foundation_implementation_wrap_private_key_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return KeyCipher
    */
    public static function wrapKeyCipher($$ctx): KeyCipher
    {
        return vscf_foundation_implementation_wrap_key_cipher_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return KeySigner
    */
    public static function wrapKeySigner($$ctx): KeySigner
    {
        return vscf_foundation_implementation_wrap_key_signer_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return ComputeSharedKey
    */
    public static function wrapComputeSharedKey($$ctx): ComputeSharedKey
    {
        return vscf_foundation_implementation_wrap_compute_shared_key_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return KeySerializer
    */
    public static function wrapKeySerializer($$ctx): KeySerializer
    {
        return vscf_foundation_implementation_wrap_key_serializer_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return KeyDeserializer
    */
    public static function wrapKeyDeserializer($$ctx): KeyDeserializer
    {
        return vscf_foundation_implementation_wrap_key_deserializer_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Asn1Reader
    */
    public static function wrapAsn1Reader($$ctx): Asn1Reader
    {
        return vscf_foundation_implementation_wrap_asn1_reader_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Asn1Writer
    */
    public static function wrapAsn1Writer($$ctx): Asn1Writer
    {
        return vscf_foundation_implementation_wrap_asn1_writer_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Alg
    */
    public static function wrapAlg($$ctx): Alg
    {
        return vscf_foundation_implementation_wrap_alg_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return AlgInfo
    */
    public static function wrapAlgInfo($$ctx): AlgInfo
    {
        return vscf_foundation_implementation_wrap_alg_info_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return AlgInfoSerializer
    */
    public static function wrapAlgInfoSerializer($$ctx): AlgInfoSerializer
    {
        return vscf_foundation_implementation_wrap_alg_info_serializer_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return AlgInfoDeserializer
    */
    public static function wrapAlgInfoDeserializer($$ctx): AlgInfoDeserializer
    {
        return vscf_foundation_implementation_wrap_alg_info_deserializer_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return MessageInfoSerializer
    */
    public static function wrapMessageInfoSerializer($$ctx): MessageInfoSerializer
    {
        return vscf_foundation_implementation_wrap_message_info_serializer_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return MessageInfoFooterSerializer
    */
    public static function wrapMessageInfoFooterSerializer($$ctx): MessageInfoFooterSerializer
    {
        return vscf_foundation_implementation_wrap_message_info_footer_serializer_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Padding
    */
    public static function wrapPadding($$ctx): Padding
    {
        return vscf_foundation_implementation_wrap_padding_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return Kem
    */
    public static function wrapKem($$ctx): Kem
    {
        return vscf_foundation_implementation_wrap_kem_php($$ctx);
    }

    /**
    *
    * @param  $$ctx
    * @return KeyWrap
    */
    public static function wrapKeyWrap($$ctx): KeyWrap
    {
        return vscf_foundation_implementation_wrap_key_wrap_php($$ctx);
    }

}
