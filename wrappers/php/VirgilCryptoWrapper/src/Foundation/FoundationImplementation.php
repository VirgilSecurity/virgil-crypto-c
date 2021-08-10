<?php
/**
* Copyright (C) 2015-2021 Virgil Security, Inc.
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

class FoundationImplementation
{

    const AES256_CBC = 1;
    const AES256_GCM = 2;
    const ALG_INFO_DER_DESERIALIZER = 3;
    const ALG_INFO_DER_SERIALIZER = 4;
    const ASN1RD = 5;
    const ASN1WR = 6;
    const CIPHER_ALG_INFO = 7;
    const COMPOUND_KEY_ALG = 8;
    const COMPOUND_KEY_ALG_INFO = 9;
    const COMPOUND_PRIVATE_KEY = 10;
    const COMPOUND_PUBLIC_KEY = 11;
    const CTR_DRBG = 12;
    const CURVE25519 = 13;
    const ECC = 14;
    const ECC_ALG_INFO = 15;
    const ECC_PRIVATE_KEY = 16;
    const ECC_PUBLIC_KEY = 17;
    const ED25519 = 18;
    const ENTROPY_ACCUMULATOR = 19;
    const FAKE_RANDOM = 20;
    const FALCON = 21;
    const HASH_BASED_ALG_INFO = 22;
    const HKDF = 23;
    const HMAC = 24;
    const HYBRID_KEY_ALG = 25;
    const HYBRID_KEY_ALG_INFO = 26;
    const HYBRID_PRIVATE_KEY = 27;
    const HYBRID_PUBLIC_KEY = 28;
    const KDF1 = 29;
    const KDF2 = 30;
    const KEY_ASN1_DESERIALIZER = 31;
    const KEY_ASN1_SERIALIZER = 32;
    const KEY_MATERIAL_RNG = 33;
    const MESSAGE_INFO_DER_SERIALIZER = 34;
    const PBE_ALG_INFO = 35;
    const PKCS5_PBES2 = 36;
    const PKCS5_PBKDF2 = 37;
    const PKCS8_SERIALIZER = 38;
    const RANDOM_PADDING = 39;
    const RAW_PRIVATE_KEY = 40;
    const RAW_PUBLIC_KEY = 41;
    const ROUND5 = 42;
    const RSA = 43;
    const RSA_PRIVATE_KEY = 44;
    const RSA_PUBLIC_KEY = 45;
    const SALTED_KDF_ALG_INFO = 46;
    const SEC1_SERIALIZER = 47;
    const SEED_ENTROPY_SOURCE = 48;
    const SHA224 = 49;
    const SHA256 = 50;
    const SHA384 = 51;
    const SHA512 = 52;
    const SIMPLE_ALG_INFO = 53;

    /**
    * Wrap C implementation object to the PHP object that implements protocol Cipher.
    *
    * @param $ctx
    * @return Cipher
    * @throws \Exception
    */
    public static function wrapCipher($ctx): Cipher
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::AES256_GCM:
                return (new Aes256Gcm($ctx));
                break;
            case self::AES256_CBC:
                return (new Aes256Cbc($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol AuthEncrypt.
    *
    * @param $ctx
    * @return AuthEncrypt
    * @throws \Exception
    */
    public static function wrapAuthEncrypt($ctx): AuthEncrypt
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::AES256_GCM:
                return (new Aes256Gcm($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol AuthDecrypt.
    *
    * @param $ctx
    * @return AuthDecrypt
    * @throws \Exception
    */
    public static function wrapAuthDecrypt($ctx): AuthDecrypt
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::AES256_GCM:
                return (new Aes256Gcm($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol CipherAuth.
    *
    * @param $ctx
    * @return CipherAuth
    * @throws \Exception
    */
    public static function wrapCipherAuth($ctx): CipherAuth
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::AES256_GCM:
                return (new Aes256Gcm($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol CipherAuthInfo.
    *
    * @param $ctx
    * @return CipherAuthInfo
    * @throws \Exception
    */
    public static function wrapCipherAuthInfo($ctx): CipherAuthInfo
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::AES256_GCM:
                return (new Aes256Gcm($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol CipherInfo.
    *
    * @param $ctx
    * @return CipherInfo
    * @throws \Exception
    */
    public static function wrapCipherInfo($ctx): CipherInfo
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::AES256_GCM:
                return (new Aes256Gcm($ctx));
                break;
            case self::AES256_CBC:
                return (new Aes256Cbc($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Decrypt.
    *
    * @param $ctx
    * @return Decrypt
    * @throws \Exception
    */
    public static function wrapDecrypt($ctx): Decrypt
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::AES256_GCM:
                return (new Aes256Gcm($ctx));
                break;
            case self::AES256_CBC:
                return (new Aes256Cbc($ctx));
                break;
            case self::PKCS5_PBES2:
                return (new Pkcs5Pbes2($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Encrypt.
    *
    * @param $ctx
    * @return Encrypt
    * @throws \Exception
    */
    public static function wrapEncrypt($ctx): Encrypt
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::AES256_GCM:
                return (new Aes256Gcm($ctx));
                break;
            case self::AES256_CBC:
                return (new Aes256Cbc($ctx));
                break;
            case self::PKCS5_PBES2:
                return (new Pkcs5Pbes2($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol SaltedKdf.
    *
    * @param $ctx
    * @return SaltedKdf
    * @throws \Exception
    */
    public static function wrapSaltedKdf($ctx): SaltedKdf
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::HKDF:
                return (new Hkdf($ctx));
                break;
            case self::PKCS5_PBKDF2:
                return (new Pkcs5Pbkdf2($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Hash.
    *
    * @param $ctx
    * @return Hash
    * @throws \Exception
    */
    public static function wrapHash($ctx): Hash
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::SHA224:
                return (new Sha224($ctx));
                break;
            case self::SHA256:
                return (new Sha256($ctx));
                break;
            case self::SHA384:
                return (new Sha384($ctx));
                break;
            case self::SHA512:
                return (new Sha512($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Mac.
    *
    * @param $ctx
    * @return Mac
    * @throws \Exception
    */
    public static function wrapMac($ctx): Mac
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::HMAC:
                return (new Hmac($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Kdf.
    *
    * @param $ctx
    * @return Kdf
    * @throws \Exception
    */
    public static function wrapKdf($ctx): Kdf
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::HKDF:
                return (new Hkdf($ctx));
                break;
            case self::KDF1:
                return (new Kdf1($ctx));
                break;
            case self::KDF2:
                return (new Kdf2($ctx));
                break;
            case self::PKCS5_PBKDF2:
                return (new Pkcs5Pbkdf2($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Random.
    *
    * @param $ctx
    * @return Random
    * @throws \Exception
    */
    public static function wrapRandom($ctx): Random
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::CTR_DRBG:
                return (new CtrDrbg($ctx));
                break;
            case self::FAKE_RANDOM:
                return (new FakeRandom($ctx));
                break;
            case self::KEY_MATERIAL_RNG:
                return (new KeyMaterialRng($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol EntropySource.
    *
    * @param $ctx
    * @return EntropySource
    * @throws \Exception
    */
    public static function wrapEntropySource($ctx): EntropySource
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::ENTROPY_ACCUMULATOR:
                return (new EntropyAccumulator($ctx));
                break;
            case self::FAKE_RANDOM:
                return (new FakeRandom($ctx));
                break;
            case self::SEED_ENTROPY_SOURCE:
                return (new SeedEntropySource($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Key.
    *
    * @param $ctx
    * @return Key
    * @throws \Exception
    */
    public static function wrapKey($ctx): Key
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::RSA_PUBLIC_KEY:
                return (new RsaPublicKey($ctx));
                break;
            case self::RSA_PRIVATE_KEY:
                return (new RsaPrivateKey($ctx));
                break;
            case self::ECC_PUBLIC_KEY:
                return (new EccPublicKey($ctx));
                break;
            case self::ECC_PRIVATE_KEY:
                return (new EccPrivateKey($ctx));
                break;
            case self::RAW_PUBLIC_KEY:
                return (new RawPublicKey($ctx));
                break;
            case self::RAW_PRIVATE_KEY:
                return (new RawPrivateKey($ctx));
                break;
            case self::COMPOUND_PUBLIC_KEY:
                return (new CompoundPublicKey($ctx));
                break;
            case self::COMPOUND_PRIVATE_KEY:
                return (new CompoundPrivateKey($ctx));
                break;
            case self::HYBRID_PUBLIC_KEY:
                return (new HybridPublicKey($ctx));
                break;
            case self::HYBRID_PRIVATE_KEY:
                return (new HybridPrivateKey($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol KeyAlg.
    *
    * @param $ctx
    * @return KeyAlg
    * @throws \Exception
    */
    public static function wrapKeyAlg($ctx): KeyAlg
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::RSA:
                return (new Rsa($ctx));
                break;
            case self::ECC:
                return (new Ecc($ctx));
                break;
            case self::ED25519:
                return (new Ed25519($ctx));
                break;
            case self::CURVE25519:
                return (new Curve25519($ctx));
                break;
            case self::FALCON:
                return (new Falcon($ctx));
                break;
            case self::ROUND5:
                return (new Round5($ctx));
                break;
            case self::COMPOUND_KEY_ALG:
                return (new CompoundKeyAlg($ctx));
                break;
            case self::HYBRID_KEY_ALG:
                return (new HybridKeyAlg($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol PublicKey.
    *
    * @param $ctx
    * @return PublicKey
    * @throws \Exception
    */
    public static function wrapPublicKey($ctx): PublicKey
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::RSA_PUBLIC_KEY:
                return (new RsaPublicKey($ctx));
                break;
            case self::ECC_PUBLIC_KEY:
                return (new EccPublicKey($ctx));
                break;
            case self::RAW_PUBLIC_KEY:
                return (new RawPublicKey($ctx));
                break;
            case self::COMPOUND_PUBLIC_KEY:
                return (new CompoundPublicKey($ctx));
                break;
            case self::HYBRID_PUBLIC_KEY:
                return (new HybridPublicKey($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol PrivateKey.
    *
    * @param $ctx
    * @return PrivateKey
    * @throws \Exception
    */
    public static function wrapPrivateKey($ctx): PrivateKey
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::RSA_PRIVATE_KEY:
                return (new RsaPrivateKey($ctx));
                break;
            case self::ECC_PRIVATE_KEY:
                return (new EccPrivateKey($ctx));
                break;
            case self::RAW_PRIVATE_KEY:
                return (new RawPrivateKey($ctx));
                break;
            case self::COMPOUND_PRIVATE_KEY:
                return (new CompoundPrivateKey($ctx));
                break;
            case self::HYBRID_PRIVATE_KEY:
                return (new HybridPrivateKey($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol KeyCipher.
    *
    * @param $ctx
    * @return KeyCipher
    * @throws \Exception
    */
    public static function wrapKeyCipher($ctx): KeyCipher
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::RSA:
                return (new Rsa($ctx));
                break;
            case self::ECC:
                return (new Ecc($ctx));
                break;
            case self::ED25519:
                return (new Ed25519($ctx));
                break;
            case self::CURVE25519:
                return (new Curve25519($ctx));
                break;
            case self::COMPOUND_KEY_ALG:
                return (new CompoundKeyAlg($ctx));
                break;
            case self::HYBRID_KEY_ALG:
                return (new HybridKeyAlg($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol KeySigner.
    *
    * @param $ctx
    * @return KeySigner
    * @throws \Exception
    */
    public static function wrapKeySigner($ctx): KeySigner
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::RSA:
                return (new Rsa($ctx));
                break;
            case self::ECC:
                return (new Ecc($ctx));
                break;
            case self::ED25519:
                return (new Ed25519($ctx));
                break;
            case self::FALCON:
                return (new Falcon($ctx));
                break;
            case self::COMPOUND_KEY_ALG:
                return (new CompoundKeyAlg($ctx));
                break;
            case self::HYBRID_KEY_ALG:
                return (new HybridKeyAlg($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol ComputeSharedKey.
    *
    * @param $ctx
    * @return ComputeSharedKey
    * @throws \Exception
    */
    public static function wrapComputeSharedKey($ctx): ComputeSharedKey
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::ECC:
                return (new Ecc($ctx));
                break;
            case self::ED25519:
                return (new Ed25519($ctx));
                break;
            case self::CURVE25519:
                return (new Curve25519($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol KeySerializer.
    *
    * @param $ctx
    * @return KeySerializer
    * @throws \Exception
    */
    public static function wrapKeySerializer($ctx): KeySerializer
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::PKCS8_SERIALIZER:
                return (new Pkcs8Serializer($ctx));
                break;
            case self::SEC1_SERIALIZER:
                return (new Sec1Serializer($ctx));
                break;
            case self::KEY_ASN1_SERIALIZER:
                return (new KeyAsn1Serializer($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol KeyDeserializer.
    *
    * @param $ctx
    * @return KeyDeserializer
    * @throws \Exception
    */
    public static function wrapKeyDeserializer($ctx): KeyDeserializer
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::KEY_ASN1_DESERIALIZER:
                return (new KeyAsn1Deserializer($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Asn1Reader.
    *
    * @param $ctx
    * @return Asn1Reader
    * @throws \Exception
    */
    public static function wrapAsn1Reader($ctx): Asn1Reader
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::ASN1RD:
                return (new Asn1rd($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Asn1Writer.
    *
    * @param $ctx
    * @return Asn1Writer
    * @throws \Exception
    */
    public static function wrapAsn1Writer($ctx): Asn1Writer
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::ASN1WR:
                return (new Asn1wr($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Alg.
    *
    * @param $ctx
    * @return Alg
    * @throws \Exception
    */
    public static function wrapAlg($ctx): Alg
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::SHA224:
                return (new Sha224($ctx));
                break;
            case self::SHA256:
                return (new Sha256($ctx));
                break;
            case self::SHA384:
                return (new Sha384($ctx));
                break;
            case self::SHA512:
                return (new Sha512($ctx));
                break;
            case self::AES256_GCM:
                return (new Aes256Gcm($ctx));
                break;
            case self::AES256_CBC:
                return (new Aes256Cbc($ctx));
                break;
            case self::HMAC:
                return (new Hmac($ctx));
                break;
            case self::HKDF:
                return (new Hkdf($ctx));
                break;
            case self::KDF1:
                return (new Kdf1($ctx));
                break;
            case self::KDF2:
                return (new Kdf2($ctx));
                break;
            case self::PKCS5_PBKDF2:
                return (new Pkcs5Pbkdf2($ctx));
                break;
            case self::PKCS5_PBES2:
                return (new Pkcs5Pbes2($ctx));
                break;
            case self::FALCON:
                return (new Falcon($ctx));
                break;
            case self::COMPOUND_KEY_ALG:
                return (new CompoundKeyAlg($ctx));
                break;
            case self::RANDOM_PADDING:
                return (new RandomPadding($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol AlgInfo.
    *
    * @param $ctx
    * @return AlgInfo
    * @throws \Exception
    */
    public static function wrapAlgInfo($ctx): AlgInfo
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::COMPOUND_KEY_ALG_INFO:
                return (new CompoundKeyAlgInfo($ctx));
                break;
            case self::HYBRID_KEY_ALG_INFO:
                return (new HybridKeyAlgInfo($ctx));
                break;
            case self::SIMPLE_ALG_INFO:
                return (new SimpleAlgInfo($ctx));
                break;
            case self::HASH_BASED_ALG_INFO:
                return (new HashBasedAlgInfo($ctx));
                break;
            case self::CIPHER_ALG_INFO:
                return (new CipherAlgInfo($ctx));
                break;
            case self::SALTED_KDF_ALG_INFO:
                return (new SaltedKdfAlgInfo($ctx));
                break;
            case self::PBE_ALG_INFO:
                return (new PbeAlgInfo($ctx));
                break;
            case self::ECC_ALG_INFO:
                return (new EccAlgInfo($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol AlgInfoSerializer.
    *
    * @param $ctx
    * @return AlgInfoSerializer
    * @throws \Exception
    */
    public static function wrapAlgInfoSerializer($ctx): AlgInfoSerializer
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::ALG_INFO_DER_SERIALIZER:
                return (new AlgInfoDerSerializer($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol AlgInfoDeserializer.
    *
    * @param $ctx
    * @return AlgInfoDeserializer
    * @throws \Exception
    */
    public static function wrapAlgInfoDeserializer($ctx): AlgInfoDeserializer
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::ALG_INFO_DER_DESERIALIZER:
                return (new AlgInfoDerDeserializer($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol MessageInfoSerializer.
    *
    * @param $ctx
    * @return MessageInfoSerializer
    * @throws \Exception
    */
    public static function wrapMessageInfoSerializer($ctx): MessageInfoSerializer
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::MESSAGE_INFO_DER_SERIALIZER:
                return (new MessageInfoDerSerializer($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol MessageInfoFooterSerializer.
    *
    * @param $ctx
    * @return MessageInfoFooterSerializer
    * @throws \Exception
    */
    public static function wrapMessageInfoFooterSerializer($ctx): MessageInfoFooterSerializer
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::MESSAGE_INFO_DER_SERIALIZER:
                return (new MessageInfoDerSerializer($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Padding.
    *
    * @param $ctx
    * @return Padding
    * @throws \Exception
    */
    public static function wrapPadding($ctx): Padding
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::RANDOM_PADDING:
                return (new RandomPadding($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }

    /**
    * Wrap C implementation object to the PHP object that implements protocol Kem.
    *
    * @param $ctx
    * @return Kem
    * @throws \Exception
    */
    public static function wrapKem($ctx): Kem
    {
        $implTag = vscf_impl_tag_php($ctx);

        switch ($implTag) {
            case self::ECC:
                return (new Ecc($ctx));
                break;
            case self::ED25519:
                return (new Ed25519($ctx));
                break;
            case self::CURVE25519:
                return (new Curve25519($ctx));
                break;
            case self::ROUND5:
                return (new Round5($ctx));
                break;
            default:
                throw new \Exception("Unexpected C implementation cast to the PHP implementation.");
                break;
        }
    }
}
