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


const initFoundationInterface = Module => {
    class FoundationInterface {

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            const implTag = vscf_impl_tag(ctxPtr);
            switch(implTag) {

                case FoundationImplTag.SHA224;
                    return Sha224.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.SHA256;
                    return Sha256.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.SHA384;
                    return Sha384.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.SHA512;
                    return Sha512.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.AES256_GCM;
                    return Aes256Gcm.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.AES256_CBC;
                    return Aes256Cbc.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.ASN1RD;
                    return Asn1rd.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.ASN1WR;
                    return Asn1wr.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.RSA_PUBLIC_KEY;
                    return RsaPublicKey.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.RSA_PRIVATE_KEY;
                    return RsaPrivateKey.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.SECP256R1_PUBLIC_KEY;
                    return Secp256r1PublicKey.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.SECP256R1_PRIVATE_KEY;
                    return Secp256r1PrivateKey.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.ENTROPY_ACCUMULATOR;
                    return EntropyAccumulator.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.CTR_DRBG;
                    return CtrDrbg.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.HMAC;
                    return Hmac.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.HKDF;
                    return Hkdf.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.KDF1;
                    return Kdf1.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.KDF2;
                    return Kdf2.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.FAKE_RANDOM;
                    return FakeRandom.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.PKCS5_PBKDF2;
                    return Pkcs5Pbkdf2.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.PKCS5_PBES2;
                    return Pkcs5Pbes2.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.SEED_ENTROPY_SOURCE;
                    return SeedEntropySource.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.KEY_MATERIAL_RNG;
                    return KeyMaterialRng.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.PKCS8_SERIALIZER;
                    return Pkcs8Serializer.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.SEC1_SERIALIZER;
                    return Sec1Serializer.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.KEY_ASN1_SERIALIZER;
                    return KeyAsn1Serializer.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.KEY_ASN1_DESERIALIZER;
                    return KeyAsn1Deserializer.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.ED25519_PUBLIC_KEY;
                    return Ed25519PublicKey.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.ED25519_PRIVATE_KEY;
                    return Ed25519PrivateKey.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.CURVE25519_PUBLIC_KEY;
                    return Curve25519PublicKey.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.CURVE25519_PRIVATE_KEY;
                    return Curve25519PrivateKey.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.ECIES;
                    return Ecies.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.SIMPLE_ALG_INFO;
                    return SimpleAlgInfo.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.HASH_BASED_ALG_INFO;
                    return HashBasedAlgInfo.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.CIPHER_ALG_INFO;
                    return CipherAlgInfo.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.SALTED_KDF_ALG_INFO;
                    return SaltedKdfAlgInfo.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.PBE_ALG_INFO;
                    return PbeAlgInfo.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.EC_ALG_INFO;
                    return EcAlgInfo.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.ALG_INFO_DER_SERIALIZER;
                    return AlgInfoDerSerializer.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.ALG_INFO_DER_DESERIALIZER;
                    return AlgInfoDerDeserializer.newAndTakeCContext(ctxPtr);

                case FoundationImplTag.MESSAGE_INFO_DER_SERIALIZER;
                    return MessageInfoDerSerializer.newAndTakeCContext(ctxPtr);

                default:
                    throw new Error('Unexpected implementation tag found: ' + implTag);
            }
        }

        /**
         * Acquire C context by making it's shallow copy.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndUseCContext(ctxPtr) {
            return new FoundationInterface.newAndTakeCContext(Module._vscf_impl_shallow_copy(ctxPtr));
        }
    }
};

module.exports = initFoundationInterface;
