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


const initFoundationInterface = (Module, modules) => {
    class FoundationInterface {

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            const implTag = Module._vscf_impl_tag(ctxPtr);
            switch(implTag) {

                case modules.FoundationImplTag.SHA224:
                    return modules.Sha224.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.SHA256:
                    return modules.Sha256.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.SHA384:
                    return modules.Sha384.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.SHA512:
                    return modules.Sha512.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.AES256_GCM:
                    return modules.Aes256Gcm.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.AES256_CBC:
                    return modules.Aes256Cbc.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ASN1RD:
                    return modules.Asn1rd.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ASN1WR:
                    return modules.Asn1wr.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.RSA_PUBLIC_KEY:
                    return modules.RsaPublicKey.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.RSA_PRIVATE_KEY:
                    return modules.RsaPrivateKey.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.RSA:
                    return modules.Rsa.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ECC_PUBLIC_KEY:
                    return modules.EccPublicKey.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ECC_PRIVATE_KEY:
                    return modules.EccPrivateKey.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ECC:
                    return modules.Ecc.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ENTROPY_ACCUMULATOR:
                    return modules.EntropyAccumulator.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.CTR_DRBG:
                    return modules.CtrDrbg.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.HMAC:
                    return modules.Hmac.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.HKDF:
                    return modules.Hkdf.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.KDF1:
                    return modules.Kdf1.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.KDF2:
                    return modules.Kdf2.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.FAKE_RANDOM:
                    return modules.FakeRandom.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.PKCS5_PBKDF2:
                    return modules.Pkcs5Pbkdf2.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.PKCS5_PBES2:
                    return modules.Pkcs5Pbes2.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.SEED_ENTROPY_SOURCE:
                    return modules.SeedEntropySource.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.KEY_MATERIAL_RNG:
                    return modules.KeyMaterialRng.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.RAW_PUBLIC_KEY:
                    return modules.RawPublicKey.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.RAW_PRIVATE_KEY:
                    return modules.RawPrivateKey.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.PKCS8_SERIALIZER:
                    return modules.Pkcs8Serializer.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.SEC1_SERIALIZER:
                    return modules.Sec1Serializer.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.KEY_ASN1_SERIALIZER:
                    return modules.KeyAsn1Serializer.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.KEY_ASN1_DESERIALIZER:
                    return modules.KeyAsn1Deserializer.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ED25519:
                    return modules.Ed25519.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.CURVE25519:
                    return modules.Curve25519.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.SIMPLE_ALG_INFO:
                    return modules.SimpleAlgInfo.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.HASH_BASED_ALG_INFO:
                    return modules.HashBasedAlgInfo.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.CIPHER_ALG_INFO:
                    return modules.CipherAlgInfo.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.SALTED_KDF_ALG_INFO:
                    return modules.SaltedKdfAlgInfo.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.PBE_ALG_INFO:
                    return modules.PbeAlgInfo.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ECC_ALG_INFO:
                    return modules.EccAlgInfo.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ALG_INFO_DER_SERIALIZER:
                    return modules.AlgInfoDerSerializer.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.ALG_INFO_DER_DESERIALIZER:
                    return modules.AlgInfoDerDeserializer.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.MESSAGE_INFO_DER_SERIALIZER:
                    return modules.MessageInfoDerSerializer.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.RANDOM_PADDING:
                    return modules.RandomPadding.newAndTakeCContext(ctxPtr);

                case modules.FoundationImplTag.PADDING_CIPHER:
                    return modules.PaddingCipher.newAndTakeCContext(ctxPtr);

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
            return new modules.FoundationInterface.newAndTakeCContext(Module._vscf_impl_shallow_copy(ctxPtr));
        }

        /**
         * Return true if given class implements C interface with a given tag.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static isImplemented(ctxPtr, interfaceTag) {
            return Module._vscf_impl_api(ctxPtr, interfaceTag) != 0;
        }
    }

    return FoundationInterface;
};

module.exports = initFoundationInterface;
