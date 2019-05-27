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


const FoundationModule = require('libfoundation');

const initFoundationInterface = require('./FoundationInterface');
const initFoundationImplTag = require('./FoundationImplTag');
const initFoundationError = require('./FoundationError');
const initAsn1Tag = require('./Asn1Tag');
const initAlgId = require('./AlgId');
const initOidId = require('./OidId');
const initRawKey = require('./RawKey');
const initOid = require('./Oid');
const initBase64 = require('./Base64');
const initPem = require('./Pem');
const initMessageInfo = require('./MessageInfo');
const initKeyRecipientInfo = require('./KeyRecipientInfo');
const initKeyRecipientInfoList = require('./KeyRecipientInfoList');
const initPasswordRecipientInfo = require('./PasswordRecipientInfo');
const initPasswordRecipientInfoList = require('./PasswordRecipientInfoList');
const initAlgFactory = require('./AlgFactory');
const initRecipientCipher = require('./RecipientCipher');
const initListKeyValueNode = require('./ListKeyValueNode');
const initMessageInfoCustomParams = require('./MessageInfoCustomParams');
const initKeyProvider = require('./KeyProvider');
const initSigner = require('./Signer');
const initVerifier = require('./Verifier');
const initSha224 = require('./Sha224');
const initSha256 = require('./Sha256');
const initSha384 = require('./Sha384');
const initSha512 = require('./Sha512');
const initAes256Gcm = require('./Aes256Gcm');
const initAes256Cbc = require('./Aes256Cbc');
const initAsn1rd = require('./Asn1rd');
const initAsn1wr = require('./Asn1wr');
const initRsaPublicKey = require('./RsaPublicKey');
const initRsaPrivateKey = require('./RsaPrivateKey');
const initSecp256r1PublicKey = require('./Secp256r1PublicKey');
const initSecp256r1PrivateKey = require('./Secp256r1PrivateKey');
const initEntropyAccumulator = require('./EntropyAccumulator');
const initCtrDrbg = require('./CtrDrbg');
const initHmac = require('./Hmac');
const initHkdf = require('./Hkdf');
const initKdf1 = require('./Kdf1');
const initKdf2 = require('./Kdf2');
const initFakeRandom = require('./FakeRandom');
const initPkcs5Pbkdf2 = require('./Pkcs5Pbkdf2');
const initPkcs5Pbes2 = require('./Pkcs5Pbes2');
const initSeedEntropySource = require('./SeedEntropySource');
const initKeyMaterialRng = require('./KeyMaterialRng');
const initPkcs8Serializer = require('./Pkcs8Serializer');
const initSec1Serializer = require('./Sec1Serializer');
const initKeyAsn1Serializer = require('./KeyAsn1Serializer');
const initKeyAsn1Deserializer = require('./KeyAsn1Deserializer');
const initEd25519PublicKey = require('./Ed25519PublicKey');
const initEd25519PrivateKey = require('./Ed25519PrivateKey');
const initCurve25519PublicKey = require('./Curve25519PublicKey');
const initCurve25519PrivateKey = require('./Curve25519PrivateKey');
const initEcies = require('./Ecies');
const initSimpleAlgInfo = require('./SimpleAlgInfo');
const initHashBasedAlgInfo = require('./HashBasedAlgInfo');
const initCipherAlgInfo = require('./CipherAlgInfo');
const initSaltedKdfAlgInfo = require('./SaltedKdfAlgInfo');
const initPbeAlgInfo = require('./PbeAlgInfo');
const initEcAlgInfo = require('./EcAlgInfo');
const initAlgInfoDerSerializer = require('./AlgInfoDerSerializer');
const initAlgInfoDerDeserializer = require('./AlgInfoDerDeserializer');
const initMessageInfoDerSerializer = require('./MessageInfoDerSerializer');

const FoundationModule = new FoundationModule();
let initPromise;

const initFoundation = () => {
    if (initPromise) {
        return initPromise;
    }
    initPromise = new Promise((resolve, reject) => {
        FoundationModule.onRuntimeInitialized = () => {
            const modules = {};

            modules.FoundationInterface = initFoundationInterface(FoundationModule, modules);
            modules.FoundationImplTag = initFoundationImplTag(FoundationModule, modules);
            modules.FoundationError = initFoundationError(FoundationModule, modules);
            modules.Asn1Tag = initAsn1Tag(FoundationModule, modules);
            modules.AlgId = initAlgId(FoundationModule, modules);
            modules.OidId = initOidId(FoundationModule, modules);
            modules.RawKey = initRawKey(FoundationModule, modules);
            modules.Oid = initOid(FoundationModule, modules);
            modules.Base64 = initBase64(FoundationModule, modules);
            modules.Pem = initPem(FoundationModule, modules);
            modules.MessageInfo = initMessageInfo(FoundationModule, modules);
            modules.KeyRecipientInfo = initKeyRecipientInfo(FoundationModule, modules);
            modules.KeyRecipientInfoList = initKeyRecipientInfoList(FoundationModule, modules);
            modules.PasswordRecipientInfo = initPasswordRecipientInfo(FoundationModule, modules);
            modules.PasswordRecipientInfoList = initPasswordRecipientInfoList(FoundationModule, modules);
            modules.AlgFactory = initAlgFactory(FoundationModule, modules);
            modules.RecipientCipher = initRecipientCipher(FoundationModule, modules);
            modules.ListKeyValueNode = initListKeyValueNode(FoundationModule, modules);
            modules.MessageInfoCustomParams = initMessageInfoCustomParams(FoundationModule, modules);
            modules.KeyProvider = initKeyProvider(FoundationModule, modules);
            modules.Signer = initSigner(FoundationModule, modules);
            modules.Verifier = initVerifier(FoundationModule, modules);
            modules.Sha224 = initSha224(FoundationModule, modules);
            modules.Sha256 = initSha256(FoundationModule, modules);
            modules.Sha384 = initSha384(FoundationModule, modules);
            modules.Sha512 = initSha512(FoundationModule, modules);
            modules.Aes256Gcm = initAes256Gcm(FoundationModule, modules);
            modules.Aes256Cbc = initAes256Cbc(FoundationModule, modules);
            modules.Asn1rd = initAsn1rd(FoundationModule, modules);
            modules.Asn1wr = initAsn1wr(FoundationModule, modules);
            modules.RsaPublicKey = initRsaPublicKey(FoundationModule, modules);
            modules.RsaPrivateKey = initRsaPrivateKey(FoundationModule, modules);
            modules.Secp256r1PublicKey = initSecp256r1PublicKey(FoundationModule, modules);
            modules.Secp256r1PrivateKey = initSecp256r1PrivateKey(FoundationModule, modules);
            modules.EntropyAccumulator = initEntropyAccumulator(FoundationModule, modules);
            modules.CtrDrbg = initCtrDrbg(FoundationModule, modules);
            modules.Hmac = initHmac(FoundationModule, modules);
            modules.Hkdf = initHkdf(FoundationModule, modules);
            modules.Kdf1 = initKdf1(FoundationModule, modules);
            modules.Kdf2 = initKdf2(FoundationModule, modules);
            modules.FakeRandom = initFakeRandom(FoundationModule, modules);
            modules.Pkcs5Pbkdf2 = initPkcs5Pbkdf2(FoundationModule, modules);
            modules.Pkcs5Pbes2 = initPkcs5Pbes2(FoundationModule, modules);
            modules.SeedEntropySource = initSeedEntropySource(FoundationModule, modules);
            modules.KeyMaterialRng = initKeyMaterialRng(FoundationModule, modules);
            modules.Pkcs8Serializer = initPkcs8Serializer(FoundationModule, modules);
            modules.Sec1Serializer = initSec1Serializer(FoundationModule, modules);
            modules.KeyAsn1Serializer = initKeyAsn1Serializer(FoundationModule, modules);
            modules.KeyAsn1Deserializer = initKeyAsn1Deserializer(FoundationModule, modules);
            modules.Ed25519PublicKey = initEd25519PublicKey(FoundationModule, modules);
            modules.Ed25519PrivateKey = initEd25519PrivateKey(FoundationModule, modules);
            modules.Curve25519PublicKey = initCurve25519PublicKey(FoundationModule, modules);
            modules.Curve25519PrivateKey = initCurve25519PrivateKey(FoundationModule, modules);
            modules.Ecies = initEcies(FoundationModule, modules);
            modules.SimpleAlgInfo = initSimpleAlgInfo(FoundationModule, modules);
            modules.HashBasedAlgInfo = initHashBasedAlgInfo(FoundationModule, modules);
            modules.CipherAlgInfo = initCipherAlgInfo(FoundationModule, modules);
            modules.SaltedKdfAlgInfo = initSaltedKdfAlgInfo(FoundationModule, modules);
            modules.PbeAlgInfo = initPbeAlgInfo(FoundationModule, modules);
            modules.EcAlgInfo = initEcAlgInfo(FoundationModule, modules);
            modules.AlgInfoDerSerializer = initAlgInfoDerSerializer(FoundationModule, modules);
            modules.AlgInfoDerDeserializer = initAlgInfoDerDeserializer(FoundationModule, modules);
            modules.MessageInfoDerSerializer = initMessageInfoDerSerializer(FoundationModule, modules);
            resolve(modules);
        };

        FoundationModule.onAbort = message => {
            reject(new Error(message));
        };
    });
    return initPromise;
};
module.exports = initFoundation;
