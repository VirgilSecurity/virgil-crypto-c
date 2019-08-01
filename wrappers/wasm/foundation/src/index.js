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


const FoundationModule = require(process.env.PROJECT_MODULE);

const initFoundationInterfaceTag = require('./FoundationInterfaceTag');
const initFoundationInterface = require('./FoundationInterface');
const initFoundationImplTag = require('./FoundationImplTag');
const initFoundationError = require('./FoundationError');
const initAsn1Tag = require('./Asn1Tag');
const initAlgId = require('./AlgId');
const initOidId = require('./OidId');
const initGroupMsgType = require('./GroupMsgType');
const initOid = require('./Oid');
const initBase64 = require('./Base64');
const initPem = require('./Pem');
const initMessageInfo = require('./MessageInfo');
const initKeyRecipientInfo = require('./KeyRecipientInfo');
const initKeyRecipientInfoList = require('./KeyRecipientInfoList');
const initPasswordRecipientInfo = require('./PasswordRecipientInfo');
const initPasswordRecipientInfoList = require('./PasswordRecipientInfoList');
const initAlgFactory = require('./AlgFactory');
const initKeyAlgFactory = require('./KeyAlgFactory');
const initEcies = require('./Ecies');
const initRecipientCipher = require('./RecipientCipher');
const initListKeyValueNode = require('./ListKeyValueNode');
const initMessageInfoCustomParams = require('./MessageInfoCustomParams');
const initKeyProvider = require('./KeyProvider');
const initSigner = require('./Signer');
const initVerifier = require('./Verifier');
const initBrainkeyClient = require('./BrainkeyClient');
const initBrainkeyServer = require('./BrainkeyServer');
const initGroupSessionMessage = require('./GroupSessionMessage');
const initGroupSessionTicket = require('./GroupSessionTicket');
const initGroupSession = require('./GroupSession');
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
const initRsa = require('./Rsa');
const initEccPublicKey = require('./EccPublicKey');
const initEccPrivateKey = require('./EccPrivateKey');
const initEcc = require('./Ecc');
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
const initRawPublicKey = require('./RawPublicKey');
const initRawPrivateKey = require('./RawPrivateKey');
const initPkcs8Serializer = require('./Pkcs8Serializer');
const initSec1Serializer = require('./Sec1Serializer');
const initKeyAsn1Serializer = require('./KeyAsn1Serializer');
const initKeyAsn1Deserializer = require('./KeyAsn1Deserializer');
const initEd25519 = require('./Ed25519');
const initCurve25519 = require('./Curve25519');
const initSimpleAlgInfo = require('./SimpleAlgInfo');
const initHashBasedAlgInfo = require('./HashBasedAlgInfo');
const initCipherAlgInfo = require('./CipherAlgInfo');
const initSaltedKdfAlgInfo = require('./SaltedKdfAlgInfo');
const initPbeAlgInfo = require('./PbeAlgInfo');
const initEccAlgInfo = require('./EccAlgInfo');
const initAlgInfoDerSerializer = require('./AlgInfoDerSerializer');
const initAlgInfoDerDeserializer = require('./AlgInfoDerDeserializer');
const initMessageInfoDerSerializer = require('./MessageInfoDerSerializer');

const initProject = () => {
    const foundationModule = new FoundationModule();
    return new Promise((resolve, reject) => {
        foundationModule.onRuntimeInitialized = () => {
            const modules = {};

            modules.FoundationInterfaceTag = initFoundationInterfaceTag(foundationModule, modules);
            modules.FoundationInterface = initFoundationInterface(foundationModule, modules);
            modules.FoundationImplTag = initFoundationImplTag(foundationModule, modules);
            modules.FoundationError = initFoundationError(foundationModule, modules);
            modules.Asn1Tag = initAsn1Tag(foundationModule, modules);
            modules.AlgId = initAlgId(foundationModule, modules);
            modules.OidId = initOidId(foundationModule, modules);
            modules.GroupMsgType = initGroupMsgType(foundationModule, modules);
            modules.Oid = initOid(foundationModule, modules);
            modules.Base64 = initBase64(foundationModule, modules);
            modules.Pem = initPem(foundationModule, modules);
            modules.MessageInfo = initMessageInfo(foundationModule, modules);
            modules.KeyRecipientInfo = initKeyRecipientInfo(foundationModule, modules);
            modules.KeyRecipientInfoList = initKeyRecipientInfoList(foundationModule, modules);
            modules.PasswordRecipientInfo = initPasswordRecipientInfo(foundationModule, modules);
            modules.PasswordRecipientInfoList = initPasswordRecipientInfoList(foundationModule, modules);
            modules.AlgFactory = initAlgFactory(foundationModule, modules);
            modules.KeyAlgFactory = initKeyAlgFactory(foundationModule, modules);
            modules.Ecies = initEcies(foundationModule, modules);
            modules.RecipientCipher = initRecipientCipher(foundationModule, modules);
            modules.ListKeyValueNode = initListKeyValueNode(foundationModule, modules);
            modules.MessageInfoCustomParams = initMessageInfoCustomParams(foundationModule, modules);
            modules.KeyProvider = initKeyProvider(foundationModule, modules);
            modules.Signer = initSigner(foundationModule, modules);
            modules.Verifier = initVerifier(foundationModule, modules);
            modules.BrainkeyClient = initBrainkeyClient(foundationModule, modules);
            modules.BrainkeyServer = initBrainkeyServer(foundationModule, modules);
            modules.GroupSessionMessage = initGroupSessionMessage(foundationModule, modules);
            modules.GroupSessionTicket = initGroupSessionTicket(foundationModule, modules);
            modules.GroupSession = initGroupSession(foundationModule, modules);
            modules.Sha224 = initSha224(foundationModule, modules);
            modules.Sha256 = initSha256(foundationModule, modules);
            modules.Sha384 = initSha384(foundationModule, modules);
            modules.Sha512 = initSha512(foundationModule, modules);
            modules.Aes256Gcm = initAes256Gcm(foundationModule, modules);
            modules.Aes256Cbc = initAes256Cbc(foundationModule, modules);
            modules.Asn1rd = initAsn1rd(foundationModule, modules);
            modules.Asn1wr = initAsn1wr(foundationModule, modules);
            modules.RsaPublicKey = initRsaPublicKey(foundationModule, modules);
            modules.RsaPrivateKey = initRsaPrivateKey(foundationModule, modules);
            modules.Rsa = initRsa(foundationModule, modules);
            modules.EccPublicKey = initEccPublicKey(foundationModule, modules);
            modules.EccPrivateKey = initEccPrivateKey(foundationModule, modules);
            modules.Ecc = initEcc(foundationModule, modules);
            modules.EntropyAccumulator = initEntropyAccumulator(foundationModule, modules);
            modules.CtrDrbg = initCtrDrbg(foundationModule, modules);
            modules.Hmac = initHmac(foundationModule, modules);
            modules.Hkdf = initHkdf(foundationModule, modules);
            modules.Kdf1 = initKdf1(foundationModule, modules);
            modules.Kdf2 = initKdf2(foundationModule, modules);
            modules.FakeRandom = initFakeRandom(foundationModule, modules);
            modules.Pkcs5Pbkdf2 = initPkcs5Pbkdf2(foundationModule, modules);
            modules.Pkcs5Pbes2 = initPkcs5Pbes2(foundationModule, modules);
            modules.SeedEntropySource = initSeedEntropySource(foundationModule, modules);
            modules.KeyMaterialRng = initKeyMaterialRng(foundationModule, modules);
            modules.RawPublicKey = initRawPublicKey(foundationModule, modules);
            modules.RawPrivateKey = initRawPrivateKey(foundationModule, modules);
            modules.Pkcs8Serializer = initPkcs8Serializer(foundationModule, modules);
            modules.Sec1Serializer = initSec1Serializer(foundationModule, modules);
            modules.KeyAsn1Serializer = initKeyAsn1Serializer(foundationModule, modules);
            modules.KeyAsn1Deserializer = initKeyAsn1Deserializer(foundationModule, modules);
            modules.Ed25519 = initEd25519(foundationModule, modules);
            modules.Curve25519 = initCurve25519(foundationModule, modules);
            modules.SimpleAlgInfo = initSimpleAlgInfo(foundationModule, modules);
            modules.HashBasedAlgInfo = initHashBasedAlgInfo(foundationModule, modules);
            modules.CipherAlgInfo = initCipherAlgInfo(foundationModule, modules);
            modules.SaltedKdfAlgInfo = initSaltedKdfAlgInfo(foundationModule, modules);
            modules.PbeAlgInfo = initPbeAlgInfo(foundationModule, modules);
            modules.EccAlgInfo = initEccAlgInfo(foundationModule, modules);
            modules.AlgInfoDerSerializer = initAlgInfoDerSerializer(foundationModule, modules);
            modules.AlgInfoDerDeserializer = initAlgInfoDerDeserializer(foundationModule, modules);
            modules.MessageInfoDerSerializer = initMessageInfoDerSerializer(foundationModule, modules);
            resolve(modules);
        };

        foundationModule.onAbort = message => {
            reject(new Error(message));
        };
    });
};
module.exports = initProject;
