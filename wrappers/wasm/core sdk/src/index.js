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


const CoreSdkModule = require(process.env.PROJECT_MODULE);

const initPrecondition = require('../foundation/precondition');
const initFoundationInterfaceTag = require('../foundation/FoundationInterfaceTag');
const initFoundationInterface = require('../foundation/FoundationInterface');
const initFoundationImplTag = require('../foundation/FoundationImplTag');
const initFoundationError = require('../foundation/FoundationError');
const initAsn1Tag = require('../foundation/Asn1Tag');
const initAlgId = require('../foundation/AlgId');
const initOidId = require('../foundation/OidId');
const initGroupMsgType = require('../foundation/GroupMsgType');
const initCipherState = require('../foundation/CipherState');
const initOid = require('../foundation/Oid');
const initBase64 = require('../foundation/Base64');
const initPem = require('../foundation/Pem');
const initMessageInfo = require('../foundation/MessageInfo');
const initKeyRecipientInfo = require('../foundation/KeyRecipientInfo');
const initKeyRecipientInfoList = require('../foundation/KeyRecipientInfoList');
const initPasswordRecipientInfo = require('../foundation/PasswordRecipientInfo');
const initPasswordRecipientInfoList = require('../foundation/PasswordRecipientInfoList');
const initAlgFactory = require('../foundation/AlgFactory');
const initKeyAlgFactory = require('../foundation/KeyAlgFactory');
const initEcies = require('../foundation/Ecies');
const initRecipientCipher = require('../foundation/RecipientCipher');
const initMessageInfoCustomParams = require('../foundation/MessageInfoCustomParams');
const initKeyProvider = require('../foundation/KeyProvider');
const initSigner = require('../foundation/Signer');
const initVerifier = require('../foundation/Verifier');
const initBrainkeyClient = require('../foundation/BrainkeyClient');
const initBrainkeyServer = require('../foundation/BrainkeyServer');
const initGroupSessionMessage = require('../foundation/GroupSessionMessage');
const initGroupSessionTicket = require('../foundation/GroupSessionTicket');
const initGroupSession = require('../foundation/GroupSession');
const initMessageInfoEditor = require('../foundation/MessageInfoEditor');
const initSignerInfo = require('../foundation/SignerInfo');
const initSignerInfoList = require('../foundation/SignerInfoList');
const initMessageInfoFooter = require('../foundation/MessageInfoFooter');
const initSignedDataInfo = require('../foundation/SignedDataInfo');
const initFooterInfo = require('../foundation/FooterInfo');
const initKeyInfo = require('../foundation/KeyInfo');
const initPaddingParams = require('../foundation/PaddingParams');
const initSha224 = require('../foundation/Sha224');
const initSha256 = require('../foundation/Sha256');
const initSha384 = require('../foundation/Sha384');
const initSha512 = require('../foundation/Sha512');
const initAes256Gcm = require('../foundation/Aes256Gcm');
const initAes256Cbc = require('../foundation/Aes256Cbc');
const initAsn1rd = require('../foundation/Asn1rd');
const initAsn1wr = require('../foundation/Asn1wr');
const initRsaPublicKey = require('../foundation/RsaPublicKey');
const initRsaPrivateKey = require('../foundation/RsaPrivateKey');
const initRsa = require('../foundation/Rsa');
const initEccPublicKey = require('../foundation/EccPublicKey');
const initEccPrivateKey = require('../foundation/EccPrivateKey');
const initEcc = require('../foundation/Ecc');
const initEntropyAccumulator = require('../foundation/EntropyAccumulator');
const initCtrDrbg = require('../foundation/CtrDrbg');
const initHmac = require('../foundation/Hmac');
const initHkdf = require('../foundation/Hkdf');
const initKdf1 = require('../foundation/Kdf1');
const initKdf2 = require('../foundation/Kdf2');
const initFakeRandom = require('../foundation/FakeRandom');
const initPkcs5Pbkdf2 = require('../foundation/Pkcs5Pbkdf2');
const initPkcs5Pbes2 = require('../foundation/Pkcs5Pbes2');
const initSeedEntropySource = require('../foundation/SeedEntropySource');
const initKeyMaterialRng = require('../foundation/KeyMaterialRng');
const initRawPublicKey = require('../foundation/RawPublicKey');
const initRawPrivateKey = require('../foundation/RawPrivateKey');
const initPkcs8Serializer = require('../foundation/Pkcs8Serializer');
const initSec1Serializer = require('../foundation/Sec1Serializer');
const initKeyAsn1Serializer = require('../foundation/KeyAsn1Serializer');
const initKeyAsn1Deserializer = require('../foundation/KeyAsn1Deserializer');
const initEd25519 = require('../foundation/Ed25519');
const initCurve25519 = require('../foundation/Curve25519');
const initFalcon = require('../foundation/Falcon');
const initRound5 = require('../foundation/Round5');
const initCompoundKeyAlgInfo = require('../foundation/CompoundKeyAlgInfo');
const initCompoundPublicKey = require('../foundation/CompoundPublicKey');
const initCompoundPrivateKey = require('../foundation/CompoundPrivateKey');
const initCompoundKeyAlg = require('../foundation/CompoundKeyAlg');
const initHybridKeyAlgInfo = require('../foundation/HybridKeyAlgInfo');
const initHybridPublicKey = require('../foundation/HybridPublicKey');
const initHybridPrivateKey = require('../foundation/HybridPrivateKey');
const initHybridKeyAlg = require('../foundation/HybridKeyAlg');
const initSimpleAlgInfo = require('../foundation/SimpleAlgInfo');
const initHashBasedAlgInfo = require('../foundation/HashBasedAlgInfo');
const initCipherAlgInfo = require('../foundation/CipherAlgInfo');
const initSaltedKdfAlgInfo = require('../foundation/SaltedKdfAlgInfo');
const initPbeAlgInfo = require('../foundation/PbeAlgInfo');
const initEccAlgInfo = require('../foundation/EccAlgInfo');
const initAlgInfoDerSerializer = require('../foundation/AlgInfoDerSerializer');
const initAlgInfoDerDeserializer = require('../foundation/AlgInfoDerDeserializer');
const initMessageInfoDerSerializer = require('../foundation/MessageInfoDerSerializer');
const initRandomPadding = require('../foundation/RandomPadding');
const initIndex = require('../foundation/index');
const initCoreSdkError = require('./CoreSdkError');
const initJwtGenerator = require('./JwtGenerator');

const initProject = options => {
    const coreSdkModule = new CoreSdkModule(options);
    return new Promise((resolve, reject) => {
        coreSdkModule.onRuntimeInitialized = () => {
            const modules = {};

            modules.Precondition = initPrecondition(coreSdkModule, modules);
            modules.FoundationInterfaceTag = initFoundationInterfaceTag(coreSdkModule, modules);
            modules.FoundationInterface = initFoundationInterface(coreSdkModule, modules);
            modules.FoundationImplTag = initFoundationImplTag(coreSdkModule, modules);
            modules.FoundationError = initFoundationError(coreSdkModule, modules);
            modules.Asn1Tag = initAsn1Tag(coreSdkModule, modules);
            modules.AlgId = initAlgId(coreSdkModule, modules);
            modules.OidId = initOidId(coreSdkModule, modules);
            modules.GroupMsgType = initGroupMsgType(coreSdkModule, modules);
            modules.CipherState = initCipherState(coreSdkModule, modules);
            modules.Oid = initOid(coreSdkModule, modules);
            modules.Base64 = initBase64(coreSdkModule, modules);
            modules.Pem = initPem(coreSdkModule, modules);
            modules.MessageInfo = initMessageInfo(coreSdkModule, modules);
            modules.KeyRecipientInfo = initKeyRecipientInfo(coreSdkModule, modules);
            modules.KeyRecipientInfoList = initKeyRecipientInfoList(coreSdkModule, modules);
            modules.PasswordRecipientInfo = initPasswordRecipientInfo(coreSdkModule, modules);
            modules.PasswordRecipientInfoList = initPasswordRecipientInfoList(coreSdkModule, modules);
            modules.AlgFactory = initAlgFactory(coreSdkModule, modules);
            modules.KeyAlgFactory = initKeyAlgFactory(coreSdkModule, modules);
            modules.Ecies = initEcies(coreSdkModule, modules);
            modules.RecipientCipher = initRecipientCipher(coreSdkModule, modules);
            modules.MessageInfoCustomParams = initMessageInfoCustomParams(coreSdkModule, modules);
            modules.KeyProvider = initKeyProvider(coreSdkModule, modules);
            modules.Signer = initSigner(coreSdkModule, modules);
            modules.Verifier = initVerifier(coreSdkModule, modules);
            modules.BrainkeyClient = initBrainkeyClient(coreSdkModule, modules);
            modules.BrainkeyServer = initBrainkeyServer(coreSdkModule, modules);
            modules.GroupSessionMessage = initGroupSessionMessage(coreSdkModule, modules);
            modules.GroupSessionTicket = initGroupSessionTicket(coreSdkModule, modules);
            modules.GroupSession = initGroupSession(coreSdkModule, modules);
            modules.MessageInfoEditor = initMessageInfoEditor(coreSdkModule, modules);
            modules.SignerInfo = initSignerInfo(coreSdkModule, modules);
            modules.SignerInfoList = initSignerInfoList(coreSdkModule, modules);
            modules.MessageInfoFooter = initMessageInfoFooter(coreSdkModule, modules);
            modules.SignedDataInfo = initSignedDataInfo(coreSdkModule, modules);
            modules.FooterInfo = initFooterInfo(coreSdkModule, modules);
            modules.KeyInfo = initKeyInfo(coreSdkModule, modules);
            modules.PaddingParams = initPaddingParams(coreSdkModule, modules);
            modules.Sha224 = initSha224(coreSdkModule, modules);
            modules.Sha256 = initSha256(coreSdkModule, modules);
            modules.Sha384 = initSha384(coreSdkModule, modules);
            modules.Sha512 = initSha512(coreSdkModule, modules);
            modules.Aes256Gcm = initAes256Gcm(coreSdkModule, modules);
            modules.Aes256Cbc = initAes256Cbc(coreSdkModule, modules);
            modules.Asn1rd = initAsn1rd(coreSdkModule, modules);
            modules.Asn1wr = initAsn1wr(coreSdkModule, modules);
            modules.RsaPublicKey = initRsaPublicKey(coreSdkModule, modules);
            modules.RsaPrivateKey = initRsaPrivateKey(coreSdkModule, modules);
            modules.Rsa = initRsa(coreSdkModule, modules);
            modules.EccPublicKey = initEccPublicKey(coreSdkModule, modules);
            modules.EccPrivateKey = initEccPrivateKey(coreSdkModule, modules);
            modules.Ecc = initEcc(coreSdkModule, modules);
            modules.EntropyAccumulator = initEntropyAccumulator(coreSdkModule, modules);
            modules.CtrDrbg = initCtrDrbg(coreSdkModule, modules);
            modules.Hmac = initHmac(coreSdkModule, modules);
            modules.Hkdf = initHkdf(coreSdkModule, modules);
            modules.Kdf1 = initKdf1(coreSdkModule, modules);
            modules.Kdf2 = initKdf2(coreSdkModule, modules);
            modules.FakeRandom = initFakeRandom(coreSdkModule, modules);
            modules.Pkcs5Pbkdf2 = initPkcs5Pbkdf2(coreSdkModule, modules);
            modules.Pkcs5Pbes2 = initPkcs5Pbes2(coreSdkModule, modules);
            modules.SeedEntropySource = initSeedEntropySource(coreSdkModule, modules);
            modules.KeyMaterialRng = initKeyMaterialRng(coreSdkModule, modules);
            modules.RawPublicKey = initRawPublicKey(coreSdkModule, modules);
            modules.RawPrivateKey = initRawPrivateKey(coreSdkModule, modules);
            modules.Pkcs8Serializer = initPkcs8Serializer(coreSdkModule, modules);
            modules.Sec1Serializer = initSec1Serializer(coreSdkModule, modules);
            modules.KeyAsn1Serializer = initKeyAsn1Serializer(coreSdkModule, modules);
            modules.KeyAsn1Deserializer = initKeyAsn1Deserializer(coreSdkModule, modules);
            modules.Ed25519 = initEd25519(coreSdkModule, modules);
            modules.Curve25519 = initCurve25519(coreSdkModule, modules);
            modules.Falcon = initFalcon(coreSdkModule, modules);
            modules.Round5 = initRound5(coreSdkModule, modules);
            modules.CompoundKeyAlgInfo = initCompoundKeyAlgInfo(coreSdkModule, modules);
            modules.CompoundPublicKey = initCompoundPublicKey(coreSdkModule, modules);
            modules.CompoundPrivateKey = initCompoundPrivateKey(coreSdkModule, modules);
            modules.CompoundKeyAlg = initCompoundKeyAlg(coreSdkModule, modules);
            modules.HybridKeyAlgInfo = initHybridKeyAlgInfo(coreSdkModule, modules);
            modules.HybridPublicKey = initHybridPublicKey(coreSdkModule, modules);
            modules.HybridPrivateKey = initHybridPrivateKey(coreSdkModule, modules);
            modules.HybridKeyAlg = initHybridKeyAlg(coreSdkModule, modules);
            modules.SimpleAlgInfo = initSimpleAlgInfo(coreSdkModule, modules);
            modules.HashBasedAlgInfo = initHashBasedAlgInfo(coreSdkModule, modules);
            modules.CipherAlgInfo = initCipherAlgInfo(coreSdkModule, modules);
            modules.SaltedKdfAlgInfo = initSaltedKdfAlgInfo(coreSdkModule, modules);
            modules.PbeAlgInfo = initPbeAlgInfo(coreSdkModule, modules);
            modules.EccAlgInfo = initEccAlgInfo(coreSdkModule, modules);
            modules.AlgInfoDerSerializer = initAlgInfoDerSerializer(coreSdkModule, modules);
            modules.AlgInfoDerDeserializer = initAlgInfoDerDeserializer(coreSdkModule, modules);
            modules.MessageInfoDerSerializer = initMessageInfoDerSerializer(coreSdkModule, modules);
            modules.RandomPadding = initRandomPadding(coreSdkModule, modules);
            modules.Index = initIndex(coreSdkModule, modules);
            modules.CoreSdkError = initCoreSdkError(coreSdkModule, modules);
            modules.JwtGenerator = initJwtGenerator(coreSdkModule, modules);
            resolve(modules);
        };

        coreSdkModule.onAbort = message => {
            reject(new Error(message));
        };
    });
};
module.exports = initProject;
