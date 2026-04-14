/*
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

JNIEXPORT jlong JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1new__(void);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1close(jlong );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1setRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1setOperationRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1setupDefaults(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1generateServerKeyPair(jlong c_ctx);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1enrollmentResponseLen(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1getEnrollment(jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1verifyPasswordResponseLen(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1verifyPassword(jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey, jbyteArray jverifyPasswordRequest);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1updateTokenLen(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1rotateKeys(jlong c_ctx, jbyteArray jserverPrivateKey);

JNIEXPORT jlong JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1new__(void);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1close(jlong );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1setRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1setOperationRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1setupDefaults(jlong c_ctx);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1setKeys(jlong c_ctx, jbyteArray jclientPrivateKey, jbyteArray jserverPublicKey);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1generateClientPrivateKey(jlong c_ctx);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1enrollmentRecordLen(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1enrollAccount(jlong c_ctx, jbyteArray jenrollmentResponse, jbyteArray jpassword);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1verifyPasswordRequestLen(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1createVerifyPasswordRequest(jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1checkResponseAndDecrypt(jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord, jbyteArray jverifyPasswordResponse);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1rotateKeys(jlong c_ctx, jbyteArray jupdateToken);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1updateEnrollmentRecord(jlong c_ctx, jbyteArray jenrollmentRecord, jbyteArray jupdateToken);

JNIEXPORT jlong JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1new__(void);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1close(jlong );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1setRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1setupDefaults(jlong c_ctx);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1encryptLen(jlong c_ctx, jint jplainTextLen);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1decryptLen(jlong c_ctx, jint jcipherTextLen);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1encrypt(jlong c_ctx, jbyteArray jplainText, jbyteArray jaccountKey);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1decrypt(jlong c_ctx, jbyteArray jcipherText, jbyteArray jaccountKey);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1authEncrypt(jlong c_ctx, jbyteArray jplainText, jbyteArray jadditionalData, jbyteArray jaccountKey);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1authDecrypt(jlong c_ctx, jbyteArray jcipherText, jbyteArray jadditionalData, jbyteArray jaccountKey);

JNIEXPORT jlong JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1new__(void);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1close(jlong );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setOperationRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setupDefaults(jlong c_ctx);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setKeysOneparty(jlong c_ctx, jbyteArray jclientPrivateKey);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setKeys(jlong c_ctx, jbyteArray jclientPrivateKey, jbyteArray jserverPublicKey);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1generateClientPrivateKey(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1generateEncryptWrap(jlong c_ctx, jint jencryptionKeyLen);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1decryptOneparty(jlong c_ctx, jbyteArray jwrap, jint jencryptionKeyLen);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1generateDecryptRequest(jlong c_ctx, jbyteArray jwrap);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1processDecryptResponse(jlong c_ctx, jbyteArray jwrap, jbyteArray jdecryptRequest, jbyteArray jdecryptResponse, jbyteArray jdeblindFactor, jint jencryptionKeyLen);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1rotateKeysOneparty(jlong c_ctx, jbyteArray jupdateToken);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1generateUpdateTokenOneparty(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1rotateKeys(jlong c_ctx, jbyteArray jupdateToken);

JNIEXPORT jlong JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1new__(void);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1close(jlong );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1setRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1setOperationRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1setupDefaults(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1generateServerKeyPair(jlong c_ctx);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1decryptResponseLen(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1processDecryptRequest(jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jdecryptRequest);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1rotateKeys(jlong c_ctx, jbyteArray jserverPrivateKey);

JNIEXPORT jlong JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1new__(void);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1close(jlong );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1setOperationRandom(jlong , jobject );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1setupDefaults(jlong c_ctx);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1setUpdateToken(jlong c_ctx, jbyteArray jupdateToken);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1updateWrap(jlong c_ctx, jbyteArray jwrap);
