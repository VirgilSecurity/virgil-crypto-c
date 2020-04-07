/*
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

#include <jni.h>

#ifndef _Included_FoundationJNI_h
#define _Included_FoundationJNI_h
#ifdef __cplusplus
extern "C" {
#endif
JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1fromAlgId (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1toAlgId (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1fromId (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1toId (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1idToAlgId (JNIEnv *, jobject, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1equal (JNIEnv *, jobject, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_base64_1encodedLen (JNIEnv *, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_base64_1encode (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_base64_1decodedLen (JNIEnv *, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_base64_1decode (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1wrappedLen (JNIEnv *, jobject, jstring, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1wrap (JNIEnv *, jobject, jstring, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1unwrappedLen (JNIEnv *, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1unwrap (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1title (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1dataEncryptionAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1keyRecipientInfoList (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1passwordRecipientInfoList (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1hasCustomParams (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1customParams (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1hasCipherKdfAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1cipherKdfAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1hasCipherPaddingAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1cipherPaddingAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1hasFooterInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1footerInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1clear (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1new___3BLcom_virgilsecurity_crypto_foundation_AlgInfo_2_3B (JNIEnv *, jobject, jbyteArray, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1recipientId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1keyEncryptionAlgorithm (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1encryptedKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasItem (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1item (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasNext (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1next (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasPrev (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1prev (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1clear (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgInfo_2_3B (JNIEnv *, jobject, jobject, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1keyEncryptionAlgorithm (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1encryptedKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasItem (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1item (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasNext (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1next (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasPrev (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1prev (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1clear (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createHashFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createMacFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createKdfFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createSaltedKdfFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createCipherFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createPaddingFromInfo (JNIEnv *, jobject, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAlgFactory_1createFromAlgId (JNIEnv *, jobject, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAlgFactory_1createFromKey (JNIEnv *, jobject, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAlgFactory_1createFromRawPublicKey (JNIEnv *, jobject, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAlgFactory_1createFromRawPrivateKey (JNIEnv *, jobject, jobject, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setCipher (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setMac (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setKdf (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setKeyAlg (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1releaseKeyAlg (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setupDefaultsNoRandom (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1encryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1encrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1decryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1decrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setEncryptionCipher (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setEncryptionPadding (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setPaddingParams (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setSignerHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1hasKeyRecipient (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1addKeyRecipient (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1clearRecipients (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1addSigner (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1clearSigners (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1customParams (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1startEncryption (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1startSignedEncryption (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1messageInfoLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1packMessageInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1encryptionOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1processEncryption (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1finishEncryption (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1startDecryptionWithKey (JNIEnv *, jobject, jlong, jbyteArray, jobject, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1startVerifiedDecryptionWithKey (JNIEnv *, jobject, jlong, jbyteArray, jobject, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1decryptionOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1processDecryption (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1finishDecryption (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1isDataSigned (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1signerInfos (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1verifySignerInfo (JNIEnv *, jobject, jlong, jobject, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1messageInfoFooterLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1packMessageInfoFooter (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addInt (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addString (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addData (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1clear (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findInt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findString (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1hasParams (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1setRsaParams (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generatePrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generatePostQuantumPrivateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generateCompoundPrivateKey (JNIEnv *, jobject, jlong, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generateHybridPrivateKey (JNIEnv *, jobject, jlong, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generateCompoundHybridPrivateKey (JNIEnv *, jobject, jlong, jobject, jobject, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1importPrivateKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1importPublicKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1exportedPublicKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1exportPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1exportedPrivateKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1exportPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1reset (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1appendData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1signatureLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1sign (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1reset (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1appendData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1verify (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1setOperationRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1blind (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1deblind (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1setOperationRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1generateIdentitySecret (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1harden (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1getType (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1getSessionId (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1getEpoch (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1serializeLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1serialize (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1deserialize (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1setRng (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1setupTicketAsNew (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1getTicketMessage (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1setRng (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1getCurrentEpoch (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1getSessionId (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1addEpoch (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1encrypt (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1decryptLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1decrypt (JNIEnv *, jobject, jlong, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1createGroupTicket (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1unpack (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1unlock (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1addKeyRecipient (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1removeKeyRecipient (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1removeAll (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1packedLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1pack (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1signerId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1signerAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1signature (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1hasItem (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1item (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1hasNext (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1next (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1hasPrev (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1prev (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1clear (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1hasSignerInfos (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1signerInfos (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1signerHashAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1signerDigest (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signedDataInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signedDataInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signedDataInfo_1hashAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1hasSignedDataInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1signedDataInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1setDataSize (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1dataSize (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgInfo_2 (JNIEnv *, jobject, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isCompound (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isHybrid (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isCompoundHybrid (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isCompoundHybridCipher (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isCompoundHybridSigner (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isHybridPostQuantum (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isHybridPostQuantumCipher (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isHybridPostQuantumSigner (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundCipherAlgId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundSignerAlgId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1hybridFirstKeyAlgId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1hybridSecondKeyAlgId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundHybridCipherFirstKeyAlgId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundHybridCipherSecondKeyAlgId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundHybridSignerFirstKeyAlgId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundHybridSignerSecondKeyAlgId (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1new__II (JNIEnv *, jobject, jint, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1frame (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1frameMax (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1hash (JNIEnv *, jobject, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1start (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1hash (JNIEnv *, jobject, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1start (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1hash (JNIEnv *, jobject, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1start (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1hash (JNIEnv *, jobject, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1start (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1preciseEncryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1setNonce (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1setKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1startEncryption (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1startDecryption (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1outLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1encryptedOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1decryptedOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1authEncrypt (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1authEncryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1authDecrypt (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1authDecryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1setAuthData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1finishAuthEncryption (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1finishAuthDecryption (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1preciseEncryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1setNonce (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1setKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1startEncryption (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1startDecryption (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1outLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1encryptedOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1decryptedOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1reset (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1leftLen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1hasError (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1status (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1getTag (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1getLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1getDataLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readTag (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readContextTag (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt8 (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt16 (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt32 (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt64 (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint8 (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint16 (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint32 (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint64 (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readBool (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readNull (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readNullOptional (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readOctetStr (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readBitstringAsOctetStr (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUtf8Str (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readOid (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readData (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readSequence (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readSet (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1reset (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1finish (JNIEnv *, jobject, jlong, jboolean);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1bytes (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writtenLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1unwrittenLen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1hasError (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1status (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1reserve (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeTag (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeContextTag (JNIEnv *, jobject, jlong, jint, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt8 (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt16 (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt32 (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt64 (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint8 (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint16 (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint32 (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint64 (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeBool (JNIEnv *, jobject, jlong, jboolean);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeNull (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeOctetStr (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeOctetStrAsBitstring (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUtf8Str (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeOid (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeSequence (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeSet (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1keyExponent (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1extractPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1generateKey (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1generateEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1importPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1importPublicKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1exportPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1exportedPublicKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1exportPublicKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1importPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1importPrivateKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1exportPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1exportedPrivateKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1exportPrivateKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1canEncrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1encryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1encrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1canDecrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1decryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1decrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1canSign (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1signatureLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1signHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1canVerify (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1verifyHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1extractPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1setEcies (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1generateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1generateEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1importPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1importPublicKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1exportPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1exportedPublicKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1exportPublicKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1importPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1importPrivateKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1exportPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1exportedPrivateKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1exportPrivateKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1canEncrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1encryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1encrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1canDecrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1decryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1decrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1canSign (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1signatureLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1signHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1canVerify (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1verifyHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1computeSharedKey (JNIEnv *, jobject, jlong, jobject, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1sharedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1kemSharedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1kemEncapsulatedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1kemEncapsulate (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1kemDecapsulate (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1addSource (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1isStrong (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1gather (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1setEntropySource (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1enablePredictionResistance (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1setReseedInterval (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1setEntropyLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1random (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1reseed (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1digestLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1mac (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1start (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1reset (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1derive (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1reset (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1setInfo (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1derive (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1derive (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1setupSourceByte (JNIEnv *, jobject, jlong, jbyte);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1setupSourceData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1random (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1reseed (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1isStrong (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1gather (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setHmac (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1derive (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1reset (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setInfo (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1setKdf (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1setCipher (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1reset (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1preciseEncryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1resetSeed (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1isStrong (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1gather (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1resetKeyMaterial (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1random (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1reseed (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1data (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1data (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1hasPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1setPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1getPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1extractPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1setAsn1Writer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePublicKeyInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePrivateKeyInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializedPublicKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializedPrivateKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1setAsn1Writer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializePublicKeyInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializePrivateKeyInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializedPublicKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializePublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializedPrivateKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializePrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1setAsn1Writer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializePublicKeyInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializePrivateKeyInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializedPublicKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializePublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializedPrivateKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializePrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1setAsn1Reader (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1deserializePublicKeyInplace (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1deserializePrivateKeyInplace (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1deserializePublicKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1deserializePrivateKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1setEcies (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1generateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1generateEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1importPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1importPublicKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1exportPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1exportedPublicKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1exportPublicKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1importPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1importPrivateKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1exportPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1exportedPrivateKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1exportPrivateKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1canEncrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1encryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1encrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1canDecrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1decryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1decrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1canSign (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1signatureLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1signHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1canVerify (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1verifyHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1computeSharedKey (JNIEnv *, jobject, jlong, jobject, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1sharedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1kemSharedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1kemEncapsulatedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1kemEncapsulate (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1kemDecapsulate (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1setEcies (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1generateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1generateEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1importPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1importPublicKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1exportPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1exportedPublicKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1exportPublicKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1importPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1importPrivateKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1exportPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1exportedPrivateKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1exportPrivateKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1canEncrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1encryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1encrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1canDecrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1decryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1decrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1computeSharedKey (JNIEnv *, jobject, jlong, jobject, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1sharedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1kemSharedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1kemEncapsulatedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1kemEncapsulate (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1kemDecapsulate (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1generateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1generateEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1importPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1importPublicKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1exportPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1exportedPublicKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1exportPublicKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1importPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1importPrivateKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1exportPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1exportedPrivateKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1exportPrivateKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1canSign (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1signatureLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1signHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1canVerify (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1verifyHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1generateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1generateEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1importPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1importPublicKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1exportPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1exportedPublicKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1exportPublicKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1importPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1importPrivateKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1exportPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1exportedPrivateKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1exportPrivateKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1kemSharedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1kemEncapsulatedKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1kemEncapsulate (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1kemDecapsulate (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1cipherAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1signerAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1cipherKey (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1signerKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1cipherKey (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1signerKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1extractPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1makeKey (JNIEnv *, jobject, jlong, jobject, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1generateEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1importPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1importPublicKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1exportPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1exportedPublicKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1exportPublicKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1importPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1importPrivateKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1exportPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1exportedPrivateKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1exportPrivateKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1canEncrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1encryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1encrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1canDecrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1decryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1decrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1canSign (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1signatureLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1signHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1canVerify (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1verifyHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlgInfo_1firstKeyAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlgInfo_1secondKeyAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlgInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPublicKey_1firstKey (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPublicKey_1secondKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPublicKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPublicKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPublicKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPublicKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPublicKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPublicKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPublicKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1firstKey (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1secondKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1algInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1bitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1isValid (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridPrivateKey_1extractPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1setCipher (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1makeKey (JNIEnv *, jobject, jlong, jobject, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1generateEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1importPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1importPublicKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1exportPublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1exportedPublicKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1exportPublicKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1importPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1importPrivateKeyData (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1exportPrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1exportedPrivateKeyDataLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1exportPrivateKeyData (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1canEncrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1encryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1encrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1canDecrypt (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1decryptedLen (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1decrypt (JNIEnv *, jobject, jlong, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1canSign (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1signatureLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1signHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1canVerify (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hybridKeyAlg_1verifyHash (JNIEnv *, jobject, jlong, jobject, jobject, jbyteArray, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_simpleAlgInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_simpleAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_simpleAlgInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgId_2 (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_simpleAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1hashAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1nonce (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgId_2_3B (JNIEnv *, jobject, jobject, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1hashAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1salt (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1iterationCount (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1kdfAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1cipherAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1keyId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1domainId (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgId_2Lcom_virgilsecurity_crypto_foundation_OidId_2Lcom_virgilsecurity_crypto_foundation_OidId_2 (JNIEnv *, jobject, jobject, jobject, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1setAsn1Writer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serializeInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serializedLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serialize (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1setAsn1Reader (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1deserializeInplace (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1deserialize (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setAsn1Reader (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setAsn1Writer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serializedLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serialize (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1readPrefix (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1deserialize (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serializedFooterLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serializeFooter (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1deserializeFooter (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1configure (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1paddedDataLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1lenMax (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1startDataProcessing (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1processData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1finishDataProcessing (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1startPaddedDataProcessing (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1processPaddedData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1finishPaddedDataProcessingOutLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1finishPaddedDataProcessing (JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif
