/*
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

#include <jni.h>

#ifndef _Included_FoundationJNI_h
#define _Included_FoundationJNI_h
#ifdef __cplusplus
extern "C" {
#endif
JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1reset (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1hasError (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1status (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_rawKey_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rawKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rawKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rawKey_1data (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1fromAlgId (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1toAlgId (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1fromId (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1toId (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1equal (JNIEnv *, jobject, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_base64_1encodedLen (JNIEnv *, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_base64_1encode (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_base64_1decodedLen (JNIEnv *, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_base64_1decode (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1wrappedLen (JNIEnv *, jobject, jstring, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1wrap (JNIEnv *, jobject, jstring, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1unwrappedLen (JNIEnv *, jobject, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1unwrap (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1title (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1addKeyRecipient (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1addPasswordRecipient (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1setDataEncryptionAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1dataEncryptionAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1keyRecipientInfoList (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1passwordRecipientInfoList (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1setCustomParams (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1customParams (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1clearRecipients (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1recipientId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1keyEncryptionAlgorithm (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1encryptedKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1add (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasItem (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1item (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasNext (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1next (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasPrev (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1prev (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1clear (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfo_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfo_1keyEncryptionAlgorithm (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfo_1encryptedKey (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1add (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasItem (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1item (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasNext (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1next (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasPrev (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1prev (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1clear (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createHashFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createMacFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createKdfFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createSaltedKdfFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createCipherFromInfo (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createPublicKeyFromRawKey (JNIEnv *, jobject, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createPrivateKeyFromRawKey (JNIEnv *, jobject, jobject);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1setEncryptionCipher (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1addKeyRecipient (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1clearRecipients (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1customParams (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1messageInfoLen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1startEncryption (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1packMessageInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1encryptionOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1processEncryption (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1finishEncryption (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1startDecryptionWithKey (JNIEnv *, jobject, jlong, jbyteArray, jobject, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1decryptionOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1processDecryption (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1finishDecryption (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_listKeyValueNode_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_listKeyValueNode_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addInt (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addString (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addData (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1clear (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findInt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findString (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1setEcies (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1setRsaParams (JNIEnv *, jobject, jlong, jint, jint);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1generatePrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1importPrivateKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1importPublicKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1reset (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1signatureLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1sign (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1reset (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1verify (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1hash (JNIEnv *, jobject, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1start (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1hash (JNIEnv *, jobject, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1start (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1hash (JNIEnv *, jobject, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1start (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1hash (JNIEnv *, jobject, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1start (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1setNonce (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1setKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1startEncryption (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1startDecryption (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1outLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1encryptedOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1decryptedOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1authEncrypt (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1authEncryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1authDecrypt (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1authDecryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1setNonce (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1setKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1startEncryption (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1startDecryption (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1outLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1encryptedOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1decryptedOutLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1reset (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1leftLen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1hasError (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1status (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1getTag (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1getLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1getDataLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readTag (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readContextTag (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt8 (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt16 (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt32 (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt64 (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint8 (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint16 (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint32 (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint64 (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readBool (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readNull (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readNullOptional (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readOctetStr (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readBitstringAsOctetStr (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUtf8Str (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readOid (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readData (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readSequence (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readSet (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1reset (JNIEnv *, jobject, jlong, jbyte, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1finish (JNIEnv *, jobject, jlong, jboolean);

JNIEXPORT jbyte JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1bytes (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1len (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writtenLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1unwrittenLen (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1hasError (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1status (JNIEnv *, jobject, jlong);

JNIEXPORT jbyte JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1reserve (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeTag (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeContextTag (JNIEnv *, jobject, jlong, jint, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt8 (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt16 (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt32 (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt64 (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint8 (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint16 (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint32 (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint64 (JNIEnv *, jobject, jlong, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeBool (JNIEnv *, jobject, jlong, jboolean);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeNull (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeOctetStr (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeOctetStrAsBitstring (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUtf8Str (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeOid (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeSequence (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeSet (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setAsn1rd (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setAsn1wr (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1keyLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1keyBitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1verifyHash (JNIEnv *, jobject, jlong, jbyteArray, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1exportPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1exportedPublicKeyLen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1importPublicKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1generateEphemeralKey (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setAsn1rd (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setAsn1wr (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setKeygenParams (JNIEnv *, jobject, jlong, jint, jint);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1keyLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1keyBitlen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1generateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1signatureLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1signHash (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1extractPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1exportPrivateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1exportedPrivateKeyLen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1importPrivateKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1addSource (JNIEnv *, jobject, jlong, jobject, jint);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1isStrong (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1gather (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1setEntropySource (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1enablePredictionResistance (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1setReseedInterval (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1setEntropyLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1random (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1reseed (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1digestLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1mac (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1start (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1update (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1finish (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1reset (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1derive (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1reset (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1setInfo (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1derive (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1setHash (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1derive (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1setupSourceByte (JNIEnv *, jobject, jlong, jbyte);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1setupSourceData (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1random (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1reseed (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1isStrong (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1gather (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setHmac (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1derive (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1reset (JNIEnv *, jobject, jlong, jbyteArray, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setInfo (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1setKdf (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1setCipher (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1reset (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_seedEntropySource_1resetSeed (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_seedEntropySource_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_seedEntropySource_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_seedEntropySource_1isStrong (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_seedEntropySource_1gather (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyMaterialRng_1resetKeyMaterial (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyMaterialRng_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyMaterialRng_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyMaterialRng_1random (JNIEnv *, jobject, jlong, jint);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyMaterialRng_1reseed (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1setAsn1Writer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializePublicKeyInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializePrivateKeyInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializedPublicKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializePublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializedPrivateKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializePrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1setAsn1Reader (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1deserializePublicKeyInplace (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1deserializePrivateKeyInplace (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1deserializePublicKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1deserializePrivateKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1setAsn1Writer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1setDerSerializer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializedPublicKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePublicKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializedPrivateKeyLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePrivateKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1setAsn1Reader (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1setDerDeserializer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1deserializePublicKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1deserializePrivateKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1setEcies (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1keyLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1keyBitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1verifyHash (JNIEnv *, jobject, jlong, jbyteArray, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1exportPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1exportedPublicKeyLen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1importPublicKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1generateEphemeralKey (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1setEcies (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1keyLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1keyBitlen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1generateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1signatureLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1signHash (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1extractPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1exportPrivateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1exportedPrivateKeyLen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1importPrivateKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1computeSharedKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1sharedKeyLen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1setEcies (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1keyLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1keyBitlen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1exportPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1exportedPublicKeyLen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1importPublicKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1generateEphemeralKey (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1setEcies (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1produceAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1restoreAlgInfo (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1keyLen (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1keyBitlen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1generateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1extractPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1exportPrivateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1exportedPrivateKeyLen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1importPrivateKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1computeSharedKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1sharedKeyLen (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setCipher (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setMac (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setKdf (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setEncryptionKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setDecryptionKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setEphemeralKey (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1encryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1decrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1decryptedLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_simpleAlgInfo_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_simpleAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_simpleAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1hashAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_cipherAlgInfo_1nonce (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_cipherAlgInfo_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_cipherAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_cipherAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1hashAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1salt (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1iterationCount (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1kdfAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1cipherAlgInfo (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1algId (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1setAsn1Writer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serializeInplace (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serializedLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serialize (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1setAsn1Reader (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1deserializeInplace (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1deserialize (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setAsn1Reader (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setAsn1Writer (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serializedLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serialize (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1readPrefix (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1deserialize (JNIEnv *, jobject, jlong, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
