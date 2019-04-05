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

#ifndef _Included_PheJNI_h
#define _Included_PheJNI_h
#ifdef __cplusplus
extern "C" {
#endif
JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1setOperationRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1generateServerKeyPair (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1enrollmentResponseLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1getEnrollment (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1verifyPasswordResponseLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1verifyPassword (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1updateTokenLen (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1rotateKeys (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1setOperationRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1setKeys (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1generateClientPrivateKey (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1enrollmentRecordLen (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1enrollAccount (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1verifyPasswordRequestLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1createVerifyPasswordRequest (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1checkResponseAndDecrypt (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1rotateKeys (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1updateEnrollmentRecord (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1setRandom (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1encryptLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1decryptLen (JNIEnv *, jobject, jlong, jint);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1encrypt (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1decrypt (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
