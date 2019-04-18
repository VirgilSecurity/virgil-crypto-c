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

#ifndef _Included_PythiaJNI_h
#define _Included_PythiaJNI_h
#ifdef __cplusplus
extern "C" {
#endif
JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1configure (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1cleanup (JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1blindedPasswordBufLen (JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1deblindedPasswordBufLen (JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1blindingSecretBufLen (JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformationPrivateKeyBufLen (JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformationPublicKeyBufLen (JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformedPasswordBufLen (JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformedTweakBufLen (JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1proofValueBufLen (JNIEnv *, jobject);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1passwordUpdateTokenBufLen (JNIEnv *, jobject);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1blind (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1deblind (JNIEnv *, jobject, jbyteArray, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1computeTransformationKeyPair (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transform (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1prove (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1verify (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1getPasswordUpdateToken (JNIEnv *, jobject, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1updateDeblindedWithToken (JNIEnv *, jobject, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
