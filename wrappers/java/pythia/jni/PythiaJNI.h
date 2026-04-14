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

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1configure(void);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1cleanup(void);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1blindedPasswordBufLen(void);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1deblindedPasswordBufLen(void);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1blindingSecretBufLen(void);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformationPrivateKeyBufLen(void);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformationPublicKeyBufLen(void);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformedPasswordBufLen(void);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformedTweakBufLen(void);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1proofValueBufLen(void);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1passwordUpdateTokenBufLen(void);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1blind(jbyteArray jpassword);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1deblind(jbyteArray jtransformedPassword, jbyteArray jblindingSecret);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1computeTransformationKeyPair(jbyteArray jtransformationKeyId, jbyteArray jpythiaSecret, jbyteArray jpythiaScopeSecret);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transform(jbyteArray jblindedPassword, jbyteArray jtweak, jbyteArray jtransformationPrivateKey);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1prove(jbyteArray jtransformedPassword, jbyteArray jblindedPassword, jbyteArray jtransformedTweak, jbyteArray jtransformationPrivateKey, jbyteArray jtransformationPublicKey);

JNIEXPORT jboolean JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1verify(jbyteArray jtransformedPassword, jbyteArray jblindedPassword, jbyteArray jtweak, jbyteArray jtransformationPublicKey, jbyteArray jproofValueC, jbyteArray jproofValueU);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1getPasswordUpdateToken(jbyteArray jpreviousTransformationPrivateKey, jbyteArray jnewTransformationPrivateKey);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1updateDeblindedWithToken(jbyteArray jdeblindedPassword, jbyteArray jpasswordUpdateToken);
