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

#ifndef _Included_RatchetJNI_h
#define _Included_RatchetJNI_h
#ifdef __cplusplus
extern "C" {
#endif
JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getType (JNIEnv *, jobject, jlong);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getCounter (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getSenderIdentityKeyId (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getReceiverIdentityKeyId (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getReceiverLongTermKeyId (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getReceiverOneTimeKeyId (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1serializeLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1serialize (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1deserialize (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1new__ (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1setRng (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1initiate (JNIEnv *, jobject, jlong, jobject, jbyteArray, jobject, jbyteArray, jobject, jbyteArray, jobject, jbyteArray, jboolean);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1initiateNoOneTimeKey (JNIEnv *, jobject, jlong, jobject, jbyteArray, jobject, jbyteArray, jobject, jbyteArray, jboolean);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1respond (JNIEnv *, jobject, jlong, jobject, jobject, jobject, jobject, jobject, jboolean);

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1respondNoOneTimeKey (JNIEnv *, jobject, jlong, jobject, jobject, jobject, jobject, jboolean);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1isInitiator (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1isPqcEnabled (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1receivedFirstResponse (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1receiverHasOneTimePublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1decryptLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1decrypt (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1serialize (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1deserialize (JNIEnv *, jobject, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
