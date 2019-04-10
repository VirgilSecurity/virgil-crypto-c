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

#ifndef _Included_RatchetJNI_h
#define _Included_RatchetJNI_h
#ifdef __cplusplus
extern "C" {
#endif
JNIEXPORT jlong JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetKeyUtils_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetKeyUtils_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetKeyUtils_1computePublicKeyId (JNIEnv *, jobject, jlong, jbyteArray, jboolean);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetKeyUtils_1extractRatchetPublicKey (JNIEnv *, jobject, jlong, jbyteArray, jboolean, jboolean, jboolean);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetKeyUtils_1extractRatchetPrivateKey (JNIEnv *, jobject, jlong, jbyteArray, jboolean, jboolean, jboolean);

JNIEXPORT jlong JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetMessage_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetMessage_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetMessage_1getType (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetMessage_1getLongTermPublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetMessage_1getOneTimePublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetMessage_1serializeLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetMessage_1serialize (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetMessage_1deserialize (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1setRng (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1initiate (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1respond (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1isInitiator (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1receivedFirstResponse (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1receiverHasOneTimePublicKey (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1decryptLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1decrypt (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1serializeLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1serialize (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetSession_1deserialize (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1close (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1getType (JNIEnv *, jobject, jlong);

JNIEXPORT jint JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1getPubKeyCount (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1getPubKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1serializeLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1serialize (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1deserialize (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1setRng (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1isInitialized (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1isPrivateKeySet (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1setPrivateKey (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1setupSession (JNIEnv *, jobject, jlong, jbyteArray, jobject);

JNIEXPORT jobject JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1encrypt (JNIEnv *, jobject, jlong, jbyteArray);

JNIEXPORT jint JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1decryptLen (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1decrypt (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1serializeLen (JNIEnv *, jobject, jlong);

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1serialize (JNIEnv *, jobject, jlong);

JNIEXPORT jobject JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupSession_1deserialize (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jlong JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1new (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1close (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1setRng (JNIEnv *, jobject, jlong, jobject);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1setupDefaults (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1addParticipant (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);

JNIEXPORT jobject JNICALL Java_virgil_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1generateTicket (JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif
