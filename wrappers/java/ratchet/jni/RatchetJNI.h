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
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1new__(void);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1close(jlong );

JNIEXPORT jobject JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getType(jlong c_ctx);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getCounter(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getSenderIdentityKeyId(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getReceiverIdentityKeyId(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getReceiverLongTermKeyId(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getReceiverOneTimeKeyId(jlong c_ctx);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1serializeLen(jlong c_ctx);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1serialize(jlong c_ctx);

JNIEXPORT jobject JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1deserialize(jbyteArray jinput);

JNIEXPORT jlong JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1new__(void);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1close(jlong );

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1setupDefaults(jlong c_ctx);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1initiate(jlong c_ctx, jobject jsenderIdentityPrivateKey, jbyteArray jsenderIdentityKeyId, jobject jreceiverIdentityPublicKey, jbyteArray jreceiverIdentityKeyId, jobject jreceiverLongTermPublicKey, jbyteArray jreceiverLongTermKeyId, jobject jreceiverOneTimePublicKey, jbyteArray jreceiverOneTimeKeyId, jboolean jenablePostQuantum);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1initiateNoOneTimeKey(jlong c_ctx, jobject jsenderIdentityPrivateKey, jbyteArray jsenderIdentityKeyId, jobject jreceiverIdentityPublicKey, jbyteArray jreceiverIdentityKeyId, jobject jreceiverLongTermPublicKey, jbyteArray jreceiverLongTermKeyId, jboolean jenablePostQuantum);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1respond(jlong c_ctx, jobject jsenderIdentityPublicKey, jobject jreceiverIdentityPrivateKey, jobject jreceiverLongTermPrivateKey, jobject jreceiverOneTimePrivateKey, jobject jmessage, jboolean jenablePostQuantum);

JNIEXPORT void JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1respondNoOneTimeKey(jlong c_ctx, jobject jsenderIdentityPublicKey, jobject jreceiverIdentityPrivateKey, jobject jreceiverLongTermPrivateKey, jobject jmessage, jboolean jenablePostQuantum);

JNIEXPORT jboolean JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1isInitiator(jlong c_ctx);

JNIEXPORT jboolean JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1isPqcEnabled(jlong c_ctx);

JNIEXPORT jboolean JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1receivedFirstResponse(jlong c_ctx);

JNIEXPORT jboolean JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1receiverHasOneTimePublicKey(jlong c_ctx);

JNIEXPORT jobject JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1encrypt(jlong c_ctx, jbyteArray jplainText);

JNIEXPORT jint JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1decryptLen(jlong c_ctx, jobject jmessage);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1decrypt(jlong c_ctx, jobject jmessage);

JNIEXPORT jbyteArray JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1serialize(jlong c_ctx);

JNIEXPORT jobject JNICALL
Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1deserialize(jbyteArray jinput);
