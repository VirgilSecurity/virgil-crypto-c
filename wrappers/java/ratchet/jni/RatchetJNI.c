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

#include "RatchetJNI.h"

#include "vscr_ratchet_public.h"

#include <string.h>

jint throwRatchetException (JNIEnv *jenv, jobject jobj, jint statusCode) {
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetException");
    if (NULL == cls) {
        VSCR_ASSERT("Class PheException not found.");
        return 0;
    }

    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");
    if (NULL == methodID) {
        VSCR_ASSERT("Class com/virgilsecurity/crypto/ratchet/RatchetException has no constructor.");
        return 0;
    }
    jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);
    if (NULL == obj) {
        VSCR_ASSERT("Can't instantiate com/virgilsecurity/crypto/ratchet/RatchetException.");
        return 0;
    }
    return (*jenv)->Throw(jenv, obj);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscr_ratchet_message_t **)&c_ctx = vscr_ratchet_message_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_message_delete(*(vscr_ratchet_message_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getType (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

    const vscr_msg_type_t proxyResult = vscr_ratchet_message_get_type(ratchet_message_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/MsgType");
    if (NULL == cls) {
        VSCR_ASSERT("Enum MsgType not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/ratchet/MsgType;");
    if (NULL == methodID) {
        VSCR_ASSERT("Enum MsgType has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getCounter (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

    jlong ret = (jlong) vscr_ratchet_message_get_counter(ratchet_message_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getSenderIdentityKeyId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_sender_identity_key_id(ratchet_message_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getReceiverIdentityKeyId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_receiver_identity_key_id(ratchet_message_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getReceiverLongTermKeyId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_receiver_long_term_key_id(ratchet_message_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getReceiverOneTimeKeyId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_receiver_one_time_key_id(ratchet_message_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1serializeLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

    jint ret = (jint) vscr_ratchet_message_serialize_len(ratchet_message_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *output = vsc_buffer_new_with_capacity(vscr_ratchet_message_serialize_len((vscr_ratchet_message_t /*2*/ *) c_ctx /*3*/));

    vscr_ratchet_message_serialize(ratchet_message_ctx /*a1*/, output /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(output));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(output), (jbyte*) vsc_buffer_bytes(output));
    // Free resources
    vsc_buffer_delete(output);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1deserialize (JNIEnv *jenv, jobject jobj, jbyteArray jinput) {
    // Wrap errors
    struct vscr_error_t /*4*/ error;
    vscr_error_reset(&error);
    // Wrap input data
    byte* input_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinput, NULL);
    vsc_data_t input = vsc_data(input_arr, (*jenv)->GetArrayLength(jenv, jinput));

    const vscr_ratchet_message_t */*5*/ proxyResult = vscr_ratchet_message_deserialize(input /*a3*/, &error /*a4*/);

    if (error.status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
    if (NULL == result_cls) {
        VSCR_ASSERT("Class RatchetMessage not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/RatchetMessage;");
    if (NULL == result_methodID) {
        VSCR_ASSERT("Class RatchetMessage has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jinput, (jbyte*) input_arr, 0);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscr_ratchet_session_t **)&c_ctx = vscr_ratchet_session_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_session_delete(*(vscr_ratchet_session_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1setRng (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrng) {
    jclass rng_cls = (*jenv)->GetObjectClass(jenv, jrng);
    if (NULL == rng_cls) {
        VSCR_ASSERT("Class Random not found.");
    }
    jfieldID rng_fidCtx = (*jenv)->GetFieldID(jenv, rng_cls, "cCtx", "J");
    if (NULL == rng_fidCtx) {
        VSCR_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong rng_c_ctx = (*jenv)->GetLongField(jenv, jrng, rng_fidCtx);
    vscf_impl_t */*6*/ rng = *(vscf_impl_t */*6*/*) &rng_c_ctx;

    vscr_ratchet_session_release_rng((vscr_ratchet_session_t /*2*/ *) c_ctx);
    vscr_ratchet_session_use_rng((vscr_ratchet_session_t /*2*/ *) c_ctx, rng);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

    vscr_status_t status = vscr_ratchet_session_setup_defaults(ratchet_session_ctx /*a1*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1initiate (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jsenderIdentityPrivateKey, jbyteArray jsenderIdentityKeyId, jobject jreceiverIdentityPublicKey, jbyteArray jreceiverIdentityKeyId, jobject jreceiverLongTermPublicKey, jbyteArray jreceiverLongTermKeyId, jobject jreceiverOneTimePublicKey, jbyteArray jreceiverOneTimeKeyId, jboolean jenablePostQuantum) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass sender_identity_private_key_cls = (*jenv)->GetObjectClass(jenv, jsenderIdentityPrivateKey);
    if (NULL == sender_identity_private_key_cls) {
        VSCR_ASSERT("Class PrivateKey not found.");
    }
    jfieldID sender_identity_private_key_fidCtx = (*jenv)->GetFieldID(jenv, sender_identity_private_key_cls, "cCtx", "J");
    if (NULL == sender_identity_private_key_fidCtx) {
        VSCR_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong sender_identity_private_key_c_ctx = (*jenv)->GetLongField(jenv, jsenderIdentityPrivateKey, sender_identity_private_key_fidCtx);
    vscf_impl_t */*6*/ sender_identity_private_key = *(vscf_impl_t */*6*/*)&sender_identity_private_key_c_ctx;

    jclass receiver_identity_public_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverIdentityPublicKey);
    if (NULL == receiver_identity_public_key_cls) {
        VSCR_ASSERT("Class PublicKey not found.");
    }
    jfieldID receiver_identity_public_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_identity_public_key_cls, "cCtx", "J");
    if (NULL == receiver_identity_public_key_fidCtx) {
        VSCR_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong receiver_identity_public_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverIdentityPublicKey, receiver_identity_public_key_fidCtx);
    vscf_impl_t */*6*/ receiver_identity_public_key = *(vscf_impl_t */*6*/*)&receiver_identity_public_key_c_ctx;

    jclass receiver_long_term_public_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverLongTermPublicKey);
    if (NULL == receiver_long_term_public_key_cls) {
        VSCR_ASSERT("Class PublicKey not found.");
    }
    jfieldID receiver_long_term_public_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_long_term_public_key_cls, "cCtx", "J");
    if (NULL == receiver_long_term_public_key_fidCtx) {
        VSCR_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong receiver_long_term_public_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverLongTermPublicKey, receiver_long_term_public_key_fidCtx);
    vscf_impl_t */*6*/ receiver_long_term_public_key = *(vscf_impl_t */*6*/*)&receiver_long_term_public_key_c_ctx;

    jclass receiver_one_time_public_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverOneTimePublicKey);
    if (NULL == receiver_one_time_public_key_cls) {
        VSCR_ASSERT("Class PublicKey not found.");
    }
    jfieldID receiver_one_time_public_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_one_time_public_key_cls, "cCtx", "J");
    if (NULL == receiver_one_time_public_key_fidCtx) {
        VSCR_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong receiver_one_time_public_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverOneTimePublicKey, receiver_one_time_public_key_fidCtx);
    vscf_impl_t */*6*/ receiver_one_time_public_key = *(vscf_impl_t */*6*/*)&receiver_one_time_public_key_c_ctx;

    // Wrap input data
    byte* sender_identity_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsenderIdentityKeyId, NULL);
    vsc_data_t sender_identity_key_id = vsc_data(sender_identity_key_id_arr, (*jenv)->GetArrayLength(jenv, jsenderIdentityKeyId));

    byte* receiver_identity_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverIdentityKeyId, NULL);
    vsc_data_t receiver_identity_key_id = vsc_data(receiver_identity_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverIdentityKeyId));

    byte* receiver_long_term_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverLongTermKeyId, NULL);
    vsc_data_t receiver_long_term_key_id = vsc_data(receiver_long_term_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverLongTermKeyId));

    byte* receiver_one_time_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverOneTimeKeyId, NULL);
    vsc_data_t receiver_one_time_key_id = vsc_data(receiver_one_time_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverOneTimeKeyId));

    vscr_status_t status = vscr_ratchet_session_initiate(ratchet_session_ctx /*a1*/, sender_identity_private_key /*a6*/, sender_identity_key_id /*a3*/, receiver_identity_public_key /*a6*/, receiver_identity_key_id /*a3*/, receiver_long_term_public_key /*a6*/, receiver_long_term_key_id /*a3*/, receiver_one_time_public_key /*a6*/, receiver_one_time_key_id /*a3*/, jenablePostQuantum /*a9*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsenderIdentityKeyId, (jbyte*) sender_identity_key_id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverIdentityKeyId, (jbyte*) receiver_identity_key_id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverLongTermKeyId, (jbyte*) receiver_long_term_key_id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverOneTimeKeyId, (jbyte*) receiver_one_time_key_id_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1initiateNoOneTimeKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jsenderIdentityPrivateKey, jbyteArray jsenderIdentityKeyId, jobject jreceiverIdentityPublicKey, jbyteArray jreceiverIdentityKeyId, jobject jreceiverLongTermPublicKey, jbyteArray jreceiverLongTermKeyId, jboolean jenablePostQuantum) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass sender_identity_private_key_cls = (*jenv)->GetObjectClass(jenv, jsenderIdentityPrivateKey);
    if (NULL == sender_identity_private_key_cls) {
        VSCR_ASSERT("Class PrivateKey not found.");
    }
    jfieldID sender_identity_private_key_fidCtx = (*jenv)->GetFieldID(jenv, sender_identity_private_key_cls, "cCtx", "J");
    if (NULL == sender_identity_private_key_fidCtx) {
        VSCR_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong sender_identity_private_key_c_ctx = (*jenv)->GetLongField(jenv, jsenderIdentityPrivateKey, sender_identity_private_key_fidCtx);
    vscf_impl_t */*6*/ sender_identity_private_key = *(vscf_impl_t */*6*/*)&sender_identity_private_key_c_ctx;

    jclass receiver_identity_public_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverIdentityPublicKey);
    if (NULL == receiver_identity_public_key_cls) {
        VSCR_ASSERT("Class PublicKey not found.");
    }
    jfieldID receiver_identity_public_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_identity_public_key_cls, "cCtx", "J");
    if (NULL == receiver_identity_public_key_fidCtx) {
        VSCR_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong receiver_identity_public_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverIdentityPublicKey, receiver_identity_public_key_fidCtx);
    vscf_impl_t */*6*/ receiver_identity_public_key = *(vscf_impl_t */*6*/*)&receiver_identity_public_key_c_ctx;

    jclass receiver_long_term_public_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverLongTermPublicKey);
    if (NULL == receiver_long_term_public_key_cls) {
        VSCR_ASSERT("Class PublicKey not found.");
    }
    jfieldID receiver_long_term_public_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_long_term_public_key_cls, "cCtx", "J");
    if (NULL == receiver_long_term_public_key_fidCtx) {
        VSCR_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong receiver_long_term_public_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverLongTermPublicKey, receiver_long_term_public_key_fidCtx);
    vscf_impl_t */*6*/ receiver_long_term_public_key = *(vscf_impl_t */*6*/*)&receiver_long_term_public_key_c_ctx;

    // Wrap input data
    byte* sender_identity_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsenderIdentityKeyId, NULL);
    vsc_data_t sender_identity_key_id = vsc_data(sender_identity_key_id_arr, (*jenv)->GetArrayLength(jenv, jsenderIdentityKeyId));

    byte* receiver_identity_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverIdentityKeyId, NULL);
    vsc_data_t receiver_identity_key_id = vsc_data(receiver_identity_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverIdentityKeyId));

    byte* receiver_long_term_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverLongTermKeyId, NULL);
    vsc_data_t receiver_long_term_key_id = vsc_data(receiver_long_term_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverLongTermKeyId));

    vscr_status_t status = vscr_ratchet_session_initiate_no_one_time_key(ratchet_session_ctx /*a1*/, sender_identity_private_key /*a6*/, sender_identity_key_id /*a3*/, receiver_identity_public_key /*a6*/, receiver_identity_key_id /*a3*/, receiver_long_term_public_key /*a6*/, receiver_long_term_key_id /*a3*/, jenablePostQuantum /*a9*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsenderIdentityKeyId, (jbyte*) sender_identity_key_id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverIdentityKeyId, (jbyte*) receiver_identity_key_id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverLongTermKeyId, (jbyte*) receiver_long_term_key_id_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1respond (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jsenderIdentityPublicKey, jobject jreceiverIdentityPrivateKey, jobject jreceiverLongTermPrivateKey, jobject jreceiverOneTimePrivateKey, jobject jmessage, jboolean jenablePostQuantum) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass sender_identity_public_key_cls = (*jenv)->GetObjectClass(jenv, jsenderIdentityPublicKey);
    if (NULL == sender_identity_public_key_cls) {
        VSCR_ASSERT("Class PublicKey not found.");
    }
    jfieldID sender_identity_public_key_fidCtx = (*jenv)->GetFieldID(jenv, sender_identity_public_key_cls, "cCtx", "J");
    if (NULL == sender_identity_public_key_fidCtx) {
        VSCR_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong sender_identity_public_key_c_ctx = (*jenv)->GetLongField(jenv, jsenderIdentityPublicKey, sender_identity_public_key_fidCtx);
    vscf_impl_t */*6*/ sender_identity_public_key = *(vscf_impl_t */*6*/*)&sender_identity_public_key_c_ctx;

    jclass receiver_identity_private_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverIdentityPrivateKey);
    if (NULL == receiver_identity_private_key_cls) {
        VSCR_ASSERT("Class PrivateKey not found.");
    }
    jfieldID receiver_identity_private_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_identity_private_key_cls, "cCtx", "J");
    if (NULL == receiver_identity_private_key_fidCtx) {
        VSCR_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong receiver_identity_private_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverIdentityPrivateKey, receiver_identity_private_key_fidCtx);
    vscf_impl_t */*6*/ receiver_identity_private_key = *(vscf_impl_t */*6*/*)&receiver_identity_private_key_c_ctx;

    jclass receiver_long_term_private_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverLongTermPrivateKey);
    if (NULL == receiver_long_term_private_key_cls) {
        VSCR_ASSERT("Class PrivateKey not found.");
    }
    jfieldID receiver_long_term_private_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_long_term_private_key_cls, "cCtx", "J");
    if (NULL == receiver_long_term_private_key_fidCtx) {
        VSCR_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong receiver_long_term_private_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverLongTermPrivateKey, receiver_long_term_private_key_fidCtx);
    vscf_impl_t */*6*/ receiver_long_term_private_key = *(vscf_impl_t */*6*/*)&receiver_long_term_private_key_c_ctx;

    jclass receiver_one_time_private_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverOneTimePrivateKey);
    if (NULL == receiver_one_time_private_key_cls) {
        VSCR_ASSERT("Class PrivateKey not found.");
    }
    jfieldID receiver_one_time_private_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_one_time_private_key_cls, "cCtx", "J");
    if (NULL == receiver_one_time_private_key_fidCtx) {
        VSCR_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong receiver_one_time_private_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverOneTimePrivateKey, receiver_one_time_private_key_fidCtx);
    vscf_impl_t */*6*/ receiver_one_time_private_key = *(vscf_impl_t */*6*/*)&receiver_one_time_private_key_c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetMessage' has no field 'cCtx'.");
    }
    jlong message_c_ctx = (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);
    vscr_ratchet_message_t */*5*/ message = *(vscr_ratchet_message_t */*5*/*) &message_c_ctx;

    vscr_status_t status = vscr_ratchet_session_respond(ratchet_session_ctx /*a1*/, sender_identity_public_key /*a6*/, receiver_identity_private_key /*a6*/, receiver_long_term_private_key /*a6*/, receiver_one_time_private_key /*a6*/, message /*a6*/, jenablePostQuantum /*a9*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1respondNoOneTimeKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jsenderIdentityPublicKey, jobject jreceiverIdentityPrivateKey, jobject jreceiverLongTermPrivateKey, jobject jmessage, jboolean jenablePostQuantum) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass sender_identity_public_key_cls = (*jenv)->GetObjectClass(jenv, jsenderIdentityPublicKey);
    if (NULL == sender_identity_public_key_cls) {
        VSCR_ASSERT("Class PublicKey not found.");
    }
    jfieldID sender_identity_public_key_fidCtx = (*jenv)->GetFieldID(jenv, sender_identity_public_key_cls, "cCtx", "J");
    if (NULL == sender_identity_public_key_fidCtx) {
        VSCR_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong sender_identity_public_key_c_ctx = (*jenv)->GetLongField(jenv, jsenderIdentityPublicKey, sender_identity_public_key_fidCtx);
    vscf_impl_t */*6*/ sender_identity_public_key = *(vscf_impl_t */*6*/*)&sender_identity_public_key_c_ctx;

    jclass receiver_identity_private_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverIdentityPrivateKey);
    if (NULL == receiver_identity_private_key_cls) {
        VSCR_ASSERT("Class PrivateKey not found.");
    }
    jfieldID receiver_identity_private_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_identity_private_key_cls, "cCtx", "J");
    if (NULL == receiver_identity_private_key_fidCtx) {
        VSCR_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong receiver_identity_private_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverIdentityPrivateKey, receiver_identity_private_key_fidCtx);
    vscf_impl_t */*6*/ receiver_identity_private_key = *(vscf_impl_t */*6*/*)&receiver_identity_private_key_c_ctx;

    jclass receiver_long_term_private_key_cls = (*jenv)->GetObjectClass(jenv, jreceiverLongTermPrivateKey);
    if (NULL == receiver_long_term_private_key_cls) {
        VSCR_ASSERT("Class PrivateKey not found.");
    }
    jfieldID receiver_long_term_private_key_fidCtx = (*jenv)->GetFieldID(jenv, receiver_long_term_private_key_cls, "cCtx", "J");
    if (NULL == receiver_long_term_private_key_fidCtx) {
        VSCR_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong receiver_long_term_private_key_c_ctx = (*jenv)->GetLongField(jenv, jreceiverLongTermPrivateKey, receiver_long_term_private_key_fidCtx);
    vscf_impl_t */*6*/ receiver_long_term_private_key = *(vscf_impl_t */*6*/*)&receiver_long_term_private_key_c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetMessage' has no field 'cCtx'.");
    }
    jlong message_c_ctx = (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);
    vscr_ratchet_message_t */*5*/ message = *(vscr_ratchet_message_t */*5*/*) &message_c_ctx;

    vscr_status_t status = vscr_ratchet_session_respond_no_one_time_key(ratchet_session_ctx /*a1*/, sender_identity_public_key /*a6*/, receiver_identity_private_key /*a6*/, receiver_long_term_private_key /*a6*/, message /*a6*/, jenablePostQuantum /*a9*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1isInitiator (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_session_is_initiator(ratchet_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1isPqcEnabled (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_session_is_pqc_enabled(ratchet_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1receivedFirstResponse (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_session_received_first_response(ratchet_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1receiverHasOneTimePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_session_receiver_has_one_time_public_key(ratchet_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jplainText) {
    // Wrap errors
    struct vscr_error_t /*4*/ error;
    vscr_error_reset(&error);
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* plain_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jplainText, NULL);
    vsc_data_t plain_text = vsc_data(plain_text_arr, (*jenv)->GetArrayLength(jenv, jplainText));

    const vscr_ratchet_message_t */*5*/ proxyResult = vscr_ratchet_session_encrypt(ratchet_session_ctx /*a1*/, plain_text /*a3*/, &error /*a4*/);

    if (error.status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
    if (NULL == result_cls) {
        VSCR_ASSERT("Class RatchetMessage not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/RatchetMessage;");
    if (NULL == result_methodID) {
        VSCR_ASSERT("Class RatchetMessage has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jplainText, (jbyte*) plain_text_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1decryptLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetMessage' has no field 'cCtx'.");
    }
    jlong message_c_ctx = (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);
    vscr_ratchet_message_t */*5*/ message = *(vscr_ratchet_message_t */*5*/*) &message_c_ctx;

    jint ret = (jint) vscr_ratchet_session_decrypt_len(ratchet_session_ctx /*a1*/, message /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetMessage' has no field 'cCtx'.");
    }
    jlong message_c_ctx = (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);
    vscr_ratchet_message_t */*5*/ message = *(vscr_ratchet_message_t */*5*/*) &message_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vscr_ratchet_session_decrypt_len((vscr_ratchet_session_t /*2*/ *) c_ctx /*3*/, message/*a*/));

    vscr_status_t status = vscr_ratchet_session_decrypt(ratchet_session_ctx /*a1*/, message /*a6*/, plain_text /*a3*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), (jbyte*) vsc_buffer_bytes(plain_text));
    // Free resources
    vsc_buffer_delete(plain_text);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

    const vsc_buffer_t */*5*/ proxyResult = vscr_ratchet_session_serialize(ratchet_session_ctx /*a1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(proxyResult));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(proxyResult), (jbyte*) vsc_buffer_bytes(proxyResult));
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1deserialize (JNIEnv *jenv, jobject jobj, jbyteArray jinput) {
    // Wrap errors
    struct vscr_error_t /*4*/ error;
    vscr_error_reset(&error);
    // Wrap input data
    byte* input_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinput, NULL);
    vsc_data_t input = vsc_data(input_arr, (*jenv)->GetArrayLength(jenv, jinput));

    const vscr_ratchet_session_t */*5*/ proxyResult = vscr_ratchet_session_deserialize(input /*a3*/, &error /*a4*/);

    if (error.status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetSession");
    if (NULL == result_cls) {
        VSCR_ASSERT("Class RatchetSession not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/RatchetSession;");
    if (NULL == result_methodID) {
        VSCR_ASSERT("Class RatchetSession has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jinput, (jbyte*) input_arr, 0);

    return ret;
}

