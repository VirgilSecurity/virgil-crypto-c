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

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetKeyId_1new__ (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscr_ratchet_key_id_new();
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetKeyId_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_key_id_delete((vscr_ratchet_key_id_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetKeyId_1computePublicKeyId (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpublicKey) {
    // Cast class context
    vscr_ratchet_key_id_t /*2*/* ratchet_key_id_ctx = (vscr_ratchet_key_id_t /*2*/*) c_ctx;

    // Wrap input data
    byte* public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpublicKey, NULL);
    vsc_data_t public_key = vsc_data(public_key_arr, (*jenv)->GetArrayLength(jenv, jpublicKey));

    vsc_buffer_t *key_id = vsc_buffer_new_with_capacity(vscr_ratchet_common_KEY_ID_LEN);

    vscr_status_t status = vscr_ratchet_key_id_compute_public_key_id(ratchet_key_id_ctx /*a1*/, public_key /*a3*/, key_id /*a3*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key_id));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key_id), (jbyte*) vsc_buffer_bytes(key_id));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpublicKey, (jbyte*) public_key_arr, 0);

    vsc_buffer_delete(key_id);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1new__ (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscr_ratchet_message_new();
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_message_delete((vscr_ratchet_message_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getType (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = (vscr_ratchet_message_t /*2*/*) c_ctx;

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
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = (vscr_ratchet_message_t /*2*/*) c_ctx;

    jlong ret = (jlong) vscr_ratchet_message_get_counter(ratchet_message_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getLongTermPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = (vscr_ratchet_message_t /*2*/*) c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_long_term_public_key(ratchet_message_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1getOneTimePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = (vscr_ratchet_message_t /*2*/*) c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_one_time_public_key(ratchet_message_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1serializeLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = (vscr_ratchet_message_t /*2*/*) c_ctx;

    jint ret = (jint) vscr_ratchet_message_serialize_len(ratchet_message_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetMessage_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_message_t /*2*/* ratchet_message_ctx = (vscr_ratchet_message_t /*2*/*) c_ctx;

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
    return (jlong) vscr_ratchet_session_new();
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_session_delete((vscr_ratchet_session_t /*2*/ *) c_ctx /*5*/);
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
    vscf_impl_t */*6*/ rng = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrng, rng_fidCtx);

    vscr_ratchet_session_release_rng((vscr_ratchet_session_t /*2*/ *) c_ctx);
    vscr_ratchet_session_use_rng((vscr_ratchet_session_t /*2*/ *) c_ctx, rng);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;

    vscr_status_t status = vscr_ratchet_session_setup_defaults(ratchet_session_ctx /*a1*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1initiate (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsenderIdentityPrivateKey, jbyteArray jreceiverIdentityPublicKey, jbyteArray jreceiverLongTermPublicKey, jbyteArray jreceiverOneTimePublicKey) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;

    // Wrap input data
    byte* sender_identity_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsenderIdentityPrivateKey, NULL);
    vsc_data_t sender_identity_private_key = vsc_data(sender_identity_private_key_arr, (*jenv)->GetArrayLength(jenv, jsenderIdentityPrivateKey));

    byte* receiver_identity_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverIdentityPublicKey, NULL);
    vsc_data_t receiver_identity_public_key = vsc_data(receiver_identity_public_key_arr, (*jenv)->GetArrayLength(jenv, jreceiverIdentityPublicKey));

    byte* receiver_long_term_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverLongTermPublicKey, NULL);
    vsc_data_t receiver_long_term_public_key = vsc_data(receiver_long_term_public_key_arr, (*jenv)->GetArrayLength(jenv, jreceiverLongTermPublicKey));

    byte* receiver_one_time_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverOneTimePublicKey, NULL);
    vsc_data_t receiver_one_time_public_key = vsc_data(receiver_one_time_public_key_arr, (*jenv)->GetArrayLength(jenv, jreceiverOneTimePublicKey));

    vscr_status_t status = vscr_ratchet_session_initiate(ratchet_session_ctx /*a1*/, sender_identity_private_key /*a3*/, receiver_identity_public_key /*a3*/, receiver_long_term_public_key /*a3*/, receiver_one_time_public_key /*a3*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsenderIdentityPrivateKey, (jbyte*) sender_identity_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverIdentityPublicKey, (jbyte*) receiver_identity_public_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverLongTermPublicKey, (jbyte*) receiver_long_term_public_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverOneTimePublicKey, (jbyte*) receiver_one_time_public_key_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1respond (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsenderIdentityPublicKey, jbyteArray jreceiverIdentityPrivateKey, jbyteArray jreceiverLongTermPrivateKey, jbyteArray jreceiverOneTimePrivateKey, jobject jmessage) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetMessage' has no field 'cCtx'.");
    }
    vscr_ratchet_message_t */*5*/ message = (vscr_ratchet_message_t */*5*/) (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);

    // Wrap input data
    byte* sender_identity_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsenderIdentityPublicKey, NULL);
    vsc_data_t sender_identity_public_key = vsc_data(sender_identity_public_key_arr, (*jenv)->GetArrayLength(jenv, jsenderIdentityPublicKey));

    byte* receiver_identity_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverIdentityPrivateKey, NULL);
    vsc_data_t receiver_identity_private_key = vsc_data(receiver_identity_private_key_arr, (*jenv)->GetArrayLength(jenv, jreceiverIdentityPrivateKey));

    byte* receiver_long_term_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverLongTermPrivateKey, NULL);
    vsc_data_t receiver_long_term_private_key = vsc_data(receiver_long_term_private_key_arr, (*jenv)->GetArrayLength(jenv, jreceiverLongTermPrivateKey));

    byte* receiver_one_time_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverOneTimePrivateKey, NULL);
    vsc_data_t receiver_one_time_private_key = vsc_data(receiver_one_time_private_key_arr, (*jenv)->GetArrayLength(jenv, jreceiverOneTimePrivateKey));

    vscr_status_t status = vscr_ratchet_session_respond(ratchet_session_ctx /*a1*/, sender_identity_public_key /*a3*/, receiver_identity_private_key /*a3*/, receiver_long_term_private_key /*a3*/, receiver_one_time_private_key /*a3*/, message /*a6*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsenderIdentityPublicKey, (jbyte*) sender_identity_public_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverIdentityPrivateKey, (jbyte*) receiver_identity_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverLongTermPrivateKey, (jbyte*) receiver_long_term_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jreceiverOneTimePrivateKey, (jbyte*) receiver_one_time_private_key_arr, 0);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1isInitiator (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_session_is_initiator(ratchet_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1receivedFirstResponse (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_session_received_first_response(ratchet_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1receiverHasOneTimePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_session_receiver_has_one_time_public_key(ratchet_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jplainText) {
    // Wrap errors
    struct vscr_error_t /*4*/ error;
    vscr_error_reset(&error);
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;

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
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetMessage' has no field 'cCtx'.");
    }
    vscr_ratchet_message_t */*5*/ message = (vscr_ratchet_message_t */*5*/) (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);

    jint ret = (jint) vscr_ratchet_session_decrypt_len(ratchet_session_ctx /*a1*/, message /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetSession_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage) {
    // Cast class context
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetMessage' has no field 'cCtx'.");
    }
    vscr_ratchet_message_t */*5*/ message = (vscr_ratchet_message_t */*5*/) (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);

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
    vscr_ratchet_session_t /*2*/* ratchet_session_ctx = (vscr_ratchet_session_t /*2*/*) c_ctx;

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

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupParticipantsInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscr_ratchet_group_participants_info_new();
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupParticipantsInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_group_participants_info_delete((vscr_ratchet_group_participants_info_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupParticipantsInfo_1new__J (JNIEnv *jenv, jobject jobj, jlong jsize) {
    jlong proxyResult = (jlong) vscr_ratchet_group_participants_info_new_size(jsize /*a9*/);
    return proxyResult;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupParticipantsInfo_1addParticipant (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jid, jbyteArray jpubKey) {
    // Cast class context
    vscr_ratchet_group_participants_info_t /*2*/* ratchet_group_participants_info_ctx = (vscr_ratchet_group_participants_info_t /*2*/*) c_ctx;

    // Wrap input data
    byte* id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jid, NULL);
    vsc_data_t id = vsc_data(id_arr, (*jenv)->GetArrayLength(jenv, jid));

    byte* pub_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpubKey, NULL);
    vsc_data_t pub_key = vsc_data(pub_key_arr, (*jenv)->GetArrayLength(jenv, jpubKey));

    vscr_status_t status = vscr_ratchet_group_participants_info_add_participant(ratchet_group_participants_info_ctx /*a1*/, id /*a3*/, pub_key /*a3*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jid, (jbyte*) id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jpubKey, (jbyte*) pub_key_arr, 0);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1new__ (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscr_ratchet_group_message_new();
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_group_message_delete((vscr_ratchet_group_message_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1getType (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_message_t /*2*/* ratchet_group_message_ctx = (vscr_ratchet_group_message_t /*2*/*) c_ctx;

    const vscr_group_msg_type_t proxyResult = vscr_ratchet_group_message_get_type(ratchet_group_message_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/GroupMsgType");
    if (NULL == cls) {
        VSCR_ASSERT("Enum GroupMsgType not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/ratchet/GroupMsgType;");
    if (NULL == methodID) {
        VSCR_ASSERT("Enum GroupMsgType has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1getSessionId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_message_t /*2*/* ratchet_group_message_ctx = (vscr_ratchet_group_message_t /*2*/*) c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_group_message_get_session_id(ratchet_group_message_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1getSenderId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_message_t /*2*/* ratchet_group_message_ctx = (vscr_ratchet_group_message_t /*2*/*) c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_group_message_get_sender_id(ratchet_group_message_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1getCounter (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_message_t /*2*/* ratchet_group_message_ctx = (vscr_ratchet_group_message_t /*2*/*) c_ctx;

    jlong ret = (jlong) vscr_ratchet_group_message_get_counter(ratchet_group_message_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1getEpoch (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_message_t /*2*/* ratchet_group_message_ctx = (vscr_ratchet_group_message_t /*2*/*) c_ctx;

    jlong ret = (jlong) vscr_ratchet_group_message_get_epoch(ratchet_group_message_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1serializeLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_message_t /*2*/* ratchet_group_message_ctx = (vscr_ratchet_group_message_t /*2*/*) c_ctx;

    jint ret = (jint) vscr_ratchet_group_message_serialize_len(ratchet_group_message_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_message_t /*2*/* ratchet_group_message_ctx = (vscr_ratchet_group_message_t /*2*/*) c_ctx;

    // Wrap input buffers
    vsc_buffer_t *output = vsc_buffer_new_with_capacity(vscr_ratchet_group_message_serialize_len((vscr_ratchet_group_message_t /*2*/ *) c_ctx /*3*/));

    vscr_ratchet_group_message_serialize(ratchet_group_message_ctx /*a1*/, output /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(output));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(output), (jbyte*) vsc_buffer_bytes(output));
    // Free resources
    vsc_buffer_delete(output);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupMessage_1deserialize (JNIEnv *jenv, jobject jobj, jbyteArray jinput) {
    // Wrap errors
    struct vscr_error_t /*4*/ error;
    vscr_error_reset(&error);
    // Wrap input data
    byte* input_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinput, NULL);
    vsc_data_t input = vsc_data(input_arr, (*jenv)->GetArrayLength(jenv, jinput));

    const vscr_ratchet_group_message_t */*5*/ proxyResult = vscr_ratchet_group_message_deserialize(input /*a3*/, &error /*a4*/);

    if (error.status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupMessage");
    if (NULL == result_cls) {
        VSCR_ASSERT("Class RatchetGroupMessage not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/RatchetGroupMessage;");
    if (NULL == result_methodID) {
        VSCR_ASSERT("Class RatchetGroupMessage has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jinput, (jbyte*) input_arr, 0);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1new__ (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscr_ratchet_group_ticket_new();
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_group_ticket_delete((vscr_ratchet_group_ticket_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1setRng (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrng) {
    jclass rng_cls = (*jenv)->GetObjectClass(jenv, jrng);
    if (NULL == rng_cls) {
        VSCR_ASSERT("Class Random not found.");
    }
    jfieldID rng_fidCtx = (*jenv)->GetFieldID(jenv, rng_cls, "cCtx", "J");
    if (NULL == rng_fidCtx) {
        VSCR_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ rng = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrng, rng_fidCtx);

    vscr_ratchet_group_ticket_release_rng((vscr_ratchet_group_ticket_t /*2*/ *) c_ctx);
    vscr_ratchet_group_ticket_use_rng((vscr_ratchet_group_ticket_t /*2*/ *) c_ctx, rng);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_ticket_t /*2*/* ratchet_group_ticket_ctx = (vscr_ratchet_group_ticket_t /*2*/*) c_ctx;

    vscr_status_t status = vscr_ratchet_group_ticket_setup_defaults(ratchet_group_ticket_ctx /*a1*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1setupTicketAsNew (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsessionId) {
    // Cast class context
    vscr_ratchet_group_ticket_t /*2*/* ratchet_group_ticket_ctx = (vscr_ratchet_group_ticket_t /*2*/*) c_ctx;

    // Wrap input data
    byte* session_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsessionId, NULL);
    vsc_data_t session_id = vsc_data(session_id_arr, (*jenv)->GetArrayLength(jenv, jsessionId));

    vscr_status_t status = vscr_ratchet_group_ticket_setup_ticket_as_new(ratchet_group_ticket_ctx /*a1*/, session_id /*a3*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsessionId, (jbyte*) session_id_arr, 0);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupTicket_1getTicketMessage (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_ticket_t /*2*/* ratchet_group_ticket_ctx = (vscr_ratchet_group_ticket_t /*2*/*) c_ctx;

    const vscr_ratchet_group_message_t */*5*/ proxyResult = vscr_ratchet_group_ticket_get_ticket_message(ratchet_group_ticket_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupMessage");
    if (NULL == result_cls) {
        VSCR_ASSERT("Class RatchetGroupMessage not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/RatchetGroupMessage;");
    if (NULL == result_methodID) {
        VSCR_ASSERT("Class RatchetGroupMessage has no 'getInstance' method.");
    }
    vscr_ratchet_group_message_shallow_copy((vscr_ratchet_group_message_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupParticipantsIds_1new__ (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscr_ratchet_group_participants_ids_new();
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupParticipantsIds_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_group_participants_ids_delete((vscr_ratchet_group_participants_ids_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupParticipantsIds_1new__J (JNIEnv *jenv, jobject jobj, jlong jsize) {
    jlong proxyResult = (jlong) vscr_ratchet_group_participants_ids_new_size(jsize /*a9*/);
    return proxyResult;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupParticipantsIds_1addId (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jid) {
    // Cast class context
    vscr_ratchet_group_participants_ids_t /*2*/* ratchet_group_participants_ids_ctx = (vscr_ratchet_group_participants_ids_t /*2*/*) c_ctx;

    // Wrap input data
    byte* id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jid, NULL);
    vsc_data_t id = vsc_data(id_arr, (*jenv)->GetArrayLength(jenv, jid));

    vscr_ratchet_group_participants_ids_add_id(ratchet_group_participants_ids_ctx /*a1*/, id /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jid, (jbyte*) id_arr, 0);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1new__ (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscr_ratchet_group_session_new();
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscr_ratchet_group_session_delete((vscr_ratchet_group_session_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1setRng (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrng) {
    jclass rng_cls = (*jenv)->GetObjectClass(jenv, jrng);
    if (NULL == rng_cls) {
        VSCR_ASSERT("Class Random not found.");
    }
    jfieldID rng_fidCtx = (*jenv)->GetFieldID(jenv, rng_cls, "cCtx", "J");
    if (NULL == rng_fidCtx) {
        VSCR_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ rng = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrng, rng_fidCtx);

    vscr_ratchet_group_session_release_rng((vscr_ratchet_group_session_t /*2*/ *) c_ctx);
    vscr_ratchet_group_session_use_rng((vscr_ratchet_group_session_t /*2*/ *) c_ctx, rng);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1isInitialized (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_group_session_is_initialized(ratchet_group_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1isPrivateKeySet (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_group_session_is_private_key_set(ratchet_group_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1isMyIdSet (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    jboolean ret = (jboolean) vscr_ratchet_group_session_is_my_id_set(ratchet_group_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1getCurrentEpoch (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    jlong ret = (jlong) vscr_ratchet_group_session_get_current_epoch(ratchet_group_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    vscr_status_t status = vscr_ratchet_group_session_setup_defaults(ratchet_group_session_ctx /*a1*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1setPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jmyPrivateKey) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    // Wrap input data
    byte* my_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmyPrivateKey, NULL);
    vsc_data_t my_private_key = vsc_data(my_private_key_arr, (*jenv)->GetArrayLength(jenv, jmyPrivateKey));

    vscr_status_t status = vscr_ratchet_group_session_set_private_key(ratchet_group_session_ctx /*a1*/, my_private_key /*a3*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jmyPrivateKey, (jbyte*) my_private_key_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1setMyId (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jmyId) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    // Wrap input data
    byte* my_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmyId, NULL);
    vsc_data_t my_id = vsc_data(my_id_arr, (*jenv)->GetArrayLength(jenv, jmyId));

    vscr_ratchet_group_session_set_my_id(ratchet_group_session_ctx /*a1*/, my_id /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jmyId, (jbyte*) my_id_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1getMyId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_group_session_get_my_id(ratchet_group_session_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1getSessionId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscr_ratchet_group_session_get_session_id(ratchet_group_session_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1getParticipantsCount (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    jlong ret = (jlong) vscr_ratchet_group_session_get_participants_count(ratchet_group_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1setupSessionState (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage, jobject jparticipants) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetGroupMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetGroupMessage' has no field 'cCtx'.");
    }
    vscr_ratchet_group_message_t */*5*/ message = (vscr_ratchet_group_message_t */*5*/) (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);

    jclass participants_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupParticipantsInfo");
    if (NULL == participants_cls) {
        VSCR_ASSERT("Class RatchetGroupParticipantsInfo not found.");
    }
    jfieldID participants_fidCtx = (*jenv)->GetFieldID(jenv, participants_cls, "cCtx", "J");
    if (NULL == participants_fidCtx) {
        VSCR_ASSERT("Class 'RatchetGroupParticipantsInfo' has no field 'cCtx'.");
    }
    vscr_ratchet_group_participants_info_t */*5*/ participants = (vscr_ratchet_group_participants_info_t */*5*/) (*jenv)->GetLongField(jenv, jparticipants, participants_fidCtx);

    vscr_status_t status = vscr_ratchet_group_session_setup_session_state(ratchet_group_session_ctx /*a1*/, message /*a6*/, participants /*a6*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1updateSessionState (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage, jobject jaddParticipants, jobject jremoveParticipants) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetGroupMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetGroupMessage' has no field 'cCtx'.");
    }
    vscr_ratchet_group_message_t */*5*/ message = (vscr_ratchet_group_message_t */*5*/) (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);

    jclass add_participants_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupParticipantsInfo");
    if (NULL == add_participants_cls) {
        VSCR_ASSERT("Class RatchetGroupParticipantsInfo not found.");
    }
    jfieldID add_participants_fidCtx = (*jenv)->GetFieldID(jenv, add_participants_cls, "cCtx", "J");
    if (NULL == add_participants_fidCtx) {
        VSCR_ASSERT("Class 'RatchetGroupParticipantsInfo' has no field 'cCtx'.");
    }
    vscr_ratchet_group_participants_info_t */*5*/ add_participants = (vscr_ratchet_group_participants_info_t */*5*/) (*jenv)->GetLongField(jenv, jaddParticipants, add_participants_fidCtx);

    jclass remove_participants_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupParticipantsIds");
    if (NULL == remove_participants_cls) {
        VSCR_ASSERT("Class RatchetGroupParticipantsIds not found.");
    }
    jfieldID remove_participants_fidCtx = (*jenv)->GetFieldID(jenv, remove_participants_cls, "cCtx", "J");
    if (NULL == remove_participants_fidCtx) {
        VSCR_ASSERT("Class 'RatchetGroupParticipantsIds' has no field 'cCtx'.");
    }
    vscr_ratchet_group_participants_ids_t */*5*/ remove_participants = (vscr_ratchet_group_participants_ids_t */*5*/) (*jenv)->GetLongField(jenv, jremoveParticipants, remove_participants_fidCtx);

    vscr_status_t status = vscr_ratchet_group_session_update_session_state(ratchet_group_session_ctx /*a1*/, message /*a6*/, add_participants /*a6*/, remove_participants /*a6*/);
    if (status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jplainText) {
    // Wrap errors
    struct vscr_error_t /*4*/ error;
    vscr_error_reset(&error);
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    // Wrap input data
    byte* plain_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jplainText, NULL);
    vsc_data_t plain_text = vsc_data(plain_text_arr, (*jenv)->GetArrayLength(jenv, jplainText));

    const vscr_ratchet_group_message_t */*5*/ proxyResult = vscr_ratchet_group_session_encrypt(ratchet_group_session_ctx /*a1*/, plain_text /*a3*/, &error /*a4*/);

    if (error.status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupMessage");
    if (NULL == result_cls) {
        VSCR_ASSERT("Class RatchetGroupMessage not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/RatchetGroupMessage;");
    if (NULL == result_methodID) {
        VSCR_ASSERT("Class RatchetGroupMessage has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jplainText, (jbyte*) plain_text_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1decryptLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetGroupMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetGroupMessage' has no field 'cCtx'.");
    }
    vscr_ratchet_group_message_t */*5*/ message = (vscr_ratchet_group_message_t */*5*/) (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);

    jint ret = (jint) vscr_ratchet_group_session_decrypt_len(ratchet_group_session_ctx /*a1*/, message /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupMessage");
    if (NULL == message_cls) {
        VSCR_ASSERT("Class RatchetGroupMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCR_ASSERT("Class 'RatchetGroupMessage' has no field 'cCtx'.");
    }
    vscr_ratchet_group_message_t */*5*/ message = (vscr_ratchet_group_message_t */*5*/) (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len((vscr_ratchet_group_session_t /*2*/ *) c_ctx /*3*/, message/*a*/));

    vscr_status_t status = vscr_ratchet_group_session_decrypt(ratchet_group_session_ctx /*a1*/, message /*a6*/, plain_text /*a3*/);
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

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    const vsc_buffer_t */*5*/ proxyResult = vscr_ratchet_group_session_serialize(ratchet_group_session_ctx /*a1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(proxyResult));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(proxyResult), (jbyte*) vsc_buffer_bytes(proxyResult));
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1deserialize (JNIEnv *jenv, jobject jobj, jbyteArray jinput) {
    // Wrap errors
    struct vscr_error_t /*4*/ error;
    vscr_error_reset(&error);
    // Wrap input data
    byte* input_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinput, NULL);
    vsc_data_t input = vsc_data(input_arr, (*jenv)->GetArrayLength(jenv, jinput));

    const vscr_ratchet_group_session_t */*5*/ proxyResult = vscr_ratchet_group_session_deserialize(input /*a3*/, &error /*a4*/);

    if (error.status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupSession");
    if (NULL == result_cls) {
        VSCR_ASSERT("Class RatchetGroupSession not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/RatchetGroupSession;");
    if (NULL == result_methodID) {
        VSCR_ASSERT("Class RatchetGroupSession has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jinput, (jbyte*) input_arr, 0);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_ratchet_RatchetJNI_ratchetGroupSession_1createGroupTicket (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscr_error_t /*4*/ error;
    vscr_error_reset(&error);
    // Cast class context
    vscr_ratchet_group_session_t /*2*/* ratchet_group_session_ctx = (vscr_ratchet_group_session_t /*2*/*) c_ctx;

    const vscr_ratchet_group_ticket_t */*5*/ proxyResult = vscr_ratchet_group_session_create_group_ticket(ratchet_group_session_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscr_status_SUCCESS) {
        throwRatchetException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetGroupTicket");
    if (NULL == result_cls) {
        VSCR_ASSERT("Class RatchetGroupTicket not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/RatchetGroupTicket;");
    if (NULL == result_methodID) {
        VSCR_ASSERT("Class RatchetGroupTicket has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

