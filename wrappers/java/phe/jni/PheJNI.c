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

#include "PheJNI.h"

#include "vsce_phe_public.h"

#include <string.h>

jint throwPheException (JNIEnv *jenv, jobject jobj, jint statusCode) {
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheException");
    if (NULL == cls) {
        VSCE_ASSERT("Class PheException not found.");
        return 0;
    }

    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");
    if (NULL == methodID) {
        VSCE_ASSERT("Class com/virgilsecurity/crypto/phe/PheException has no constructor.");
        return 0;
    }
    jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);
    if (NULL == obj) {
        VSCE_ASSERT("Can't instantiate com/virgilsecurity/crypto/phe/PheException.");
        return 0;
    }
    return (*jenv)->Throw(jenv, obj);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vsce_phe_server_t **)&c_ctx = vsce_phe_server_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_phe_server_delete(*(vsce_phe_server_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vsce_phe_server_release_random((vsce_phe_server_t /*2*/ *) c_ctx);
    vsce_phe_server_use_random((vsce_phe_server_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1setOperationRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject joperationRandom) {
    jclass operation_random_cls = (*jenv)->GetObjectClass(jenv, joperationRandom);
    if (NULL == operation_random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID operation_random_fidCtx = (*jenv)->GetFieldID(jenv, operation_random_cls, "cCtx", "J");
    if (NULL == operation_random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong operation_random_c_ctx = (*jenv)->GetLongField(jenv, joperationRandom, operation_random_fidCtx);
    vscf_impl_t */*6*/ operation_random = *(vscf_impl_t */*6*/*) &operation_random_c_ctx;

    vsce_phe_server_release_operation_random((vsce_phe_server_t /*2*/ *) c_ctx);
    vsce_phe_server_use_operation_random((vsce_phe_server_t /*2*/ *) c_ctx, operation_random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

    vsce_status_t status = vsce_phe_server_setup_defaults(phe_server_ctx /*a1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1generateServerKeyPair (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_phe_server_generate_server_key_pair(phe_server_ctx /*a1*/, server_private_key /*a3*/, server_public_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheServerGenerateServerKeyPairResult");
    if (NULL == cls) {
        VSCE_ASSERT("Class PheServerGenerateServerKeyPairResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidServerPrivateKey = (*jenv)->GetFieldID(jenv, cls, "serverPrivateKey", "[B");
    jbyteArray jServerPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(server_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jServerPrivateKeyArr, 0, vsc_buffer_len(server_private_key), (jbyte*) vsc_buffer_bytes(server_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidServerPrivateKey, jServerPrivateKeyArr);
    jfieldID fidServerPublicKey = (*jenv)->GetFieldID(jenv, cls, "serverPublicKey", "[B");
    jbyteArray jServerPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(server_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jServerPublicKeyArr, 0, vsc_buffer_len(server_public_key), (jbyte*) vsc_buffer_bytes(server_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidServerPublicKey, jServerPublicKeyArr);
    // Free resources
    vsc_buffer_delete(server_private_key);

    vsc_buffer_delete(server_public_key);

    return newObj;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1enrollmentResponseLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

    jint ret = (jint) vsce_phe_server_enrollment_response_len(phe_server_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1getEnrollment (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey) {
    // Cast class context
    vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
    vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

    byte* server_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL);
    vsc_data_t server_public_key = vsc_data(server_public_key_arr, (*jenv)->GetArrayLength(jenv, jserverPublicKey));

    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len((vsce_phe_server_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_server_get_enrollment(phe_server_ctx /*a1*/, server_private_key /*a3*/, server_public_key /*a3*/, enrollment_response /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(enrollment_response));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(enrollment_response), (jbyte*) vsc_buffer_bytes(enrollment_response));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jserverPublicKey, (jbyte*) server_public_key_arr, 0);

    vsc_buffer_delete(enrollment_response);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1verifyPasswordResponseLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

    jint ret = (jint) vsce_phe_server_verify_password_response_len(phe_server_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1verifyPassword (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey, jbyteArray jverifyPasswordRequest) {
    // Cast class context
    vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
    vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

    byte* server_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL);
    vsc_data_t server_public_key = vsc_data(server_public_key_arr, (*jenv)->GetArrayLength(jenv, jserverPublicKey));

    byte* verify_password_request_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jverifyPasswordRequest, NULL);
    vsc_data_t verify_password_request = vsc_data(verify_password_request_arr, (*jenv)->GetArrayLength(jenv, jverifyPasswordRequest));

    vsc_buffer_t *verify_password_response = vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len((vsce_phe_server_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_server_verify_password(phe_server_ctx /*a1*/, server_private_key /*a3*/, server_public_key /*a3*/, verify_password_request /*a3*/, verify_password_response /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(verify_password_response));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(verify_password_response), (jbyte*) vsc_buffer_bytes(verify_password_response));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jserverPublicKey, (jbyte*) server_public_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jverifyPasswordRequest, (jbyte*) verify_password_request_arr, 0);

    vsc_buffer_delete(verify_password_response);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1updateTokenLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

    jint ret = (jint) vsce_phe_server_update_token_len(phe_server_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheServer_1rotateKeys (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey) {
    // Cast class context
    vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
    vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

    vsc_buffer_t *new_server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(vsce_phe_server_update_token_len((vsce_phe_server_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_server_rotate_keys(phe_server_ctx /*a1*/, server_private_key /*a3*/, new_server_private_key /*a3*/, new_server_public_key /*a3*/, update_token /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheServerRotateKeysResult");
    if (NULL == cls) {
        VSCE_ASSERT("Class PheServerRotateKeysResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidNewServerPrivateKey = (*jenv)->GetFieldID(jenv, cls, "newServerPrivateKey", "[B");
    jbyteArray jNewServerPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewServerPrivateKeyArr, 0, vsc_buffer_len(new_server_private_key), (jbyte*) vsc_buffer_bytes(new_server_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewServerPrivateKey, jNewServerPrivateKeyArr);
    jfieldID fidNewServerPublicKey = (*jenv)->GetFieldID(jenv, cls, "newServerPublicKey", "[B");
    jbyteArray jNewServerPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewServerPublicKeyArr, 0, vsc_buffer_len(new_server_public_key), (jbyte*) vsc_buffer_bytes(new_server_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewServerPublicKey, jNewServerPublicKeyArr);
    jfieldID fidUpdateToken = (*jenv)->GetFieldID(jenv, cls, "updateToken", "[B");
    jbyteArray jUpdateTokenArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(update_token));
    (*jenv)->SetByteArrayRegion (jenv, jUpdateTokenArr, 0, vsc_buffer_len(update_token), (jbyte*) vsc_buffer_bytes(update_token));
    (*jenv)->SetObjectField(jenv, newObj, fidUpdateToken, jUpdateTokenArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

    vsc_buffer_delete(new_server_private_key);

    vsc_buffer_delete(new_server_public_key);

    vsc_buffer_delete(update_token);

    return newObj;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vsce_phe_client_t **)&c_ctx = vsce_phe_client_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_phe_client_delete(*(vsce_phe_client_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vsce_phe_client_release_random((vsce_phe_client_t /*2*/ *) c_ctx);
    vsce_phe_client_use_random((vsce_phe_client_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1setOperationRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject joperationRandom) {
    jclass operation_random_cls = (*jenv)->GetObjectClass(jenv, joperationRandom);
    if (NULL == operation_random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID operation_random_fidCtx = (*jenv)->GetFieldID(jenv, operation_random_cls, "cCtx", "J");
    if (NULL == operation_random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong operation_random_c_ctx = (*jenv)->GetLongField(jenv, joperationRandom, operation_random_fidCtx);
    vscf_impl_t */*6*/ operation_random = *(vscf_impl_t */*6*/*) &operation_random_c_ctx;

    vsce_phe_client_release_operation_random((vsce_phe_client_t /*2*/ *) c_ctx);
    vsce_phe_client_use_operation_random((vsce_phe_client_t /*2*/ *) c_ctx, operation_random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    vsce_status_t status = vsce_phe_client_setup_defaults(phe_client_ctx /*a1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1setKeys (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jclientPrivateKey, jbyteArray jserverPublicKey) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* client_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jclientPrivateKey, NULL);
    vsc_data_t client_private_key = vsc_data(client_private_key_arr, (*jenv)->GetArrayLength(jenv, jclientPrivateKey));

    byte* server_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL);
    vsc_data_t server_public_key = vsc_data(server_public_key_arr, (*jenv)->GetArrayLength(jenv, jserverPublicKey));

    vsce_status_t status = vsce_phe_client_set_keys(phe_client_ctx /*a1*/, client_private_key /*a3*/, server_public_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jclientPrivateKey, (jbyte*) client_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jserverPublicKey, (jbyte*) server_public_key_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1generateClientPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsce_status_t status = vsce_phe_client_generate_client_private_key(phe_client_ctx /*a1*/, client_private_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(client_private_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(client_private_key), (jbyte*) vsc_buffer_bytes(client_private_key));
    // Free resources
    vsc_buffer_delete(client_private_key);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1enrollmentRecordLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    jint ret = (jint) vsce_phe_client_enrollment_record_len(phe_client_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1enrollAccount (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jenrollmentResponse, jbyteArray jpassword) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* enrollment_response_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jenrollmentResponse, NULL);
    vsc_data_t enrollment_response = vsc_data(enrollment_response_arr, (*jenv)->GetArrayLength(jenv, jenrollmentResponse));

    byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
    vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len((vsce_phe_client_t /*2*/ *) c_ctx /*3*/));

    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

    vsce_status_t status = vsce_phe_client_enroll_account(phe_client_ctx /*a1*/, enrollment_response /*a3*/, password /*a3*/, enrollment_record /*a3*/, account_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheClientEnrollAccountResult");
    if (NULL == cls) {
        VSCE_ASSERT("Class PheClientEnrollAccountResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidEnrollmentRecord = (*jenv)->GetFieldID(jenv, cls, "enrollmentRecord", "[B");
    jbyteArray jEnrollmentRecordArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(enrollment_record));
    (*jenv)->SetByteArrayRegion (jenv, jEnrollmentRecordArr, 0, vsc_buffer_len(enrollment_record), (jbyte*) vsc_buffer_bytes(enrollment_record));
    (*jenv)->SetObjectField(jenv, newObj, fidEnrollmentRecord, jEnrollmentRecordArr);
    jfieldID fidAccountKey = (*jenv)->GetFieldID(jenv, cls, "accountKey", "[B");
    jbyteArray jAccountKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(account_key));
    (*jenv)->SetByteArrayRegion (jenv, jAccountKeyArr, 0, vsc_buffer_len(account_key), (jbyte*) vsc_buffer_bytes(account_key));
    (*jenv)->SetObjectField(jenv, newObj, fidAccountKey, jAccountKeyArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jenrollmentResponse, (jbyte*) enrollment_response_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

    vsc_buffer_delete(enrollment_record);

    vsc_buffer_delete(account_key);

    return newObj;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1verifyPasswordRequestLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    jint ret = (jint) vsce_phe_client_verify_password_request_len(phe_client_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1createVerifyPasswordRequest (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
    vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

    byte* enrollment_record_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, NULL);
    vsc_data_t enrollment_record = vsc_data(enrollment_record_arr, (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

    vsc_buffer_t *verify_password_request = vsc_buffer_new_with_capacity(vsce_phe_client_verify_password_request_len((vsce_phe_client_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_client_create_verify_password_request(phe_client_ctx /*a1*/, password /*a3*/, enrollment_record /*a3*/, verify_password_request /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(verify_password_request));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(verify_password_request), (jbyte*) vsc_buffer_bytes(verify_password_request));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jenrollmentRecord, (jbyte*) enrollment_record_arr, 0);

    vsc_buffer_delete(verify_password_request);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1checkResponseAndDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord, jbyteArray jverifyPasswordResponse) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
    vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

    byte* enrollment_record_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, NULL);
    vsc_data_t enrollment_record = vsc_data(enrollment_record_arr, (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

    byte* verify_password_response_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jverifyPasswordResponse, NULL);
    vsc_data_t verify_password_response = vsc_data(verify_password_response_arr, (*jenv)->GetArrayLength(jenv, jverifyPasswordResponse));

    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

    vsce_status_t status = vsce_phe_client_check_response_and_decrypt(phe_client_ctx /*a1*/, password /*a3*/, enrollment_record /*a3*/, verify_password_response /*a3*/, account_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(account_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(account_key), (jbyte*) vsc_buffer_bytes(account_key));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jenrollmentRecord, (jbyte*) enrollment_record_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jverifyPasswordResponse, (jbyte*) verify_password_response_arr, 0);

    vsc_buffer_delete(account_key);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1rotateKeys (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jupdateToken) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
    vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

    vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_phe_client_rotate_keys(phe_client_ctx /*a1*/, update_token /*a3*/, new_client_private_key /*a3*/, new_server_public_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheClientRotateKeysResult");
    if (NULL == cls) {
        VSCE_ASSERT("Class PheClientRotateKeysResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidNewClientPrivateKey = (*jenv)->GetFieldID(jenv, cls, "newClientPrivateKey", "[B");
    jbyteArray jNewClientPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_client_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewClientPrivateKeyArr, 0, vsc_buffer_len(new_client_private_key), (jbyte*) vsc_buffer_bytes(new_client_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewClientPrivateKey, jNewClientPrivateKeyArr);
    jfieldID fidNewServerPublicKey = (*jenv)->GetFieldID(jenv, cls, "newServerPublicKey", "[B");
    jbyteArray jNewServerPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewServerPublicKeyArr, 0, vsc_buffer_len(new_server_public_key), (jbyte*) vsc_buffer_bytes(new_server_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewServerPublicKey, jNewServerPublicKeyArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jupdateToken, (jbyte*) update_token_arr, 0);

    vsc_buffer_delete(new_client_private_key);

    vsc_buffer_delete(new_server_public_key);

    return newObj;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheClient_1updateEnrollmentRecord (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jenrollmentRecord, jbyteArray jupdateToken) {
    // Cast class context
    vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* enrollment_record_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, NULL);
    vsc_data_t enrollment_record = vsc_data(enrollment_record_arr, (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

    byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
    vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

    vsc_buffer_t *new_enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len((vsce_phe_client_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_client_update_enrollment_record(phe_client_ctx /*a1*/, enrollment_record /*a3*/, update_token /*a3*/, new_enrollment_record /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_enrollment_record));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(new_enrollment_record), (jbyte*) vsc_buffer_bytes(new_enrollment_record));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jenrollmentRecord, (jbyte*) enrollment_record_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jupdateToken, (jbyte*) update_token_arr, 0);

    vsc_buffer_delete(new_enrollment_record);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vsce_phe_cipher_t **)&c_ctx = vsce_phe_cipher_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_phe_cipher_delete(*(vsce_phe_cipher_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vsce_phe_cipher_release_random((vsce_phe_cipher_t /*2*/ *) c_ctx);
    vsce_phe_cipher_use_random((vsce_phe_cipher_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

    vsce_status_t status = vsce_phe_cipher_setup_defaults(phe_cipher_ctx /*a1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1encryptLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jplainTextLen) {
    // Cast class context
    vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

    jint ret = (jint) vsce_phe_cipher_encrypt_len(phe_cipher_ctx /*a1*/, jplainTextLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1decryptLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jcipherTextLen) {
    // Cast class context
    vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

    jint ret = (jint) vsce_phe_cipher_decrypt_len(phe_cipher_ctx /*a1*/, jcipherTextLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jplainText, jbyteArray jaccountKey) {
    // Cast class context
    vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* plain_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jplainText, NULL);
    vsc_data_t plain_text = vsc_data(plain_text_arr, (*jenv)->GetArrayLength(jenv, jplainText));

    byte* account_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL);
    vsc_data_t account_key = vsc_data(account_key_arr, (*jenv)->GetArrayLength(jenv, jaccountKey));

    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_encrypt_len((vsce_phe_cipher_t /*2*/ *) c_ctx /*3*/, plain_text.len/*a*/));

    vsce_status_t status = vsce_phe_cipher_encrypt(phe_cipher_ctx /*a1*/, plain_text /*a3*/, account_key /*a3*/, cipher_text /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(cipher_text));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(cipher_text), (jbyte*) vsc_buffer_bytes(cipher_text));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jplainText, (jbyte*) plain_text_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jaccountKey, (jbyte*) account_key_arr, 0);

    vsc_buffer_delete(cipher_text);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jcipherText, jbyteArray jaccountKey) {
    // Cast class context
    vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* cipher_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jcipherText, NULL);
    vsc_data_t cipher_text = vsc_data(cipher_text_arr, (*jenv)->GetArrayLength(jenv, jcipherText));

    byte* account_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL);
    vsc_data_t account_key = vsc_data(account_key_arr, (*jenv)->GetArrayLength(jenv, jaccountKey));

    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_decrypt_len((vsce_phe_cipher_t /*2*/ *) c_ctx /*3*/, cipher_text.len/*a*/));

    vsce_status_t status = vsce_phe_cipher_decrypt(phe_cipher_ctx /*a1*/, cipher_text /*a3*/, account_key /*a3*/, plain_text /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), (jbyte*) vsc_buffer_bytes(plain_text));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jcipherText, (jbyte*) cipher_text_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jaccountKey, (jbyte*) account_key_arr, 0);

    vsc_buffer_delete(plain_text);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1authEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jplainText, jbyteArray jadditionalData, jbyteArray jaccountKey) {
    // Cast class context
    vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* plain_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jplainText, NULL);
    vsc_data_t plain_text = vsc_data(plain_text_arr, (*jenv)->GetArrayLength(jenv, jplainText));

    byte* additional_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jadditionalData, NULL);
    vsc_data_t additional_data = vsc_data(additional_data_arr, (*jenv)->GetArrayLength(jenv, jadditionalData));

    byte* account_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL);
    vsc_data_t account_key = vsc_data(account_key_arr, (*jenv)->GetArrayLength(jenv, jaccountKey));

    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_encrypt_len((vsce_phe_cipher_t /*2*/ *) c_ctx /*3*/, plain_text.len/*a*/));

    vsce_status_t status = vsce_phe_cipher_auth_encrypt(phe_cipher_ctx /*a1*/, plain_text /*a3*/, additional_data /*a3*/, account_key /*a3*/, cipher_text /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(cipher_text));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(cipher_text), (jbyte*) vsc_buffer_bytes(cipher_text));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jplainText, (jbyte*) plain_text_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jadditionalData, (jbyte*) additional_data_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jaccountKey, (jbyte*) account_key_arr, 0);

    vsc_buffer_delete(cipher_text);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_pheCipher_1authDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jcipherText, jbyteArray jadditionalData, jbyteArray jaccountKey) {
    // Cast class context
    vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* cipher_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jcipherText, NULL);
    vsc_data_t cipher_text = vsc_data(cipher_text_arr, (*jenv)->GetArrayLength(jenv, jcipherText));

    byte* additional_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jadditionalData, NULL);
    vsc_data_t additional_data = vsc_data(additional_data_arr, (*jenv)->GetArrayLength(jenv, jadditionalData));

    byte* account_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL);
    vsc_data_t account_key = vsc_data(account_key_arr, (*jenv)->GetArrayLength(jenv, jaccountKey));

    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_decrypt_len((vsce_phe_cipher_t /*2*/ *) c_ctx /*3*/, cipher_text.len/*a*/));

    vsce_status_t status = vsce_phe_cipher_auth_decrypt(phe_cipher_ctx /*a1*/, cipher_text /*a3*/, additional_data /*a3*/, account_key /*a3*/, plain_text /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), (jbyte*) vsc_buffer_bytes(plain_text));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jcipherText, (jbyte*) cipher_text_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jadditionalData, (jbyte*) additional_data_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jaccountKey, (jbyte*) account_key_arr, 0);

    vsc_buffer_delete(plain_text);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vsce_uokms_client_t **)&c_ctx = vsce_uokms_client_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_uokms_client_delete(*(vsce_uokms_client_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vsce_uokms_client_release_random((vsce_uokms_client_t /*2*/ *) c_ctx);
    vsce_uokms_client_use_random((vsce_uokms_client_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setOperationRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject joperationRandom) {
    jclass operation_random_cls = (*jenv)->GetObjectClass(jenv, joperationRandom);
    if (NULL == operation_random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID operation_random_fidCtx = (*jenv)->GetFieldID(jenv, operation_random_cls, "cCtx", "J");
    if (NULL == operation_random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong operation_random_c_ctx = (*jenv)->GetLongField(jenv, joperationRandom, operation_random_fidCtx);
    vscf_impl_t */*6*/ operation_random = *(vscf_impl_t */*6*/*) &operation_random_c_ctx;

    vsce_uokms_client_release_operation_random((vsce_uokms_client_t /*2*/ *) c_ctx);
    vsce_uokms_client_use_operation_random((vsce_uokms_client_t /*2*/ *) c_ctx, operation_random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    vsce_status_t status = vsce_uokms_client_setup_defaults(uokms_client_ctx /*a1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setKeysOneparty (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jclientPrivateKey) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* client_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jclientPrivateKey, NULL);
    vsc_data_t client_private_key = vsc_data(client_private_key_arr, (*jenv)->GetArrayLength(jenv, jclientPrivateKey));

    vsce_status_t status = vsce_uokms_client_set_keys_oneparty(uokms_client_ctx /*a1*/, client_private_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jclientPrivateKey, (jbyte*) client_private_key_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1setKeys (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jclientPrivateKey, jbyteArray jserverPublicKey) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* client_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jclientPrivateKey, NULL);
    vsc_data_t client_private_key = vsc_data(client_private_key_arr, (*jenv)->GetArrayLength(jenv, jclientPrivateKey));

    byte* server_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL);
    vsc_data_t server_public_key = vsc_data(server_public_key_arr, (*jenv)->GetArrayLength(jenv, jserverPublicKey));

    vsce_status_t status = vsce_uokms_client_set_keys(uokms_client_ctx /*a1*/, client_private_key /*a3*/, server_public_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jclientPrivateKey, (jbyte*) client_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jserverPublicKey, (jbyte*) server_public_key_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1generateClientPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsce_status_t status = vsce_uokms_client_generate_client_private_key(uokms_client_ctx /*a1*/, client_private_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(client_private_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(client_private_key), (jbyte*) vsc_buffer_bytes(client_private_key));
    // Free resources
    vsc_buffer_delete(client_private_key);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1generateEncryptWrap (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jencryptionKeyLen) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsc_buffer_t *encryption_key = vsc_buffer_new_with_capacity(jencryptionKeyLen);

    vsce_status_t status = vsce_uokms_client_generate_encrypt_wrap(uokms_client_ctx /*a1*/, wrap /*a3*/, jencryptionKeyLen /*a9*/, encryption_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsClientGenerateEncryptWrapResult");
    if (NULL == cls) {
        VSCE_ASSERT("Class UokmsClientGenerateEncryptWrapResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidWrap = (*jenv)->GetFieldID(jenv, cls, "wrap", "[B");
    jbyteArray jWrapArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(wrap));
    (*jenv)->SetByteArrayRegion (jenv, jWrapArr, 0, vsc_buffer_len(wrap), (jbyte*) vsc_buffer_bytes(wrap));
    (*jenv)->SetObjectField(jenv, newObj, fidWrap, jWrapArr);
    jfieldID fidEncryptionKey = (*jenv)->GetFieldID(jenv, cls, "encryptionKey", "[B");
    jbyteArray jEncryptionKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(encryption_key));
    (*jenv)->SetByteArrayRegion (jenv, jEncryptionKeyArr, 0, vsc_buffer_len(encryption_key), (jbyte*) vsc_buffer_bytes(encryption_key));
    (*jenv)->SetObjectField(jenv, newObj, fidEncryptionKey, jEncryptionKeyArr);
    // Free resources
    vsc_buffer_delete(wrap);

    vsc_buffer_delete(encryption_key);

    return newObj;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1decryptOneparty (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jwrap, jint jencryptionKeyLen) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* wrap_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jwrap, NULL);
    vsc_data_t wrap = vsc_data(wrap_arr, (*jenv)->GetArrayLength(jenv, jwrap));

    vsc_buffer_t *encryption_key = vsc_buffer_new_with_capacity(jencryptionKeyLen);

    vsce_status_t status = vsce_uokms_client_decrypt_oneparty(uokms_client_ctx /*a1*/, wrap /*a3*/, jencryptionKeyLen /*a9*/, encryption_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(encryption_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(encryption_key), (jbyte*) vsc_buffer_bytes(encryption_key));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jwrap, (jbyte*) wrap_arr, 0);

    vsc_buffer_delete(encryption_key);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1generateDecryptRequest (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jwrap) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* wrap_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jwrap, NULL);
    vsc_data_t wrap = vsc_data(wrap_arr, (*jenv)->GetArrayLength(jenv, jwrap));

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *decrypt_request = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_uokms_client_generate_decrypt_request(uokms_client_ctx /*a1*/, wrap /*a3*/, deblind_factor /*a3*/, decrypt_request /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsClientGenerateDecryptRequestResult");
    if (NULL == cls) {
        VSCE_ASSERT("Class UokmsClientGenerateDecryptRequestResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidDeblindFactor = (*jenv)->GetFieldID(jenv, cls, "deblindFactor", "[B");
    jbyteArray jDeblindFactorArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(deblind_factor));
    (*jenv)->SetByteArrayRegion (jenv, jDeblindFactorArr, 0, vsc_buffer_len(deblind_factor), (jbyte*) vsc_buffer_bytes(deblind_factor));
    (*jenv)->SetObjectField(jenv, newObj, fidDeblindFactor, jDeblindFactorArr);
    jfieldID fidDecryptRequest = (*jenv)->GetFieldID(jenv, cls, "decryptRequest", "[B");
    jbyteArray jDecryptRequestArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(decrypt_request));
    (*jenv)->SetByteArrayRegion (jenv, jDecryptRequestArr, 0, vsc_buffer_len(decrypt_request), (jbyte*) vsc_buffer_bytes(decrypt_request));
    (*jenv)->SetObjectField(jenv, newObj, fidDecryptRequest, jDecryptRequestArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jwrap, (jbyte*) wrap_arr, 0);

    vsc_buffer_delete(deblind_factor);

    vsc_buffer_delete(decrypt_request);

    return newObj;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1processDecryptResponse (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jwrap, jbyteArray jdecryptRequest, jbyteArray jdecryptResponse, jbyteArray jdeblindFactor, jint jencryptionKeyLen) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* wrap_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jwrap, NULL);
    vsc_data_t wrap = vsc_data(wrap_arr, (*jenv)->GetArrayLength(jenv, jwrap));

    byte* decrypt_request_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdecryptRequest, NULL);
    vsc_data_t decrypt_request = vsc_data(decrypt_request_arr, (*jenv)->GetArrayLength(jenv, jdecryptRequest));

    byte* decrypt_response_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdecryptResponse, NULL);
    vsc_data_t decrypt_response = vsc_data(decrypt_response_arr, (*jenv)->GetArrayLength(jenv, jdecryptResponse));

    byte* deblind_factor_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdeblindFactor, NULL);
    vsc_data_t deblind_factor = vsc_data(deblind_factor_arr, (*jenv)->GetArrayLength(jenv, jdeblindFactor));

    vsc_buffer_t *encryption_key = vsc_buffer_new_with_capacity(jencryptionKeyLen);

    vsce_status_t status = vsce_uokms_client_process_decrypt_response(uokms_client_ctx /*a1*/, wrap /*a3*/, decrypt_request /*a3*/, decrypt_response /*a3*/, deblind_factor /*a3*/, jencryptionKeyLen /*a9*/, encryption_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(encryption_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(encryption_key), (jbyte*) vsc_buffer_bytes(encryption_key));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jwrap, (jbyte*) wrap_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jdecryptRequest, (jbyte*) decrypt_request_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jdecryptResponse, (jbyte*) decrypt_response_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jdeblindFactor, (jbyte*) deblind_factor_arr, 0);

    vsc_buffer_delete(encryption_key);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1rotateKeysOneparty (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jupdateToken) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
    vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

    vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsce_status_t status = vsce_uokms_client_rotate_keys_oneparty(uokms_client_ctx /*a1*/, update_token /*a3*/, new_client_private_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_client_private_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(new_client_private_key), (jbyte*) vsc_buffer_bytes(new_client_private_key));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jupdateToken, (jbyte*) update_token_arr, 0);

    vsc_buffer_delete(new_client_private_key);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1generateUpdateTokenOneparty (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsce_status_t status = vsce_uokms_client_generate_update_token_oneparty(uokms_client_ctx /*a1*/, update_token /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(update_token));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(update_token), (jbyte*) vsc_buffer_bytes(update_token));
    // Free resources
    vsc_buffer_delete(update_token);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsClient_1rotateKeys (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jupdateToken) {
    // Cast class context
    vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
    vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

    vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_uokms_client_rotate_keys(uokms_client_ctx /*a1*/, update_token /*a3*/, new_client_private_key /*a3*/, new_server_public_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsClientRotateKeysResult");
    if (NULL == cls) {
        VSCE_ASSERT("Class UokmsClientRotateKeysResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidNewClientPrivateKey = (*jenv)->GetFieldID(jenv, cls, "newClientPrivateKey", "[B");
    jbyteArray jNewClientPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_client_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewClientPrivateKeyArr, 0, vsc_buffer_len(new_client_private_key), (jbyte*) vsc_buffer_bytes(new_client_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewClientPrivateKey, jNewClientPrivateKeyArr);
    jfieldID fidNewServerPublicKey = (*jenv)->GetFieldID(jenv, cls, "newServerPublicKey", "[B");
    jbyteArray jNewServerPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewServerPublicKeyArr, 0, vsc_buffer_len(new_server_public_key), (jbyte*) vsc_buffer_bytes(new_server_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewServerPublicKey, jNewServerPublicKeyArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jupdateToken, (jbyte*) update_token_arr, 0);

    vsc_buffer_delete(new_client_private_key);

    vsc_buffer_delete(new_server_public_key);

    return newObj;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vsce_uokms_server_t **)&c_ctx = vsce_uokms_server_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_uokms_server_delete(*(vsce_uokms_server_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vsce_uokms_server_release_random((vsce_uokms_server_t /*2*/ *) c_ctx);
    vsce_uokms_server_use_random((vsce_uokms_server_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1setOperationRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject joperationRandom) {
    jclass operation_random_cls = (*jenv)->GetObjectClass(jenv, joperationRandom);
    if (NULL == operation_random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID operation_random_fidCtx = (*jenv)->GetFieldID(jenv, operation_random_cls, "cCtx", "J");
    if (NULL == operation_random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong operation_random_c_ctx = (*jenv)->GetLongField(jenv, joperationRandom, operation_random_fidCtx);
    vscf_impl_t */*6*/ operation_random = *(vscf_impl_t */*6*/*) &operation_random_c_ctx;

    vsce_uokms_server_release_operation_random((vsce_uokms_server_t /*2*/ *) c_ctx);
    vsce_uokms_server_use_operation_random((vsce_uokms_server_t /*2*/ *) c_ctx, operation_random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

    vsce_status_t status = vsce_uokms_server_setup_defaults(uokms_server_ctx /*a1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1generateServerKeyPair (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_uokms_server_generate_server_key_pair(uokms_server_ctx /*a1*/, server_private_key /*a3*/, server_public_key /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsServerGenerateServerKeyPairResult");
    if (NULL == cls) {
        VSCE_ASSERT("Class UokmsServerGenerateServerKeyPairResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidServerPrivateKey = (*jenv)->GetFieldID(jenv, cls, "serverPrivateKey", "[B");
    jbyteArray jServerPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(server_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jServerPrivateKeyArr, 0, vsc_buffer_len(server_private_key), (jbyte*) vsc_buffer_bytes(server_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidServerPrivateKey, jServerPrivateKeyArr);
    jfieldID fidServerPublicKey = (*jenv)->GetFieldID(jenv, cls, "serverPublicKey", "[B");
    jbyteArray jServerPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(server_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jServerPublicKeyArr, 0, vsc_buffer_len(server_public_key), (jbyte*) vsc_buffer_bytes(server_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidServerPublicKey, jServerPublicKeyArr);
    // Free resources
    vsc_buffer_delete(server_private_key);

    vsc_buffer_delete(server_public_key);

    return newObj;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1decryptResponseLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

    jint ret = (jint) vsce_uokms_server_decrypt_response_len(uokms_server_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1processDecryptRequest (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jdecryptRequest) {
    // Cast class context
    vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
    vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

    byte* decrypt_request_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdecryptRequest, NULL);
    vsc_data_t decrypt_request = vsc_data(decrypt_request_arr, (*jenv)->GetArrayLength(jenv, jdecryptRequest));

    vsc_buffer_t *decrypt_response = vsc_buffer_new_with_capacity(vsce_uokms_server_decrypt_response_len((vsce_uokms_server_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_uokms_server_process_decrypt_request(uokms_server_ctx /*a1*/, server_private_key /*a3*/, decrypt_request /*a3*/, decrypt_response /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(decrypt_response));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(decrypt_response), (jbyte*) vsc_buffer_bytes(decrypt_response));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jdecryptRequest, (jbyte*) decrypt_request_arr, 0);

    vsc_buffer_delete(decrypt_response);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsServer_1rotateKeys (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey) {
    // Cast class context
    vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
    vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

    vsc_buffer_t *new_server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsce_status_t status = vsce_uokms_server_rotate_keys(uokms_server_ctx /*a1*/, server_private_key /*a3*/, new_server_private_key /*a3*/, new_server_public_key /*a3*/, update_token /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsServerRotateKeysResult");
    if (NULL == cls) {
        VSCE_ASSERT("Class UokmsServerRotateKeysResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidNewServerPrivateKey = (*jenv)->GetFieldID(jenv, cls, "newServerPrivateKey", "[B");
    jbyteArray jNewServerPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewServerPrivateKeyArr, 0, vsc_buffer_len(new_server_private_key), (jbyte*) vsc_buffer_bytes(new_server_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewServerPrivateKey, jNewServerPrivateKeyArr);
    jfieldID fidNewServerPublicKey = (*jenv)->GetFieldID(jenv, cls, "newServerPublicKey", "[B");
    jbyteArray jNewServerPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewServerPublicKeyArr, 0, vsc_buffer_len(new_server_public_key), (jbyte*) vsc_buffer_bytes(new_server_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewServerPublicKey, jNewServerPublicKeyArr);
    jfieldID fidUpdateToken = (*jenv)->GetFieldID(jenv, cls, "updateToken", "[B");
    jbyteArray jUpdateTokenArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(update_token));
    (*jenv)->SetByteArrayRegion (jenv, jUpdateTokenArr, 0, vsc_buffer_len(update_token), (jbyte*) vsc_buffer_bytes(update_token));
    (*jenv)->SetObjectField(jenv, newObj, fidUpdateToken, jUpdateTokenArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

    vsc_buffer_delete(new_server_private_key);

    vsc_buffer_delete(new_server_public_key);

    vsc_buffer_delete(update_token);

    return newObj;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vsce_uokms_wrap_rotation_t **)&c_ctx = vsce_uokms_wrap_rotation_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_uokms_wrap_rotation_delete(*(vsce_uokms_wrap_rotation_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1setOperationRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject joperationRandom) {
    jclass operation_random_cls = (*jenv)->GetObjectClass(jenv, joperationRandom);
    if (NULL == operation_random_cls) {
        VSCE_ASSERT("Class Random not found.");
    }
    jfieldID operation_random_fidCtx = (*jenv)->GetFieldID(jenv, operation_random_cls, "cCtx", "J");
    if (NULL == operation_random_fidCtx) {
        VSCE_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong operation_random_c_ctx = (*jenv)->GetLongField(jenv, joperationRandom, operation_random_fidCtx);
    vscf_impl_t */*6*/ operation_random = *(vscf_impl_t */*6*/*) &operation_random_c_ctx;

    vsce_uokms_wrap_rotation_release_operation_random((vsce_uokms_wrap_rotation_t /*2*/ *) c_ctx);
    vsce_uokms_wrap_rotation_use_operation_random((vsce_uokms_wrap_rotation_t /*2*/ *) c_ctx, operation_random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vsce_uokms_wrap_rotation_t /*2*/* uokms_wrap_rotation_ctx = *(vsce_uokms_wrap_rotation_t /*2*/**) &c_ctx;

    vsce_status_t status = vsce_uokms_wrap_rotation_setup_defaults(uokms_wrap_rotation_ctx /*a1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1setUpdateToken (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jupdateToken) {
    // Cast class context
    vsce_uokms_wrap_rotation_t /*2*/* uokms_wrap_rotation_ctx = *(vsce_uokms_wrap_rotation_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
    vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

    vsce_status_t status = vsce_uokms_wrap_rotation_set_update_token(uokms_wrap_rotation_ctx /*a1*/, update_token /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jupdateToken, (jbyte*) update_token_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_phe_PheJNI_uokmsWrapRotation_1updateWrap (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jwrap) {
    // Cast class context
    vsce_uokms_wrap_rotation_t /*2*/* uokms_wrap_rotation_ctx = *(vsce_uokms_wrap_rotation_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* wrap_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jwrap, NULL);
    vsc_data_t wrap = vsc_data(wrap_arr, (*jenv)->GetArrayLength(jenv, jwrap));

    vsc_buffer_t *new_wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_uokms_wrap_rotation_update_wrap(uokms_wrap_rotation_ctx /*a1*/, wrap /*a3*/, new_wrap /*a3*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_wrap));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(new_wrap), (jbyte*) vsc_buffer_bytes(new_wrap));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jwrap, (jbyte*) wrap_arr, 0);

    vsc_buffer_delete(new_wrap);

    return ret;
}

