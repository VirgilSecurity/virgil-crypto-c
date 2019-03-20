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

#include <stdio.h>

#include <string.h>

#include "virgil_crypto_phe_PheJNI.h"

#include <virgil/crypto/phe/vsce_error.h>

#include <virgil/crypto/phe/vsce_phe_server.h>

#include <virgil/crypto/phe/vsce_phe_client.h>

#include <virgil/crypto/phe/vsce_phe_cipher.h>

jint throwPheException (JNIEnv *jenv, jobject jobj, jint statusCode) {
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/phe/PheException");
    if (NULL == cls) {
        printf("Class PheException not found.");
        return 0;
    }

    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");
    if (NULL == methodID) {
        printf("Class virgil/crypto/phe/PheException has no constructor.");
        return 0;
    }
    jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);
    if (NULL == obj) {
        printf("Can't instantiate virgil/crypto/phe/PheException.");
        return 0;
    }
    return (*jenv)->Throw(jenv, obj);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_error_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vsce_alloc(vsce_error_ctx_size());
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_error_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_dealloc((vsce_error_t /*2*/ *) c_ctx /*4*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_error_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_error_reset((vsce_error_t /*2*/ *) c_ctx /*1*/);
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_phe_PheJNI_error_1hasError (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vsce_error_has_error((vsce_error_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_error_1status (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_status_t status = vsce_error_status((vsce_error_t /*2*/ *) c_ctx /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vsce_phe_server_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_phe_server_delete((vsce_phe_server_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vsce_phe_server_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vsce_phe_server_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1setOperationRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject joperationRandom) {
    jclass operation_random_cls = (*jenv)->GetObjectClass(jenv, joperationRandom);
    if (NULL == operation_random_cls) {
        printf("Class Random not found.");
    }
    jfieldID operation_random_fidCtx = (*jenv)->GetFieldID(jenv, operation_random_cls, "cCtx", "J");
    if (NULL == operation_random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ operation_random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, joperationRandom, operation_random_fidCtx);

    vsce_phe_server_release_operation_random((vscf_impl_t */*6*/ *) c_ctx);
    vsce_phe_server_use_operation_random((vscf_impl_t */*6*/ *) c_ctx, operation_random);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1generateServerKeyPair (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_phe_server_generate_server_key_pair((vsce_phe_server_t /*2*/ *) c_ctx /*1*/, server_private_key /*1*/, server_public_key /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/phe/PheServerGenerateServerKeyPairResult");
    if (NULL == cls) {
        printf("Class PheServerGenerateServerKeyPairResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidServerPrivateKey = (*jenv)->GetFieldID(jenv, cls, "serverPrivateKey", "[B");
    jbyteArray jServerPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(server_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jServerPrivateKeyArr, 0, vsc_buffer_len(server_private_key), vsc_buffer_bytes(server_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidServerPrivateKey, jServerPrivateKeyArr);
    jfieldID fidServerPublicKey = (*jenv)->GetFieldID(jenv, cls, "serverPublicKey", "[B");
    jbyteArray jServerPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(server_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jServerPublicKeyArr, 0, vsc_buffer_len(server_public_key), vsc_buffer_bytes(server_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidServerPublicKey, jServerPublicKeyArr);
    // Free resources
    vsc_buffer_delete(server_private_key);

    vsc_buffer_delete(server_public_key);

    return newObj;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1enrollmentResponseLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vsce_phe_server_enrollment_response_len((vsce_phe_server_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1getEnrollment (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey) {
    // Wrap input data
    vsc_data_t server_private_key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL),
        (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

    vsc_data_t server_public_key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL),
        (*jenv)->GetArrayLength(jenv, jserverPublicKey));

    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len((vsce_phe_server_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_server_get_enrollment((vsce_phe_server_t /*2*/ *) c_ctx /*1*/, server_private_key /*1*/, server_public_key /*1*/, enrollment_response /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(enrollment_response));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(enrollment_response), vsc_buffer_bytes(enrollment_response));
    // Free resources
    vsc_buffer_delete(enrollment_response);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1verifyPasswordResponseLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vsce_phe_server_verify_password_response_len((vsce_phe_server_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1verifyPassword (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey, jbyteArray jverifyPasswordRequest) {
    // Wrap input data
    vsc_data_t server_private_key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL),
        (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

    vsc_data_t server_public_key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL),
        (*jenv)->GetArrayLength(jenv, jserverPublicKey));

    vsc_data_t verify_password_request = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jverifyPasswordRequest, NULL),
        (*jenv)->GetArrayLength(jenv, jverifyPasswordRequest));

    vsc_buffer_t *verify_password_response = vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len((vsce_phe_server_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_server_verify_password((vsce_phe_server_t /*2*/ *) c_ctx /*1*/, server_private_key /*1*/, server_public_key /*1*/, verify_password_request /*1*/, verify_password_response /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(verify_password_response));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(verify_password_response), vsc_buffer_bytes(verify_password_response));
    // Free resources
    vsc_buffer_delete(verify_password_response);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1updateTokenLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vsce_phe_server_update_token_len((vsce_phe_server_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1rotateKeys (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey) {
    // Wrap input data
    vsc_data_t server_private_key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL),
        (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

    vsc_buffer_t *new_server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(vsce_phe_server_update_token_len((vsce_phe_server_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_server_rotate_keys((vsce_phe_server_t /*2*/ *) c_ctx /*1*/, server_private_key /*1*/, new_server_private_key /*1*/, new_server_public_key /*1*/, update_token /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/phe/PheServerRotateKeysResult");
    if (NULL == cls) {
        printf("Class PheServerRotateKeysResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidNewServerPrivateKey = (*jenv)->GetFieldID(jenv, cls, "newServerPrivateKey", "[B");
    jbyteArray jNewServerPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewServerPrivateKeyArr, 0, vsc_buffer_len(new_server_private_key), vsc_buffer_bytes(new_server_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewServerPrivateKey, jNewServerPrivateKeyArr);
    jfieldID fidNewServerPublicKey = (*jenv)->GetFieldID(jenv, cls, "newServerPublicKey", "[B");
    jbyteArray jNewServerPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewServerPublicKeyArr, 0, vsc_buffer_len(new_server_public_key), vsc_buffer_bytes(new_server_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewServerPublicKey, jNewServerPublicKeyArr);
    jfieldID fidUpdateToken = (*jenv)->GetFieldID(jenv, cls, "updateToken", "[B");
    jbyteArray jUpdateTokenArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(update_token));
    (*jenv)->SetByteArrayRegion (jenv, jUpdateTokenArr, 0, vsc_buffer_len(update_token), vsc_buffer_bytes(update_token));
    (*jenv)->SetObjectField(jenv, newObj, fidUpdateToken, jUpdateTokenArr);
    // Free resources
    vsc_buffer_delete(new_server_private_key);

    vsc_buffer_delete(new_server_public_key);

    vsc_buffer_delete(update_token);

    return newObj;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vsce_phe_client_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_phe_client_delete((vsce_phe_client_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vsce_phe_client_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vsce_phe_client_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1setOperationRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject joperationRandom) {
    jclass operation_random_cls = (*jenv)->GetObjectClass(jenv, joperationRandom);
    if (NULL == operation_random_cls) {
        printf("Class Random not found.");
    }
    jfieldID operation_random_fidCtx = (*jenv)->GetFieldID(jenv, operation_random_cls, "cCtx", "J");
    if (NULL == operation_random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ operation_random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, joperationRandom, operation_random_fidCtx);

    vsce_phe_client_release_operation_random((vscf_impl_t */*6*/ *) c_ctx);
    vsce_phe_client_use_operation_random((vscf_impl_t */*6*/ *) c_ctx, operation_random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1setKeys (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jclientPrivateKey, jbyteArray jserverPublicKey) {
    // Wrap input data
    vsc_data_t client_private_key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jclientPrivateKey, NULL),
        (*jenv)->GetArrayLength(jenv, jclientPrivateKey));

    vsc_data_t server_public_key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL),
        (*jenv)->GetArrayLength(jenv, jserverPublicKey));

    vsce_status_t status = vsce_phe_client_set_keys((vsce_phe_client_t /*2*/ *) c_ctx /*1*/, client_private_key /*1*/, server_public_key /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1generateClientPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsce_status_t status = vsce_phe_client_generate_client_private_key((vsce_phe_client_t /*2*/ *) c_ctx /*1*/, client_private_key /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(client_private_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(client_private_key), vsc_buffer_bytes(client_private_key));
    // Free resources
    vsc_buffer_delete(client_private_key);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1enrollmentRecordLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vsce_phe_client_enrollment_record_len((vsce_phe_client_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1enrollAccount (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jenrollmentResponse, jbyteArray jpassword) {
    // Wrap input data
    vsc_data_t enrollment_response = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jenrollmentResponse, NULL),
        (*jenv)->GetArrayLength(jenv, jenrollmentResponse));

    vsc_data_t password = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpassword, NULL),
        (*jenv)->GetArrayLength(jenv, jpassword));

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len((vsce_phe_client_t /*2*/ *) c_ctx /*3*/));

    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

    vsce_status_t status = vsce_phe_client_enroll_account((vsce_phe_client_t /*2*/ *) c_ctx /*1*/, enrollment_response /*1*/, password /*1*/, enrollment_record /*1*/, account_key /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/phe/PheClientEnrollAccountResult");
    if (NULL == cls) {
        printf("Class PheClientEnrollAccountResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidEnrollmentRecord = (*jenv)->GetFieldID(jenv, cls, "enrollmentRecord", "[B");
    jbyteArray jEnrollmentRecordArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(enrollment_record));
    (*jenv)->SetByteArrayRegion (jenv, jEnrollmentRecordArr, 0, vsc_buffer_len(enrollment_record), vsc_buffer_bytes(enrollment_record));
    (*jenv)->SetObjectField(jenv, newObj, fidEnrollmentRecord, jEnrollmentRecordArr);
    jfieldID fidAccountKey = (*jenv)->GetFieldID(jenv, cls, "accountKey", "[B");
    jbyteArray jAccountKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(account_key));
    (*jenv)->SetByteArrayRegion (jenv, jAccountKeyArr, 0, vsc_buffer_len(account_key), vsc_buffer_bytes(account_key));
    (*jenv)->SetObjectField(jenv, newObj, fidAccountKey, jAccountKeyArr);
    // Free resources
    vsc_buffer_delete(enrollment_record);

    vsc_buffer_delete(account_key);

    return newObj;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1verifyPasswordRequestLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vsce_phe_client_verify_password_request_len((vsce_phe_client_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1createVerifyPasswordRequest (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord) {
    // Wrap input data
    vsc_data_t password = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpassword, NULL),
        (*jenv)->GetArrayLength(jenv, jpassword));

    vsc_data_t enrollment_record = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, NULL),
        (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

    vsc_buffer_t *verify_password_request = vsc_buffer_new_with_capacity(vsce_phe_client_verify_password_request_len((vsce_phe_client_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_client_create_verify_password_request((vsce_phe_client_t /*2*/ *) c_ctx /*1*/, password /*1*/, enrollment_record /*1*/, verify_password_request /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(verify_password_request));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(verify_password_request), vsc_buffer_bytes(verify_password_request));
    // Free resources
    vsc_buffer_delete(verify_password_request);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1checkResponseAndDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord, jbyteArray jverifyPasswordResponse) {
    // Wrap input data
    vsc_data_t password = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpassword, NULL),
        (*jenv)->GetArrayLength(jenv, jpassword));

    vsc_data_t enrollment_record = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, NULL),
        (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

    vsc_data_t verify_password_response = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jverifyPasswordResponse, NULL),
        (*jenv)->GetArrayLength(jenv, jverifyPasswordResponse));

    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

    vsce_status_t status = vsce_phe_client_check_response_and_decrypt((vsce_phe_client_t /*2*/ *) c_ctx /*1*/, password /*1*/, enrollment_record /*1*/, verify_password_response /*1*/, account_key /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(account_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(account_key), vsc_buffer_bytes(account_key));
    // Free resources
    vsc_buffer_delete(account_key);

    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1rotateKeys (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jupdateToken) {
    // Wrap input data
    vsc_data_t update_token = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL),
        (*jenv)->GetArrayLength(jenv, jupdateToken));

    vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_status_t status = vsce_phe_client_rotate_keys((vsce_phe_client_t /*2*/ *) c_ctx /*1*/, update_token /*1*/, new_client_private_key /*1*/, new_server_public_key /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/phe/PheClientRotateKeysResult");
    if (NULL == cls) {
        printf("Class PheClientRotateKeysResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidNewClientPrivateKey = (*jenv)->GetFieldID(jenv, cls, "newClientPrivateKey", "[B");
    jbyteArray jNewClientPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_client_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewClientPrivateKeyArr, 0, vsc_buffer_len(new_client_private_key), vsc_buffer_bytes(new_client_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewClientPrivateKey, jNewClientPrivateKeyArr);
    jfieldID fidNewServerPublicKey = (*jenv)->GetFieldID(jenv, cls, "newServerPublicKey", "[B");
    jbyteArray jNewServerPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jNewServerPublicKeyArr, 0, vsc_buffer_len(new_server_public_key), vsc_buffer_bytes(new_server_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidNewServerPublicKey, jNewServerPublicKeyArr);
    // Free resources
    vsc_buffer_delete(new_client_private_key);

    vsc_buffer_delete(new_server_public_key);

    return newObj;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1updateEnrollmentRecord (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jenrollmentRecord, jbyteArray jupdateToken) {
    // Wrap input data
    vsc_data_t enrollment_record = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, NULL),
        (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

    vsc_data_t update_token = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL),
        (*jenv)->GetArrayLength(jenv, jupdateToken));

    vsc_buffer_t *new_enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len((vsce_phe_client_t /*2*/ *) c_ctx /*3*/));

    vsce_status_t status = vsce_phe_client_update_enrollment_record((vsce_phe_client_t /*2*/ *) c_ctx /*1*/, enrollment_record /*1*/, update_token /*1*/, new_enrollment_record /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_enrollment_record));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(new_enrollment_record), vsc_buffer_bytes(new_enrollment_record));
    // Free resources
    vsc_buffer_delete(new_enrollment_record);

    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vsce_phe_cipher_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_phe_cipher_delete((vsce_phe_cipher_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vsce_phe_cipher_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vsce_phe_cipher_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsce_phe_cipher_setup_defaults((vsce_phe_cipher_t /*2*/ *) c_ctx /*1*/);
}

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1encryptLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jplainTextLen) {
    jint ret = vsce_phe_cipher_encrypt_len((vsce_phe_cipher_t /*2*/ *) c_ctx /*1*/, jplainTextLen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1decryptLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jcipherTextLen) {
    jint ret = vsce_phe_cipher_decrypt_len((vsce_phe_cipher_t /*2*/ *) c_ctx /*1*/, jcipherTextLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jplainText, jbyteArray jaccountKey) {
    // Wrap input data
    vsc_data_t plain_text = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jplainText, NULL),
        (*jenv)->GetArrayLength(jenv, jplainText));

    vsc_data_t account_key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL),
        (*jenv)->GetArrayLength(jenv, jaccountKey));

    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_encrypt_len((vsce_phe_cipher_t /*2*/ *) c_ctx /*3*/, plain_text.len/*a*/));

    vsce_status_t status = vsce_phe_cipher_encrypt((vsce_phe_cipher_t /*2*/ *) c_ctx /*1*/, plain_text /*1*/, account_key /*1*/, cipher_text /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(cipher_text));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(cipher_text), vsc_buffer_bytes(cipher_text));
    // Free resources
    vsc_buffer_delete(cipher_text);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jcipherText, jbyteArray jaccountKey) {
    // Wrap input data
    vsc_data_t cipher_text = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jcipherText, NULL),
        (*jenv)->GetArrayLength(jenv, jcipherText));

    vsc_data_t account_key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL),
        (*jenv)->GetArrayLength(jenv, jaccountKey));

    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_decrypt_len((vsce_phe_cipher_t /*2*/ *) c_ctx /*3*/, cipher_text.len/*a*/));

    vsce_status_t status = vsce_phe_cipher_decrypt((vsce_phe_cipher_t /*2*/ *) c_ctx /*1*/, cipher_text /*1*/, account_key /*1*/, plain_text /*1*/);
    if (status != vsce_status_SUCCESS) {
        throwPheException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), vsc_buffer_bytes(plain_text));
    // Free resources
    vsc_buffer_delete(plain_text);

    return ret;
}

