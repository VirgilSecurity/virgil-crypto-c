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

#include "PythiaJNI.h"

#include "vscp_pythia_public.h"

#include <string.h>

jint throwPythiaException (JNIEnv *jenv, jobject jobj, jint statusCode) {
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/pythia/PythiaException");
    if (NULL == cls) {
        VSCP_ASSERT("Class PheException not found.");
        return 0;
    }

    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");
    if (NULL == methodID) {
        VSCP_ASSERT("Class com/virgilsecurity/crypto/pythia/PythiaException has no constructor.");
        return 0;
    }
    jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);
    if (NULL == obj) {
        VSCP_ASSERT("Can't instantiate com/virgilsecurity/crypto/pythia/PythiaException.");
        return 0;
    }
    return (*jenv)->Throw(jenv, obj);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1configure (JNIEnv *jenv, jobject jobj) {
    vscp_status_t status = vscp_pythia_configure();
    if (status != vscp_status_SUCCESS) {
        throwPythiaException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1cleanup (JNIEnv *jenv, jobject jobj) {
    vscp_pythia_cleanup();
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1blindedPasswordBufLen (JNIEnv *jenv, jobject jobj) {
    jint ret = (jint) vscp_pythia_blinded_password_buf_len();
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1deblindedPasswordBufLen (JNIEnv *jenv, jobject jobj) {
    jint ret = (jint) vscp_pythia_deblinded_password_buf_len();
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1blindingSecretBufLen (JNIEnv *jenv, jobject jobj) {
    jint ret = (jint) vscp_pythia_blinding_secret_buf_len();
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformationPrivateKeyBufLen (JNIEnv *jenv, jobject jobj) {
    jint ret = (jint) vscp_pythia_transformation_private_key_buf_len();
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformationPublicKeyBufLen (JNIEnv *jenv, jobject jobj) {
    jint ret = (jint) vscp_pythia_transformation_public_key_buf_len();
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformedPasswordBufLen (JNIEnv *jenv, jobject jobj) {
    jint ret = (jint) vscp_pythia_transformed_password_buf_len();
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transformedTweakBufLen (JNIEnv *jenv, jobject jobj) {
    jint ret = (jint) vscp_pythia_transformed_tweak_buf_len();
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1proofValueBufLen (JNIEnv *jenv, jobject jobj) {
    jint ret = (jint) vscp_pythia_proof_value_buf_len();
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1passwordUpdateTokenBufLen (JNIEnv *jenv, jobject jobj) {
    jint ret = (jint) vscp_pythia_password_update_token_buf_len();
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1blind (JNIEnv *jenv, jobject jobj, jbyteArray jpassword) {
    // Wrap input data
    byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
    vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

    vsc_buffer_t *blinded_password = vsc_buffer_new_with_capacity(vscp_pythia_blinded_password_buf_len());

    vsc_buffer_t *blinding_secret = vsc_buffer_new_with_capacity(vscp_pythia_blinding_secret_buf_len());

    vscp_status_t status = vscp_pythia_blind(password /*a3*/, blinded_password /*a3*/, blinding_secret /*a3*/);
    if (status != vscp_status_SUCCESS) {
        throwPythiaException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/pythia/PythiaBlindResult");
    if (NULL == cls) {
        VSCP_ASSERT("Class PythiaBlindResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidBlindedPassword = (*jenv)->GetFieldID(jenv, cls, "blindedPassword", "[B");
    jbyteArray jBlindedPasswordArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(blinded_password));
    (*jenv)->SetByteArrayRegion (jenv, jBlindedPasswordArr, 0, vsc_buffer_len(blinded_password), (jbyte*) vsc_buffer_bytes(blinded_password));
    (*jenv)->SetObjectField(jenv, newObj, fidBlindedPassword, jBlindedPasswordArr);
    jfieldID fidBlindingSecret = (*jenv)->GetFieldID(jenv, cls, "blindingSecret", "[B");
    jbyteArray jBlindingSecretArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(blinding_secret));
    (*jenv)->SetByteArrayRegion (jenv, jBlindingSecretArr, 0, vsc_buffer_len(blinding_secret), (jbyte*) vsc_buffer_bytes(blinding_secret));
    (*jenv)->SetObjectField(jenv, newObj, fidBlindingSecret, jBlindingSecretArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

    vsc_buffer_delete(blinded_password);

    vsc_buffer_delete(blinding_secret);

    return newObj;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1deblind (JNIEnv *jenv, jobject jobj, jbyteArray jtransformedPassword, jbyteArray jblindingSecret) {
    // Wrap input data
    byte* transformed_password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtransformedPassword, NULL);
    vsc_data_t transformed_password = vsc_data(transformed_password_arr, (*jenv)->GetArrayLength(jenv, jtransformedPassword));

    byte* blinding_secret_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jblindingSecret, NULL);
    vsc_data_t blinding_secret = vsc_data(blinding_secret_arr, (*jenv)->GetArrayLength(jenv, jblindingSecret));

    vsc_buffer_t *deblinded_password = vsc_buffer_new_with_capacity(vscp_pythia_deblinded_password_buf_len());

    vscp_status_t status = vscp_pythia_deblind(transformed_password /*a3*/, blinding_secret /*a3*/, deblinded_password /*a3*/);
    if (status != vscp_status_SUCCESS) {
        throwPythiaException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(deblinded_password));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(deblinded_password), (jbyte*) vsc_buffer_bytes(deblinded_password));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jtransformedPassword, (jbyte*) transformed_password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jblindingSecret, (jbyte*) blinding_secret_arr, 0);

    vsc_buffer_delete(deblinded_password);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1computeTransformationKeyPair (JNIEnv *jenv, jobject jobj, jbyteArray jtransformationKeyId, jbyteArray jpythiaSecret, jbyteArray jpythiaScopeSecret) {
    // Wrap input data
    byte* transformation_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtransformationKeyId, NULL);
    vsc_data_t transformation_key_id = vsc_data(transformation_key_id_arr, (*jenv)->GetArrayLength(jenv, jtransformationKeyId));

    byte* pythia_secret_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpythiaSecret, NULL);
    vsc_data_t pythia_secret = vsc_data(pythia_secret_arr, (*jenv)->GetArrayLength(jenv, jpythiaSecret));

    byte* pythia_scope_secret_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpythiaScopeSecret, NULL);
    vsc_data_t pythia_scope_secret = vsc_data(pythia_scope_secret_arr, (*jenv)->GetArrayLength(jenv, jpythiaScopeSecret));

    vsc_buffer_t *transformation_private_key = vsc_buffer_new_with_capacity(vscp_pythia_transformation_private_key_buf_len());

    vsc_buffer_t *transformation_public_key = vsc_buffer_new_with_capacity(vscp_pythia_transformation_public_key_buf_len());

    vscp_status_t status = vscp_pythia_compute_transformation_key_pair(transformation_key_id /*a3*/, pythia_secret /*a3*/, pythia_scope_secret /*a3*/, transformation_private_key /*a3*/, transformation_public_key /*a3*/);
    if (status != vscp_status_SUCCESS) {
        throwPythiaException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/pythia/PythiaComputeTransformationKeyPairResult");
    if (NULL == cls) {
        VSCP_ASSERT("Class PythiaComputeTransformationKeyPairResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidTransformationPrivateKey = (*jenv)->GetFieldID(jenv, cls, "transformationPrivateKey", "[B");
    jbyteArray jTransformationPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(transformation_private_key));
    (*jenv)->SetByteArrayRegion (jenv, jTransformationPrivateKeyArr, 0, vsc_buffer_len(transformation_private_key), (jbyte*) vsc_buffer_bytes(transformation_private_key));
    (*jenv)->SetObjectField(jenv, newObj, fidTransformationPrivateKey, jTransformationPrivateKeyArr);
    jfieldID fidTransformationPublicKey = (*jenv)->GetFieldID(jenv, cls, "transformationPublicKey", "[B");
    jbyteArray jTransformationPublicKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(transformation_public_key));
    (*jenv)->SetByteArrayRegion (jenv, jTransformationPublicKeyArr, 0, vsc_buffer_len(transformation_public_key), (jbyte*) vsc_buffer_bytes(transformation_public_key));
    (*jenv)->SetObjectField(jenv, newObj, fidTransformationPublicKey, jTransformationPublicKeyArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jtransformationKeyId, (jbyte*) transformation_key_id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jpythiaSecret, (jbyte*) pythia_secret_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jpythiaScopeSecret, (jbyte*) pythia_scope_secret_arr, 0);

    vsc_buffer_delete(transformation_private_key);

    vsc_buffer_delete(transformation_public_key);

    return newObj;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1transform (JNIEnv *jenv, jobject jobj, jbyteArray jblindedPassword, jbyteArray jtweak, jbyteArray jtransformationPrivateKey) {
    // Wrap input data
    byte* blinded_password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jblindedPassword, NULL);
    vsc_data_t blinded_password = vsc_data(blinded_password_arr, (*jenv)->GetArrayLength(jenv, jblindedPassword));

    byte* tweak_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtweak, NULL);
    vsc_data_t tweak = vsc_data(tweak_arr, (*jenv)->GetArrayLength(jenv, jtweak));

    byte* transformation_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtransformationPrivateKey, NULL);
    vsc_data_t transformation_private_key = vsc_data(transformation_private_key_arr, (*jenv)->GetArrayLength(jenv, jtransformationPrivateKey));

    vsc_buffer_t *transformed_password = vsc_buffer_new_with_capacity(vscp_pythia_transformed_password_buf_len());

    vsc_buffer_t *transformed_tweak = vsc_buffer_new_with_capacity(vscp_pythia_transformed_tweak_buf_len());

    vscp_status_t status = vscp_pythia_transform(blinded_password /*a3*/, tweak /*a3*/, transformation_private_key /*a3*/, transformed_password /*a3*/, transformed_tweak /*a3*/);
    if (status != vscp_status_SUCCESS) {
        throwPythiaException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/pythia/PythiaTransformResult");
    if (NULL == cls) {
        VSCP_ASSERT("Class PythiaTransformResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidTransformedPassword = (*jenv)->GetFieldID(jenv, cls, "transformedPassword", "[B");
    jbyteArray jTransformedPasswordArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(transformed_password));
    (*jenv)->SetByteArrayRegion (jenv, jTransformedPasswordArr, 0, vsc_buffer_len(transformed_password), (jbyte*) vsc_buffer_bytes(transformed_password));
    (*jenv)->SetObjectField(jenv, newObj, fidTransformedPassword, jTransformedPasswordArr);
    jfieldID fidTransformedTweak = (*jenv)->GetFieldID(jenv, cls, "transformedTweak", "[B");
    jbyteArray jTransformedTweakArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(transformed_tweak));
    (*jenv)->SetByteArrayRegion (jenv, jTransformedTweakArr, 0, vsc_buffer_len(transformed_tweak), (jbyte*) vsc_buffer_bytes(transformed_tweak));
    (*jenv)->SetObjectField(jenv, newObj, fidTransformedTweak, jTransformedTweakArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jblindedPassword, (jbyte*) blinded_password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jtweak, (jbyte*) tweak_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jtransformationPrivateKey, (jbyte*) transformation_private_key_arr, 0);

    vsc_buffer_delete(transformed_password);

    vsc_buffer_delete(transformed_tweak);

    return newObj;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1prove (JNIEnv *jenv, jobject jobj, jbyteArray jtransformedPassword, jbyteArray jblindedPassword, jbyteArray jtransformedTweak, jbyteArray jtransformationPrivateKey, jbyteArray jtransformationPublicKey) {
    // Wrap input data
    byte* transformed_password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtransformedPassword, NULL);
    vsc_data_t transformed_password = vsc_data(transformed_password_arr, (*jenv)->GetArrayLength(jenv, jtransformedPassword));

    byte* blinded_password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jblindedPassword, NULL);
    vsc_data_t blinded_password = vsc_data(blinded_password_arr, (*jenv)->GetArrayLength(jenv, jblindedPassword));

    byte* transformed_tweak_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtransformedTweak, NULL);
    vsc_data_t transformed_tweak = vsc_data(transformed_tweak_arr, (*jenv)->GetArrayLength(jenv, jtransformedTweak));

    byte* transformation_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtransformationPrivateKey, NULL);
    vsc_data_t transformation_private_key = vsc_data(transformation_private_key_arr, (*jenv)->GetArrayLength(jenv, jtransformationPrivateKey));

    byte* transformation_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtransformationPublicKey, NULL);
    vsc_data_t transformation_public_key = vsc_data(transformation_public_key_arr, (*jenv)->GetArrayLength(jenv, jtransformationPublicKey));

    vsc_buffer_t *proof_value_c = vsc_buffer_new_with_capacity(vscp_pythia_proof_value_buf_len());

    vsc_buffer_t *proof_value_u = vsc_buffer_new_with_capacity(vscp_pythia_proof_value_buf_len());

    vscp_status_t status = vscp_pythia_prove(transformed_password /*a3*/, blinded_password /*a3*/, transformed_tweak /*a3*/, transformation_private_key /*a3*/, transformation_public_key /*a3*/, proof_value_c /*a3*/, proof_value_u /*a3*/);
    if (status != vscp_status_SUCCESS) {
        throwPythiaException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/pythia/PythiaProveResult");
    if (NULL == cls) {
        VSCP_ASSERT("Class PythiaProveResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidProofValueC = (*jenv)->GetFieldID(jenv, cls, "proofValueC", "[B");
    jbyteArray jProofValueCArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(proof_value_c));
    (*jenv)->SetByteArrayRegion (jenv, jProofValueCArr, 0, vsc_buffer_len(proof_value_c), (jbyte*) vsc_buffer_bytes(proof_value_c));
    (*jenv)->SetObjectField(jenv, newObj, fidProofValueC, jProofValueCArr);
    jfieldID fidProofValueU = (*jenv)->GetFieldID(jenv, cls, "proofValueU", "[B");
    jbyteArray jProofValueUArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(proof_value_u));
    (*jenv)->SetByteArrayRegion (jenv, jProofValueUArr, 0, vsc_buffer_len(proof_value_u), (jbyte*) vsc_buffer_bytes(proof_value_u));
    (*jenv)->SetObjectField(jenv, newObj, fidProofValueU, jProofValueUArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jtransformedPassword, (jbyte*) transformed_password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jblindedPassword, (jbyte*) blinded_password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jtransformedTweak, (jbyte*) transformed_tweak_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jtransformationPrivateKey, (jbyte*) transformation_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jtransformationPublicKey, (jbyte*) transformation_public_key_arr, 0);

    vsc_buffer_delete(proof_value_c);

    vsc_buffer_delete(proof_value_u);

    return newObj;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1verify (JNIEnv *jenv, jobject jobj, jbyteArray jtransformedPassword, jbyteArray jblindedPassword, jbyteArray jtweak, jbyteArray jtransformationPublicKey, jbyteArray jproofValueC, jbyteArray jproofValueU) {
    // Wrap input data
    byte* transformed_password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtransformedPassword, NULL);
    vsc_data_t transformed_password = vsc_data(transformed_password_arr, (*jenv)->GetArrayLength(jenv, jtransformedPassword));

    byte* blinded_password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jblindedPassword, NULL);
    vsc_data_t blinded_password = vsc_data(blinded_password_arr, (*jenv)->GetArrayLength(jenv, jblindedPassword));

    byte* tweak_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtweak, NULL);
    vsc_data_t tweak = vsc_data(tweak_arr, (*jenv)->GetArrayLength(jenv, jtweak));

    byte* transformation_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtransformationPublicKey, NULL);
    vsc_data_t transformation_public_key = vsc_data(transformation_public_key_arr, (*jenv)->GetArrayLength(jenv, jtransformationPublicKey));

    byte* proof_value_c_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jproofValueC, NULL);
    vsc_data_t proof_value_c = vsc_data(proof_value_c_arr, (*jenv)->GetArrayLength(jenv, jproofValueC));

    byte* proof_value_u_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jproofValueU, NULL);
    vsc_data_t proof_value_u = vsc_data(proof_value_u_arr, (*jenv)->GetArrayLength(jenv, jproofValueU));

    vscp_status_t status = vscp_pythia_verify(transformed_password /*a3*/, blinded_password /*a3*/, tweak /*a3*/, transformation_public_key /*a3*/, proof_value_c /*a3*/, proof_value_u /*a3*/);
    if (status != vscp_status_SUCCESS) {
        throwPythiaException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jtransformedPassword, (jbyte*) transformed_password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jblindedPassword, (jbyte*) blinded_password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jtweak, (jbyte*) tweak_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jtransformationPublicKey, (jbyte*) transformation_public_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jproofValueC, (jbyte*) proof_value_c_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jproofValueU, (jbyte*) proof_value_u_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1getPasswordUpdateToken (JNIEnv *jenv, jobject jobj, jbyteArray jpreviousTransformationPrivateKey, jbyteArray jnewTransformationPrivateKey) {
    // Wrap input data
    byte* previous_transformation_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpreviousTransformationPrivateKey, NULL);
    vsc_data_t previous_transformation_private_key = vsc_data(previous_transformation_private_key_arr, (*jenv)->GetArrayLength(jenv, jpreviousTransformationPrivateKey));

    byte* new_transformation_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jnewTransformationPrivateKey, NULL);
    vsc_data_t new_transformation_private_key = vsc_data(new_transformation_private_key_arr, (*jenv)->GetArrayLength(jenv, jnewTransformationPrivateKey));

    vsc_buffer_t *password_update_token = vsc_buffer_new_with_capacity(vscp_pythia_password_update_token_buf_len());

    vscp_status_t status = vscp_pythia_get_password_update_token(previous_transformation_private_key /*a3*/, new_transformation_private_key /*a3*/, password_update_token /*a3*/);
    if (status != vscp_status_SUCCESS) {
        throwPythiaException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(password_update_token));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(password_update_token), (jbyte*) vsc_buffer_bytes(password_update_token));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpreviousTransformationPrivateKey, (jbyte*) previous_transformation_private_key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jnewTransformationPrivateKey, (jbyte*) new_transformation_private_key_arr, 0);

    vsc_buffer_delete(password_update_token);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_pythia_PythiaJNI_pythia_1updateDeblindedWithToken (JNIEnv *jenv, jobject jobj, jbyteArray jdeblindedPassword, jbyteArray jpasswordUpdateToken) {
    // Wrap input data
    byte* deblinded_password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdeblindedPassword, NULL);
    vsc_data_t deblinded_password = vsc_data(deblinded_password_arr, (*jenv)->GetArrayLength(jenv, jdeblindedPassword));

    byte* password_update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpasswordUpdateToken, NULL);
    vsc_data_t password_update_token = vsc_data(password_update_token_arr, (*jenv)->GetArrayLength(jenv, jpasswordUpdateToken));

    vsc_buffer_t *updated_deblinded_password = vsc_buffer_new_with_capacity(vscp_pythia_deblinded_password_buf_len());

    vscp_status_t status = vscp_pythia_update_deblinded_with_token(deblinded_password /*a3*/, password_update_token /*a3*/, updated_deblinded_password /*a3*/);
    if (status != vscp_status_SUCCESS) {
        throwPythiaException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(updated_deblinded_password));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(updated_deblinded_password), (jbyte*) vsc_buffer_bytes(updated_deblinded_password));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdeblindedPassword, (jbyte*) deblinded_password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jpasswordUpdateToken, (jbyte*) password_update_token_arr, 0);

    vsc_buffer_delete(updated_deblinded_password);

    return ret;
}

