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

#include "virgil_crypto_foundation_FoundationJNI.h"

#include <virgil/crypto/foundation/vscf_error.h>

#include <virgil/crypto/foundation/vscf_raw_key.h>

#include <virgil/crypto/foundation/vscf_oid.h>

#include <virgil/crypto/foundation/vscf_base64.h>

#include <virgil/crypto/foundation/vscf_pem.h>

#include <virgil/crypto/foundation/vscf_message_info.h>

#include <virgil/crypto/foundation/vscf_key_recipient_info.h>

#include <virgil/crypto/foundation/vscf_key_recipient_info_list.h>

#include <virgil/crypto/foundation/vscf_password_recipient_info.h>

#include <virgil/crypto/foundation/vscf_password_recipient_info_list.h>

#include <virgil/crypto/foundation/vscf_alg_factory.h>

#include <virgil/crypto/foundation/vscf_recipient_cipher.h>

#include <virgil/crypto/foundation/vscf_list_key_value_node.h>

#include <virgil/crypto/foundation/vscf_message_info_custom_params.h>

#include <virgil/crypto/foundation/vscf_key_provider.h>

#include <virgil/crypto/foundation/vscf_signer.h>

#include <virgil/crypto/foundation/vscf_verifier.h>

#include <virgil/crypto/foundation/vscf_sha224.h>

#include <virgil/crypto/foundation/vscf_sha256.h>

#include <virgil/crypto/foundation/vscf_sha384.h>

#include <virgil/crypto/foundation/vscf_sha512.h>

#include <virgil/crypto/foundation/vscf_aes256_gcm.h>

#include <virgil/crypto/foundation/vscf_aes256_cbc.h>

#include <virgil/crypto/foundation/vscf_asn1rd.h>

#include <virgil/crypto/foundation/vscf_asn1wr.h>

#include <virgil/crypto/foundation/vscf_rsa_public_key.h>

#include <virgil/crypto/foundation/vscf_rsa_private_key.h>

#include <virgil/crypto/foundation/vscf_entropy_accumulator.h>

#include <virgil/crypto/foundation/vscf_ctr_drbg.h>

#include <virgil/crypto/foundation/vscf_hmac.h>

#include <virgil/crypto/foundation/vscf_hkdf.h>

#include <virgil/crypto/foundation/vscf_kdf1.h>

#include <virgil/crypto/foundation/vscf_kdf2.h>

#include <virgil/crypto/foundation/vscf_fake_random.h>

#include <virgil/crypto/foundation/vscf_pkcs5_pbkdf2.h>

#include <virgil/crypto/foundation/vscf_pkcs5_pbes2.h>

#include <virgil/crypto/foundation/vscf_pkcs8_der_serializer.h>

#include <virgil/crypto/foundation/vscf_pkcs8_der_deserializer.h>

#include <virgil/crypto/foundation/vscf_pkcs8_serializer.h>

#include <virgil/crypto/foundation/vscf_pkcs8_deserializer.h>

#include <virgil/crypto/foundation/vscf_ed25519_public_key.h>

#include <virgil/crypto/foundation/vscf_ed25519_private_key.h>

#include <virgil/crypto/foundation/vscf_curve25519_public_key.h>

#include <virgil/crypto/foundation/vscf_curve25519_private_key.h>

#include <virgil/crypto/foundation/vscf_ecies.h>

#include <virgil/crypto/foundation/vscf_simple_alg_info.h>

#include <virgil/crypto/foundation/vscf_hash_based_alg_info.h>

#include <virgil/crypto/foundation/vscf_cipher_alg_info.h>

#include <virgil/crypto/foundation/vscf_salted_kdf_alg_info.h>

#include <virgil/crypto/foundation/vscf_pbe_alg_info.h>

#include <virgil/crypto/foundation/vscf_alg_info_der_serializer.h>

#include <virgil/crypto/foundation/vscf_alg_info_der_deserializer.h>

#include <virgil/crypto/foundation/vscf_message_info_der_serializer.h>

jint throwFoundationException (JNIEnv *jenv, jobject jobj, jint statusCode) {
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/FoundationException");
    if (NULL == cls) {
        printf("Class PheException not found.");
        return 0;
    }

    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");
    if (NULL == methodID) {
        printf("Class virgil/crypto/foundation/FoundationException has no constructor.");
        return 0;
    }
    jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);
    if (NULL == obj) {
        printf("Can't instantiate virgil/crypto/foundation/FoundationException.");
        return 0;
    }
    return (*jenv)->Throw(jenv, obj);
}

char* getAlgClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_alg_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Alg.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_SHA224:
        strcat (classFullName, "Sha224");
        break;
    case vscf_impl_tag_SHA256:
        strcat (classFullName, "Sha256");
        break;
    case vscf_impl_tag_SHA384:
        strcat (classFullName, "Sha384");
        break;
    case vscf_impl_tag_SHA512:
        strcat (classFullName, "Sha512");
        break;
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    case vscf_impl_tag_AES256_CBC:
        strcat (classFullName, "Aes256Cbc");
        break;
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        strcat (classFullName, "RsaPublicKey");
        break;
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        strcat (classFullName, "RsaPrivateKey");
        break;
    case vscf_impl_tag_HMAC:
        strcat (classFullName, "Hmac");
        break;
    case vscf_impl_tag_HKDF:
        strcat (classFullName, "Hkdf");
        break;
    case vscf_impl_tag_KDF1:
        strcat (classFullName, "Kdf1");
        break;
    case vscf_impl_tag_KDF2:
        strcat (classFullName, "Kdf2");
        break;
    case vscf_impl_tag_PKCS5_PBKDF2:
        strcat (classFullName, "Pkcs5Pbkdf2");
        break;
    case vscf_impl_tag_PKCS5_PBES2:
        strcat (classFullName, "Pkcs5Pbes2");
        break;
    case vscf_impl_tag_ED25519_PUBLIC_KEY:
        strcat (classFullName, "Ed25519PublicKey");
        break;
    case vscf_impl_tag_ED25519_PRIVATE_KEY:
        strcat (classFullName, "Ed25519PrivateKey");
        break;
    case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
        strcat (classFullName, "Curve25519PublicKey");
        break;
    case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
        strcat (classFullName, "Curve25519PrivateKey");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAlg (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getAlgClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getHashClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_hash_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Hash.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_SHA224:
        strcat (classFullName, "Sha224");
        break;
    case vscf_impl_tag_SHA256:
        strcat (classFullName, "Sha256");
        break;
    case vscf_impl_tag_SHA384:
        strcat (classFullName, "Sha384");
        break;
    case vscf_impl_tag_SHA512:
        strcat (classFullName, "Sha512");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapHash (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getHashClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getEncryptClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_encrypt_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Encrypt.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    case vscf_impl_tag_AES256_CBC:
        strcat (classFullName, "Aes256Cbc");
        break;
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        strcat (classFullName, "RsaPublicKey");
        break;
    case vscf_impl_tag_PKCS5_PBES2:
        strcat (classFullName, "Pkcs5Pbes2");
        break;
    case vscf_impl_tag_ED25519_PUBLIC_KEY:
        strcat (classFullName, "Ed25519PublicKey");
        break;
    case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
        strcat (classFullName, "Curve25519PublicKey");
        break;
    case vscf_impl_tag_ECIES:
        strcat (classFullName, "Ecies");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getEncryptClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getDecryptClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_decrypt_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Decrypt.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    case vscf_impl_tag_AES256_CBC:
        strcat (classFullName, "Aes256Cbc");
        break;
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        strcat (classFullName, "RsaPrivateKey");
        break;
    case vscf_impl_tag_PKCS5_PBES2:
        strcat (classFullName, "Pkcs5Pbes2");
        break;
    case vscf_impl_tag_ED25519_PRIVATE_KEY:
        strcat (classFullName, "Ed25519PrivateKey");
        break;
    case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
        strcat (classFullName, "Curve25519PrivateKey");
        break;
    case vscf_impl_tag_ECIES:
        strcat (classFullName, "Ecies");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getDecryptClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getCipherInfoClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_cipher_info_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface CipherInfo.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    case vscf_impl_tag_AES256_CBC:
        strcat (classFullName, "Aes256Cbc");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapCipherInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getCipherInfoClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getCipherClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_cipher_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Cipher.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    case vscf_impl_tag_AES256_CBC:
        strcat (classFullName, "Aes256Cbc");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapCipher (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getCipherClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getCipherAuthInfoClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_cipher_auth_info_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface CipherAuthInfo.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapCipherAuthInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getCipherAuthInfoClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getAuthEncryptClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_auth_encrypt_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface AuthEncrypt.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAuthEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getAuthEncryptClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getAuthDecryptClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_auth_decrypt_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface AuthDecrypt.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAuthDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getAuthDecryptClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getCipherAuthClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_cipher_auth_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface CipherAuth.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapCipherAuth (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getCipherAuthClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getAsn1ReaderClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_asn1_reader_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Asn1Reader.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_ASN1RD:
        strcat (classFullName, "Asn1rd");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAsn1Reader (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getAsn1ReaderClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getAsn1WriterClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_asn1_writer_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Asn1Writer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_ASN1WR:
        strcat (classFullName, "Asn1wr");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getAsn1WriterClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getDefaultsClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_defaults_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Defaults.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        strcat (classFullName, "RsaPublicKey");
        break;
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        strcat (classFullName, "RsaPrivateKey");
        break;
    case vscf_impl_tag_ENTROPY_ACCUMULATOR:
        strcat (classFullName, "EntropyAccumulator");
        break;
    case vscf_impl_tag_CTR_DRBG:
        strcat (classFullName, "CtrDrbg");
        break;
    case vscf_impl_tag_PKCS5_PBKDF2:
        strcat (classFullName, "Pkcs5Pbkdf2");
        break;
    case vscf_impl_tag_PKCS8_DER_SERIALIZER:
        strcat (classFullName, "Pkcs8DerSerializer");
        break;
    case vscf_impl_tag_PKCS8_DER_DESERIALIZER:
        strcat (classFullName, "Pkcs8DerDeserializer");
        break;
    case vscf_impl_tag_PKCS8_SERIALIZER:
        strcat (classFullName, "Pkcs8Serializer");
        break;
    case vscf_impl_tag_PKCS8_DESERIALIZER:
        strcat (classFullName, "Pkcs8Deserializer");
        break;
    case vscf_impl_tag_ED25519_PUBLIC_KEY:
        strcat (classFullName, "Ed25519PublicKey");
        break;
    case vscf_impl_tag_ED25519_PRIVATE_KEY:
        strcat (classFullName, "Ed25519PrivateKey");
        break;
    case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
        strcat (classFullName, "Curve25519PublicKey");
        break;
    case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
        strcat (classFullName, "Curve25519PrivateKey");
        break;
    case vscf_impl_tag_ECIES:
        strcat (classFullName, "Ecies");
        break;
    case vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
        strcat (classFullName, "AlgInfoDerSerializer");
        break;
    case vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
        strcat (classFullName, "AlgInfoDerDeserializer");
        break;
    case vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        strcat (classFullName, "MessageInfoDerSerializer");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getDefaultsClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getKeyClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_key_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Key.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        strcat (classFullName, "RsaPublicKey");
        break;
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        strcat (classFullName, "RsaPrivateKey");
        break;
    case vscf_impl_tag_ED25519_PUBLIC_KEY:
        strcat (classFullName, "Ed25519PublicKey");
        break;
    case vscf_impl_tag_ED25519_PRIVATE_KEY:
        strcat (classFullName, "Ed25519PrivateKey");
        break;
    case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
        strcat (classFullName, "Curve25519PublicKey");
        break;
    case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
        strcat (classFullName, "Curve25519PrivateKey");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getKeyClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getVerifyHashClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_verify_hash_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface VerifyHash.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        strcat (classFullName, "RsaPublicKey");
        break;
    case vscf_impl_tag_ED25519_PUBLIC_KEY:
        strcat (classFullName, "Ed25519PublicKey");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapVerifyHash (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getVerifyHashClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getPublicKeyClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_public_key_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface PublicKey.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        strcat (classFullName, "RsaPublicKey");
        break;
    case vscf_impl_tag_ED25519_PUBLIC_KEY:
        strcat (classFullName, "Ed25519PublicKey");
        break;
    case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
        strcat (classFullName, "Curve25519PublicKey");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getPublicKeyClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getGenerateEphemeralKeyClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_generate_ephemeral_key_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface GenerateEphemeralKey.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        strcat (classFullName, "RsaPublicKey");
        break;
    case vscf_impl_tag_ED25519_PUBLIC_KEY:
        strcat (classFullName, "Ed25519PublicKey");
        break;
    case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
        strcat (classFullName, "Curve25519PublicKey");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapGenerateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getGenerateEphemeralKeyClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getGenerateKeyClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_generate_key_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface GenerateKey.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        strcat (classFullName, "RsaPrivateKey");
        break;
    case vscf_impl_tag_ED25519_PRIVATE_KEY:
        strcat (classFullName, "Ed25519PrivateKey");
        break;
    case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
        strcat (classFullName, "Curve25519PrivateKey");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapGenerateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getGenerateKeyClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getSignHashClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_sign_hash_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface SignHash.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        strcat (classFullName, "RsaPrivateKey");
        break;
    case vscf_impl_tag_ED25519_PRIVATE_KEY:
        strcat (classFullName, "Ed25519PrivateKey");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapSignHash (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getSignHashClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getPrivateKeyClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_private_key_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface PrivateKey.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        strcat (classFullName, "RsaPrivateKey");
        break;
    case vscf_impl_tag_ED25519_PRIVATE_KEY:
        strcat (classFullName, "Ed25519PrivateKey");
        break;
    case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
        strcat (classFullName, "Curve25519PrivateKey");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getPrivateKeyClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getEntropySourceClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_entropy_source_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface EntropySource.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_ENTROPY_ACCUMULATOR:
        strcat (classFullName, "EntropyAccumulator");
        break;
    case vscf_impl_tag_FAKE_RANDOM:
        strcat (classFullName, "FakeRandom");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapEntropySource (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getEntropySourceClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getRandomClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_random_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Random.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_CTR_DRBG:
        strcat (classFullName, "CtrDrbg");
        break;
    case vscf_impl_tag_FAKE_RANDOM:
        strcat (classFullName, "FakeRandom");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getRandomClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getMacClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_mac_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Mac.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_HMAC:
        strcat (classFullName, "Hmac");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapMac (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getMacClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getKdfClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_kdf_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface Kdf.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_HKDF:
        strcat (classFullName, "Hkdf");
        break;
    case vscf_impl_tag_KDF1:
        strcat (classFullName, "Kdf1");
        break;
    case vscf_impl_tag_KDF2:
        strcat (classFullName, "Kdf2");
        break;
    case vscf_impl_tag_PKCS5_PBKDF2:
        strcat (classFullName, "Pkcs5Pbkdf2");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKdf (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getKdfClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getSaltedKdfClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_salted_kdf_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface SaltedKdf.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_HKDF:
        strcat (classFullName, "Hkdf");
        break;
    case vscf_impl_tag_PKCS5_PBKDF2:
        strcat (classFullName, "Pkcs5Pbkdf2");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapSaltedKdf (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getSaltedKdfClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getKeySerializerClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_key_serializer_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface KeySerializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_PKCS8_DER_SERIALIZER:
        strcat (classFullName, "Pkcs8DerSerializer");
        break;
    case vscf_impl_tag_PKCS8_SERIALIZER:
        strcat (classFullName, "Pkcs8Serializer");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKeySerializer (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getKeySerializerClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getKeyDeserializerClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_key_deserializer_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface KeyDeserializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_PKCS8_DER_DESERIALIZER:
        strcat (classFullName, "Pkcs8DerDeserializer");
        break;
    case vscf_impl_tag_PKCS8_DESERIALIZER:
        strcat (classFullName, "Pkcs8Deserializer");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKeyDeserializer (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getKeyDeserializerClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getComputeSharedKeyClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_compute_shared_key_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface ComputeSharedKey.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_ED25519_PRIVATE_KEY:
        strcat (classFullName, "Ed25519PrivateKey");
        break;
    case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
        strcat (classFullName, "Curve25519PrivateKey");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapComputeSharedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getComputeSharedKeyClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getAlgInfoClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_alg_info_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface AlgInfo.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_SIMPLE_ALG_INFO:
        strcat (classFullName, "SimpleAlgInfo");
        break;
    case vscf_impl_tag_HASH_BASED_ALG_INFO:
        strcat (classFullName, "HashBasedAlgInfo");
        break;
    case vscf_impl_tag_CIPHER_ALG_INFO:
        strcat (classFullName, "CipherAlgInfo");
        break;
    case vscf_impl_tag_SALTED_KDF_ALG_INFO:
        strcat (classFullName, "SaltedKdfAlgInfo");
        break;
    case vscf_impl_tag_PBE_ALG_INFO:
        strcat (classFullName, "PbeAlgInfo");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getAlgInfoClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getAlgInfoSerializerClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_alg_info_serializer_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface AlgInfoSerializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
        strcat (classFullName, "AlgInfoDerSerializer");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAlgInfoSerializer (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getAlgInfoSerializerClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getAlgInfoDeserializerClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_alg_info_deserializer_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface AlgInfoDeserializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
        strcat (classFullName, "AlgInfoDerDeserializer");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAlgInfoDeserializer (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getAlgInfoDeserializerClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

char* getMessageInfoSerializerClassName (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    if (!vscf_message_info_serializer_is_implemented(c_ctx)) {
        printf("Given C implementation does not implement interface MessageInfoSerializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "virgil/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag((vscf_impl_t*) c_ctx);
    switch(implTag) {
    case vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        strcat (classFullName, "MessageInfoDerSerializer");
        break;
    default:
        free(classFullName);
        printf("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapMessageInfoSerializer (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    char *classFullName = getMessageInfoSerializerClassName(jenv, jobj, c_ctx);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    free(classFullName);
    if (NULL == cls) {
        printf("Class not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(J)V");
    if (NULL == methodID) {
        printf("Class has no constructor with C context parameter.");
    }
    return (*jenv)->NewObject(jenv, cls, methodID, c_ctx);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_alloc(vscf_error_ctx_size());
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_dealloc((vscf_error_t /*2*/ *) c_ctx /*4*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_error_reset((vscf_error_t /*2*/ *) c_ctx /*1*/);
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1hasError (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_error_has_error((vscf_error_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_error_1status (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_error_status((vscf_error_t /*2*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_rawKey_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_raw_key_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rawKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_raw_key_delete((vscf_raw_key_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rawKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_raw_key_alg_id((vscf_raw_key_t /*2*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rawKey_1data (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_raw_key_data((vscf_raw_key_t /*2*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1fromAlgId (JNIEnv *jenv, jobject jobj, jobject jalgId) {
    vsc_data_t /*3*/ proxyResult = vscf_oid_from_alg_id(/* !enum! */ 1);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1toAlgId (JNIEnv *jenv, jobject jobj, jbyteArray joid) {
    // Wrap input data
    vsc_data_t oid = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, joid, NULL),
        (*jenv)->GetArrayLength(jenv, joid));

    vscf_alg_id_t proxyResult = vscf_oid_to_alg_id(oid /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1fromId (JNIEnv *jenv, jobject jobj, jobject joidId) {
    vsc_data_t /*3*/ proxyResult = vscf_oid_from_id(/* !enum! */ 1);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1toId (JNIEnv *jenv, jobject jobj, jbyteArray joid) {
    // Wrap input data
    vsc_data_t oid = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, joid, NULL),
        (*jenv)->GetArrayLength(jenv, joid));

    vscf_oid_id_t proxyResult = vscf_oid_to_id(oid /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/OidId");
    if (NULL == cls) {
        printf("Enum OidId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/OidId;");
    if (NULL == methodID) {
        printf("Enum OidId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_oid_1equal (JNIEnv *jenv, jobject jobj, jbyteArray jlhs, jbyteArray jrhs) {
    // Wrap input data
    vsc_data_t lhs = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jlhs, NULL),
        (*jenv)->GetArrayLength(jenv, jlhs));

    vsc_data_t rhs = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jrhs, NULL),
        (*jenv)->GetArrayLength(jenv, jrhs));

    jboolean ret = vscf_oid_equal(lhs /*1*/, rhs /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_base64_1encodedLen (JNIEnv *jenv, jobject jobj, jint jdataLen) {
    jint ret = vscf_base64_encoded_len(jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_base64_1encode (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *str = vsc_buffer_new_with_capacity(vscf_base64_encoded_len(data.len/*a*/));

    vscf_base64_encode(data /*1*/, str /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(str));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(str), vsc_buffer_bytes(str));
    // Free resources
    vsc_buffer_delete(str);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_base64_1decodedLen (JNIEnv *jenv, jobject jobj, jint jstrLen) {
    jint ret = vscf_base64_decoded_len(jstrLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_base64_1decode (JNIEnv *jenv, jobject jobj, jbyteArray jstr) {
    // Wrap input data
    vsc_data_t str = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jstr, NULL),
        (*jenv)->GetArrayLength(jenv, jstr));

    vsc_buffer_t *data = vsc_buffer_new_with_capacity(vscf_base64_decoded_len(str.len/*a*/));

    vscf_status_t status = vscf_base64_decode(str /*1*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), vsc_buffer_bytes(data));
    // Free resources
    vsc_buffer_delete(data);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1wrappedLen (JNIEnv *jenv, jobject jobj, jstring jtitle, jint jdataLen) {
    // Wrap Java strings
    char *title = (*jenv)->GetStringUTFChars(jenv, jtitle, NULL);

    jint ret = vscf_pem_wrapped_len(jtitle /*4*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1wrap (JNIEnv *jenv, jobject jobj, jstring jtitle, jbyteArray jdata) {
    // Wrap Java strings
    char *title = (*jenv)->GetStringUTFChars(jenv, jtitle, NULL);

    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *pem = vsc_buffer_new_with_capacity(vscf_pem_wrapped_len(title/*a*/, data.len/*a*/));

    vscf_pem_wrap(jtitle /*4*/, data /*1*/, pem /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(pem));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(pem), vsc_buffer_bytes(pem));
    // Free resources
    vsc_buffer_delete(pem);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1unwrappedLen (JNIEnv *jenv, jobject jobj, jint jpemLen) {
    jint ret = vscf_pem_unwrapped_len(jpemLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1unwrap (JNIEnv *jenv, jobject jobj, jbyteArray jpem) {
    // Wrap input data
    vsc_data_t pem = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpem, NULL),
        (*jenv)->GetArrayLength(jenv, jpem));

    vsc_buffer_t *data = vsc_buffer_new_with_capacity(vscf_pem_unwrapped_len(pem.len/*a*/));

    vscf_status_t status = vscf_pem_unwrap(pem /*1*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), vsc_buffer_bytes(data));
    // Free resources
    vsc_buffer_delete(data);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pem_1title (JNIEnv *jenv, jobject jobj, jbyteArray jpem) {
    // Wrap input data
    vsc_data_t pem = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpem, NULL),
        (*jenv)->GetArrayLength(jenv, jpem));

    vsc_data_t /*3*/ proxyResult = vscf_pem_title(pem /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_message_info_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_delete((vscf_message_info_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1addKeyRecipient (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkeyRecipient) {
    // Wrap Java classes
    jclass key_recipient_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/KeyRecipientInfo");
    if (NULL == key_recipient_cls) {
        printf("Class KeyRecipientInfo not found.");
    }
    jfieldID key_recipient_fidCtx = (*jenv)->GetFieldID(jenv, key_recipient_cls, "cCtx", "J");
    if (NULL == key_recipient_fidCtx) {
        printf("Class 'KeyRecipientInfo' has no field 'cCtx'.");
    }
    vscf_key_recipient_info_t * /*5*/ key_recipient = (vscf_key_recipient_info_t * /*5*/) (*jenv)->GetLongField(jenv, jkeyRecipient, key_recipient_fidCtx);

    vscf_message_info_add_key_recipient((vscf_message_info_t /*2*/ *) c_ctx /*1*/, key_recipient /*3*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1addPasswordRecipient (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpasswordRecipient) {
    // Wrap Java classes
    jclass password_recipient_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/PasswordRecipientInfo");
    if (NULL == password_recipient_cls) {
        printf("Class PasswordRecipientInfo not found.");
    }
    jfieldID password_recipient_fidCtx = (*jenv)->GetFieldID(jenv, password_recipient_cls, "cCtx", "J");
    if (NULL == password_recipient_fidCtx) {
        printf("Class 'PasswordRecipientInfo' has no field 'cCtx'.");
    }
    vscf_password_recipient_info_t * /*5*/ password_recipient = (vscf_password_recipient_info_t * /*5*/) (*jenv)->GetLongField(jenv, jpasswordRecipient, password_recipient_fidCtx);

    vscf_message_info_add_password_recipient((vscf_message_info_t /*2*/ *) c_ctx /*1*/, password_recipient /*3*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1setDataEncryptionAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jdataEncryptionAlgInfo) {
    // Wrap Java interfaces
    jclass data_encryption_alg_info_cls = (*jenv)->GetObjectClass(jenv, jdataEncryptionAlgInfo);
    if (NULL == data_encryption_alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID data_encryption_alg_info_fidCtx = (*jenv)->GetFieldID(jenv, data_encryption_alg_info_cls, "cCtx", "J");
    if (NULL == data_encryption_alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ data_encryption_alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jdataEncryptionAlgInfo, data_encryption_alg_info_fidCtx);

    vscf_message_info_set_data_encryption_alg_info((vscf_message_info_t /*2*/ *) c_ctx /*1*/, data_encryption_alg_info /*3*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1dataEncryptionAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_message_info_data_encryption_alg_info((vscf_message_info_t /*2*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1keyRecipientInfoList (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_recipient_info_list_t * /*5*/ proxyResult = vscf_message_info_key_recipient_info_list((vscf_message_info_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/KeyRecipientInfoList");
    if (NULL == result_cls) {
        printf("Class KeyRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class KeyRecipientInfoList has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1passwordRecipientInfoList (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_password_recipient_info_list_t * /*5*/ proxyResult = vscf_message_info_password_recipient_info_list((vscf_message_info_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/PasswordRecipientInfoList");
    if (NULL == result_cls) {
        printf("Class PasswordRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class PasswordRecipientInfoList has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1setCustomParams (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jcustomParams) {
    // Wrap Java classes
    jclass custom_params_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/MessageInfoCustomParams");
    if (NULL == custom_params_cls) {
        printf("Class MessageInfoCustomParams not found.");
    }
    jfieldID custom_params_fidCtx = (*jenv)->GetFieldID(jenv, custom_params_cls, "cCtx", "J");
    if (NULL == custom_params_fidCtx) {
        printf("Class 'MessageInfoCustomParams' has no field 'cCtx'.");
    }
    vscf_message_info_custom_params_t * /*5*/ custom_params = (vscf_message_info_custom_params_t * /*5*/) (*jenv)->GetLongField(jenv, jcustomParams, custom_params_fidCtx);

    vscf_message_info_set_custom_params((vscf_message_info_t /*2*/ *) c_ctx /*1*/, custom_params /*3*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1customParams (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_custom_params_t * /*5*/ proxyResult = vscf_message_info_custom_params((vscf_message_info_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/MessageInfoCustomParams");
    if (NULL == result_cls) {
        printf("Class MessageInfoCustomParams not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class MessageInfoCustomParams has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfo_1clearRecipients (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_clear_recipients((vscf_message_info_t /*2*/ *) c_ctx /*1*/);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_key_recipient_info_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_recipient_info_delete((vscf_key_recipient_info_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1recipientId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_key_recipient_info_recipient_id((vscf_key_recipient_info_t /*2*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1keyEncryptionAlgorithm (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_key_recipient_info_key_encryption_algorithm((vscf_key_recipient_info_t /*2*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfo_1encryptedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_key_recipient_info_encrypted_key((vscf_key_recipient_info_t /*2*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_key_recipient_info_list_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_recipient_info_list_delete((vscf_key_recipient_info_list_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1add (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkeyRecipientInfo) {
    // Wrap Java classes
    jclass key_recipient_info_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/KeyRecipientInfo");
    if (NULL == key_recipient_info_cls) {
        printf("Class KeyRecipientInfo not found.");
    }
    jfieldID key_recipient_info_fidCtx = (*jenv)->GetFieldID(jenv, key_recipient_info_cls, "cCtx", "J");
    if (NULL == key_recipient_info_fidCtx) {
        printf("Class 'KeyRecipientInfo' has no field 'cCtx'.");
    }
    vscf_key_recipient_info_t * /*5*/ key_recipient_info = (vscf_key_recipient_info_t * /*5*/) (*jenv)->GetLongField(jenv, jkeyRecipientInfo, key_recipient_info_fidCtx);

    vscf_key_recipient_info_list_add((vscf_key_recipient_info_list_t /*2*/ *) c_ctx /*1*/, key_recipient_info /*3*/);
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasItem (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_key_recipient_info_list_has_item((vscf_key_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1item (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_recipient_info_t * /*5*/ proxyResult = vscf_key_recipient_info_list_item((vscf_key_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/KeyRecipientInfo");
    if (NULL == result_cls) {
        printf("Class KeyRecipientInfo not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class KeyRecipientInfo has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasNext (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_key_recipient_info_list_has_next((vscf_key_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1next (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_recipient_info_list_t * /*5*/ proxyResult = vscf_key_recipient_info_list_next((vscf_key_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/KeyRecipientInfoList");
    if (NULL == result_cls) {
        printf("Class KeyRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class KeyRecipientInfoList has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasPrev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_key_recipient_info_list_has_prev((vscf_key_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1prev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_recipient_info_list_t * /*5*/ proxyResult = vscf_key_recipient_info_list_prev((vscf_key_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/KeyRecipientInfoList");
    if (NULL == result_cls) {
        printf("Class KeyRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class KeyRecipientInfoList has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyRecipientInfoList_1clear (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_recipient_info_list_clear((vscf_key_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfo_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_password_recipient_info_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_password_recipient_info_delete((vscf_password_recipient_info_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfo_1keyEncryptionAlgorithm (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_password_recipient_info_key_encryption_algorithm((vscf_password_recipient_info_t /*2*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfo_1encryptedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_password_recipient_info_encrypted_key((vscf_password_recipient_info_t /*2*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_password_recipient_info_list_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_password_recipient_info_list_delete((vscf_password_recipient_info_list_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1add (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpasswordRecipientInfo) {
    // Wrap Java classes
    jclass password_recipient_info_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/PasswordRecipientInfo");
    if (NULL == password_recipient_info_cls) {
        printf("Class PasswordRecipientInfo not found.");
    }
    jfieldID password_recipient_info_fidCtx = (*jenv)->GetFieldID(jenv, password_recipient_info_cls, "cCtx", "J");
    if (NULL == password_recipient_info_fidCtx) {
        printf("Class 'PasswordRecipientInfo' has no field 'cCtx'.");
    }
    vscf_password_recipient_info_t * /*5*/ password_recipient_info = (vscf_password_recipient_info_t * /*5*/) (*jenv)->GetLongField(jenv, jpasswordRecipientInfo, password_recipient_info_fidCtx);

    vscf_password_recipient_info_list_add((vscf_password_recipient_info_list_t /*2*/ *) c_ctx /*1*/, password_recipient_info /*3*/);
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasItem (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_password_recipient_info_list_has_item((vscf_password_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1item (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_password_recipient_info_t * /*5*/ proxyResult = vscf_password_recipient_info_list_item((vscf_password_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/PasswordRecipientInfo");
    if (NULL == result_cls) {
        printf("Class PasswordRecipientInfo not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class PasswordRecipientInfo has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasNext (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_password_recipient_info_list_has_next((vscf_password_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1next (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_password_recipient_info_list_t * /*5*/ proxyResult = vscf_password_recipient_info_list_next((vscf_password_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/PasswordRecipientInfoList");
    if (NULL == result_cls) {
        printf("Class PasswordRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class PasswordRecipientInfoList has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasPrev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_password_recipient_info_list_has_prev((vscf_password_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1prev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_password_recipient_info_list_t * /*5*/ proxyResult = vscf_password_recipient_info_list_prev((vscf_password_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/PasswordRecipientInfoList");
    if (NULL == result_cls) {
        printf("Class PasswordRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class PasswordRecipientInfoList has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1clear (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_password_recipient_info_list_clear((vscf_password_recipient_info_list_t /*2*/ *) c_ctx /*1*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createHashFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_hash_from_info(alg_info /*3*/);
    // TDB interface
    jobject ret = wrapHash(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createMacFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_mac_from_info(alg_info /*3*/);
    // TDB interface
    jobject ret = wrapMac(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createKdfFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_kdf_from_info(alg_info /*3*/);
    // TDB interface
    jobject ret = wrapKdf(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createSaltedKdfFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_salted_kdf_from_info(alg_info /*3*/);
    // TDB interface
    jobject ret = wrapSaltedKdf(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createCipherFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_cipher_from_info(alg_info /*3*/);
    // TDB interface
    jobject ret = wrapCipher(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createPublicKeyFromRawKey (JNIEnv *jenv, jobject jobj, jobject jrawKey) {
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/RawKey");
    if (NULL == raw_key_cls) {
        printf("Class RawKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        printf("Class 'RawKey' has no field 'cCtx'.");
    }
    vscf_raw_key_t * /*5*/ raw_key = (vscf_raw_key_t * /*5*/) (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);

    vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_public_key_from_raw_key(raw_key /*3*/);
    // TDB interface
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algFactory_1createPrivateKeyFromRawKey (JNIEnv *jenv, jobject jobj, jobject jrawKey) {
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/RawKey");
    if (NULL == raw_key_cls) {
        printf("Class RawKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        printf("Class 'RawKey' has no field 'cCtx'.");
    }
    vscf_raw_key_t * /*5*/ raw_key = (vscf_raw_key_t * /*5*/) (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);

    vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_private_key_from_raw_key(raw_key /*3*/);
    // TDB interface
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_recipient_cipher_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_recipient_cipher_delete((vscf_recipient_cipher_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vscf_recipient_cipher_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vscf_recipient_cipher_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1setEncryptionCipher (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jencryptionCipher) {
    jclass encryption_cipher_cls = (*jenv)->GetObjectClass(jenv, jencryptionCipher);
    if (NULL == encryption_cipher_cls) {
        printf("Class Cipher not found.");
    }
    jfieldID encryption_cipher_fidCtx = (*jenv)->GetFieldID(jenv, encryption_cipher_cls, "cCtx", "J");
    if (NULL == encryption_cipher_fidCtx) {
        printf("Class 'Cipher' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ encryption_cipher = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jencryptionCipher, encryption_cipher_fidCtx);

    vscf_recipient_cipher_release_encryption_cipher((vscf_impl_t */*6*/ *) c_ctx);
    vscf_recipient_cipher_use_encryption_cipher((vscf_impl_t */*6*/ *) c_ctx, encryption_cipher);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1addKeyRecipient (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jrecipientId, jobject jpublicKey) {
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        printf("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        printf("Class 'PublicKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ public_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);

    // Wrap input data
    vsc_data_t recipient_id = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL),
        (*jenv)->GetArrayLength(jenv, jrecipientId));

    vscf_recipient_cipher_add_key_recipient((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/, recipient_id /*1*/, public_key /*3*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1clearRecipients (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_recipient_cipher_clear_recipients((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1customParams (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_custom_params_t * /*5*/ proxyResult = vscf_recipient_cipher_custom_params((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/MessageInfoCustomParams");
    if (NULL == result_cls) {
        printf("Class MessageInfoCustomParams not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class MessageInfoCustomParams has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1messageInfoLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_recipient_cipher_message_info_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1startEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_recipient_cipher_start_encryption((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1packMessageInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *message_info = vsc_buffer_new_with_capacity(vscf_recipient_cipher_message_info_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/));

    vscf_recipient_cipher_pack_message_info((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/, message_info /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(message_info));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(message_info), vsc_buffer_bytes(message_info));
    // Free resources
    vsc_buffer_delete(message_info);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1encryptionOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_recipient_cipher_encryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1processEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_encryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_recipient_cipher_process_encryption((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1finishEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_encryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/, 0/*b*/));

    vscf_status_t status = vscf_recipient_cipher_finish_encryption((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1startDecryptionWithKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jrecipientId, jobject jprivateKey, jbyteArray jmessageInfo) {
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        printf("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        printf("Class 'PrivateKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ private_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);

    // Wrap input data
    vsc_data_t recipient_id = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL),
        (*jenv)->GetArrayLength(jenv, jrecipientId));

    vsc_data_t message_info = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jmessageInfo, NULL),
        (*jenv)->GetArrayLength(jenv, jmessageInfo));

    vscf_status_t status = vscf_recipient_cipher_start_decryption_with_key((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/, recipient_id /*1*/, private_key /*3*/, message_info /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1decryptionOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_recipient_cipher_decryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1processDecryption (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_recipient_cipher_process_decryption((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_recipientCipher_1finishDecryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/, 0/*b*/));

    vscf_status_t status = vscf_recipient_cipher_finish_decryption((vscf_recipient_cipher_t /*2*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_listKeyValueNode_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_list_key_value_node_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_listKeyValueNode_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_list_key_value_node_delete((vscf_list_key_value_node_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_message_info_custom_params_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_custom_params_delete((vscf_message_info_custom_params_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addInt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey, jint jvalue) {
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    vscf_message_info_custom_params_add_int((vscf_message_info_custom_params_t /*2*/ *) c_ctx /*1*/, key /*1*/, jvalue /*4*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addString (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey, jbyteArray jvalue) {
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    vsc_data_t value = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jvalue, NULL),
        (*jenv)->GetArrayLength(jenv, jvalue));

    vscf_message_info_custom_params_add_string((vscf_message_info_custom_params_t /*2*/ *) c_ctx /*1*/, key /*1*/, value /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey, jbyteArray jvalue) {
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    vsc_data_t value = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jvalue, NULL),
        (*jenv)->GetArrayLength(jenv, jvalue));

    vscf_message_info_custom_params_add_data((vscf_message_info_custom_params_t /*2*/ *) c_ctx /*1*/, key /*1*/, value /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1clear (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_custom_params_clear((vscf_message_info_custom_params_t /*2*/ *) c_ctx /*1*/);
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findInt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    jint ret = vscf_message_info_custom_params_find_int((vscf_message_info_custom_params_t /*2*/ *) c_ctx /*1*/, key /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findString (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    vsc_data_t /*3*/ proxyResult = vscf_message_info_custom_params_find_string((vscf_message_info_custom_params_t /*2*/ *) c_ctx /*1*/, key /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    vsc_data_t /*3*/ proxyResult = vscf_message_info_custom_params_find_data((vscf_message_info_custom_params_t /*2*/ *) c_ctx /*1*/, key /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_key_provider_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_provider_delete((vscf_key_provider_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vscf_key_provider_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vscf_key_provider_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1setEcies (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jecies) {
    jclass ecies_cls = (*jenv)->GetObjectClass(jenv, jecies);
    if (NULL == ecies_cls) {
        printf("Class Ecies not found.");
    }
    jfieldID ecies_fidCtx = (*jenv)->GetFieldID(jenv, ecies_cls, "cCtx", "J");
    if (NULL == ecies_fidCtx) {
        printf("Class 'Ecies' has no field 'cCtx'.");
    }
    vscf_ecies_t * /*5*/ ecies = (vscf_ecies_t * /*5*/) (*jenv)->GetLongField(jenv, jecies, ecies_fidCtx);

    vscf_key_provider_release_ecies((vscf_ecies_t * /*5*/ *) c_ctx);
    vscf_key_provider_use_ecies((vscf_ecies_t * /*5*/ *) c_ctx, ecies);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_key_provider_setup_defaults((vscf_key_provider_t /*2*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1setRsaParams (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jbitlen, jint jexponent) {
    vscf_key_provider_set_rsa_params((vscf_key_provider_t /*2*/ *) c_ctx /*1*/, jbitlen /*4*/, jexponent /*4*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1generatePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgId) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_private_key((vscf_key_provider_t /*2*/ *) c_ctx /*1*/, /* !enum! */ 1, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    // TDB interface
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpkcs8Data) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t pkcs8_data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpkcs8Data, NULL),
        (*jenv)->GetArrayLength(jenv, jpkcs8Data));

    vscf_impl_t */*6*/ proxyResult = vscf_key_provider_import_private_key((vscf_key_provider_t /*2*/ *) c_ctx /*1*/, pkcs8_data /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    // TDB interface
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_keyProvider_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpkcs8Data) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t pkcs8_data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpkcs8Data, NULL),
        (*jenv)->GetArrayLength(jenv, jpkcs8Data));

    vscf_impl_t */*6*/ proxyResult = vscf_key_provider_import_public_key((vscf_key_provider_t /*2*/ *) c_ctx /*1*/, pkcs8_data /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    // TDB interface
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_signer_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_signer_delete((vscf_signer_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        printf("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        printf("Class 'Hash' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ hash = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);

    vscf_signer_release_hash((vscf_impl_t */*6*/ *) c_ctx);
    vscf_signer_use_hash((vscf_impl_t */*6*/ *) c_ctx, hash);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_signer_reset((vscf_signer_t /*2*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_signer_update((vscf_signer_t /*2*/ *) c_ctx /*1*/, data /*1*/);
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        printf("Class SignHash not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        printf("Class 'SignHash' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ private_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);

    jint ret = vscf_signer_signature_len((vscf_signer_t /*2*/ *) c_ctx /*1*/, private_key /*3*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_signer_1sign (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        printf("Class SignHash not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        printf("Class 'SignHash' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ private_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_signer_signature_len((vscf_signer_t /*2*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_signer_sign((vscf_signer_t /*2*/ *) c_ctx /*1*/, private_key /*3*/, signature /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), vsc_buffer_bytes(signature));
    // Free resources
    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_verifier_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_verifier_delete((vscf_verifier_t /*2*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsignature) {
    // Wrap input data
    vsc_data_t signature = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jsignature, NULL),
        (*jenv)->GetArrayLength(jenv, jsignature));

    vscf_status_t status = vscf_verifier_reset((vscf_verifier_t /*2*/ *) c_ctx /*1*/, signature /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_verifier_update((vscf_verifier_t /*2*/ *) c_ctx /*1*/, data /*1*/);
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_verifier_1verify (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        printf("Class VerifyHash not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        printf("Class 'VerifyHash' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ public_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);

    jboolean ret = vscf_verifier_verify((vscf_verifier_t /*2*/ *) c_ctx /*1*/, public_key /*3*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_sha224_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha224_delete((vscf_sha224_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_sha224_alg_id((vscf_sha224_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_sha224_produce_alg_info((vscf_sha224_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_sha224_restore_alg_info((vscf_sha224_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1hash (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha224_DIGEST_LEN);

    vscf_sha224_hash(data /*1*/, digest /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha224_start((vscf_sha224_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_sha224_update((vscf_sha224_t /*7*/ *) c_ctx /*1*/, data /*1*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha224_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha224_DIGEST_LEN);

    vscf_sha224_finish((vscf_sha224_t /*7*/ *) c_ctx /*1*/, digest /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_sha256_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha256_delete((vscf_sha256_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_sha256_alg_id((vscf_sha256_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_sha256_produce_alg_info((vscf_sha256_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_sha256_restore_alg_info((vscf_sha256_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1hash (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_hash(data /*1*/, digest /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha256_start((vscf_sha256_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_sha256_update((vscf_sha256_t /*7*/ *) c_ctx /*1*/, data /*1*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha256_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_finish((vscf_sha256_t /*7*/ *) c_ctx /*1*/, digest /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_sha384_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha384_delete((vscf_sha384_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_sha384_alg_id((vscf_sha384_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_sha384_produce_alg_info((vscf_sha384_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_sha384_restore_alg_info((vscf_sha384_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1hash (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha384_DIGEST_LEN);

    vscf_sha384_hash(data /*1*/, digest /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha384_start((vscf_sha384_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_sha384_update((vscf_sha384_t /*7*/ *) c_ctx /*1*/, data /*1*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha384_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha384_DIGEST_LEN);

    vscf_sha384_finish((vscf_sha384_t /*7*/ *) c_ctx /*1*/, digest /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_sha512_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha512_delete((vscf_sha512_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_sha512_alg_id((vscf_sha512_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_sha512_produce_alg_info((vscf_sha512_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_sha512_restore_alg_info((vscf_sha512_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1hash (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);

    vscf_sha512_hash(data /*1*/, digest /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha512_start((vscf_sha512_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_sha512_update((vscf_sha512_t /*7*/ *) c_ctx /*1*/, data /*1*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_sha512_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);

    vscf_sha512_finish((vscf_sha512_t /*7*/ *) c_ctx /*1*/, digest /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_aes256_gcm_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_aes256_gcm_delete((vscf_aes256_gcm_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_aes256_gcm_alg_id((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_aes256_gcm_produce_alg_info((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_aes256_gcm_restore_alg_info((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_encrypted_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_gcm_encrypt((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_gcm_encrypted_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_decrypted_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_gcm_decrypt((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_gcm_decrypted_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1setNonce (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jnonce) {
    // Wrap input data
    vsc_data_t nonce = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jnonce, NULL),
        (*jenv)->GetArrayLength(jenv, jnonce));

    vscf_aes256_gcm_set_nonce((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, nonce /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1setKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    vscf_aes256_gcm_set_key((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, key /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1startEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_aes256_gcm_start_encryption((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1startDecryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_aes256_gcm_start_decryption((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_aes256_gcm_update((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1outLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_gcm_out_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1encryptedOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_gcm_encrypted_out_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1decryptedOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_gcm_decrypted_out_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*3*/, 0/*b*/));

    vscf_status_t status = vscf_aes256_gcm_finish((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1authEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jbyteArray jauthData) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_data_t auth_data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jauthData, NULL),
        (*jenv)->GetArrayLength(jenv, jauthData));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_auth_encrypted_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vsc_buffer_t *tag = vsc_buffer_new_with_capacity(vscf_aes256_gcm_AUTH_TAG_LEN);

    vscf_status_t status = vscf_aes256_gcm_auth_encrypt((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, data /*1*/, auth_data /*1*/, out /*1*/, tag /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AuthEncryptAuthEncryptResult");
    if (NULL == cls) {
        printf("Class AuthEncryptAuthEncryptResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidOut = (*jenv)->GetFieldID(jenv, cls, "out", "[B");
    jbyteArray jOutArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, jOutArr, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    (*jenv)->SetObjectField(jenv, newObj, fidOut, jOutArr);
    jfieldID fidTag = (*jenv)->GetFieldID(jenv, cls, "tag", "[B");
    jbyteArray jTagArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(tag));
    (*jenv)->SetByteArrayRegion (jenv, jTagArr, 0, vsc_buffer_len(tag), vsc_buffer_bytes(tag));
    (*jenv)->SetObjectField(jenv, newObj, fidTag, jTagArr);
    // Free resources
    vsc_buffer_delete(out);

    vsc_buffer_delete(tag);

    return newObj;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1authEncryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_gcm_auth_encrypted_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1authDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jbyteArray jauthData, jbyteArray jtag) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_data_t auth_data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jauthData, NULL),
        (*jenv)->GetArrayLength(jenv, jauthData));

    vsc_data_t tag = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jtag, NULL),
        (*jenv)->GetArrayLength(jenv, jtag));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_auth_decrypted_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_gcm_auth_decrypt((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, data /*1*/, auth_data /*1*/, tag /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Gcm_1authDecryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_gcm_auth_decrypted_len((vscf_aes256_gcm_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_aes256_cbc_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_aes256_cbc_delete((vscf_aes256_cbc_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_aes256_cbc_alg_id((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_aes256_cbc_produce_alg_info((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_aes256_cbc_restore_alg_info((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_encrypted_len((vscf_aes256_cbc_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_cbc_encrypt((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_cbc_encrypted_len((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_decrypted_len((vscf_aes256_cbc_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_cbc_decrypt((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_cbc_decrypted_len((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1setNonce (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jnonce) {
    // Wrap input data
    vsc_data_t nonce = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jnonce, NULL),
        (*jenv)->GetArrayLength(jenv, jnonce));

    vscf_aes256_cbc_set_nonce((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, nonce /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1setKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    vscf_aes256_cbc_set_key((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, key /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1startEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_aes256_cbc_start_encryption((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1startDecryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_aes256_cbc_start_decryption((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_out_len((vscf_aes256_cbc_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_aes256_cbc_update((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1outLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_cbc_out_len((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1encryptedOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_cbc_encrypted_out_len((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1decryptedOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_aes256_cbc_decrypted_out_len((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_aes256Cbc_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_out_len((vscf_aes256_cbc_t /*7*/ *) c_ctx /*3*/, 0/*b*/));

    vscf_status_t status = vscf_aes256_cbc_finish((vscf_aes256_cbc_t /*7*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_asn1rd_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_asn1rd_delete((vscf_asn1rd_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_asn1rd_reset((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/, data /*1*/);
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1leftLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_left_len((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1hasError (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_asn1rd_has_error((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1status (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_asn1rd_status((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1getTag (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_get_tag((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1getLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_get_len((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1getDataLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_get_data_len((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readTag (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jtag) {
    jint ret = vscf_asn1rd_read_tag((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/, jtag /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readContextTag (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jtag) {
    jint ret = vscf_asn1rd_read_context_tag((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/, jtag /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_read_int((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt8 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_read_int8((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt16 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_read_int16((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt32 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_read_int32((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readInt64 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_read_int64((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jlong ret = vscf_asn1rd_read_uint((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint8 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jlong ret = vscf_asn1rd_read_uint8((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint16 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jlong ret = vscf_asn1rd_read_uint16((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint32 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jlong ret = vscf_asn1rd_read_uint32((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUint64 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jlong ret = vscf_asn1rd_read_uint64((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readBool (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_asn1rd_read_bool((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readNull (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_asn1rd_read_null((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readNullOptional (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_asn1rd_read_null_optional((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readOctetStr (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_octet_str((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readBitstringAsOctetStr (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_bitstring_as_octet_str((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readUtf8Str (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_utf8_str((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readOid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_oid((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_data((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/, jlen /*4*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readSequence (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_read_sequence((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1rd_1readSet (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1rd_read_set((vscf_asn1rd_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_asn1wr_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_asn1wr_delete((vscf_asn1wr_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyte jout, jint joutLen) {
    vscf_asn1wr_reset((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jout /*4*/, joutLen /*4*/);
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx, jboolean jdoNotAdjust) {
    jint ret = vscf_asn1wr_finish((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jdoNotAdjust /*4*/);
    return ret;
}

JNIEXPORT jbyte JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1bytes (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jbyte ret = vscf_asn1wr_bytes((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1wr_len((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writtenLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1wr_written_len((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1unwrittenLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1wr_unwritten_len((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1hasError (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_asn1wr_has_error((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1status (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_asn1wr_status((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyte JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1reserve (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    jbyte ret = vscf_asn1wr_reserve((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jlen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeTag (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jtag) {
    jint ret = vscf_asn1wr_write_tag((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jtag /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeContextTag (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jtag, jint jlen) {
    jint ret = vscf_asn1wr_write_context_tag((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jtag /*4*/, jlen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    jint ret = vscf_asn1wr_write_len((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jlen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    jint ret = vscf_asn1wr_write_int((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt8 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    jint ret = vscf_asn1wr_write_int8((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt16 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    jint ret = vscf_asn1wr_write_int16((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt32 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    jint ret = vscf_asn1wr_write_int32((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeInt64 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    jint ret = vscf_asn1wr_write_int64((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    jint ret = vscf_asn1wr_write_uint((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint8 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    jint ret = vscf_asn1wr_write_uint8((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint16 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    jint ret = vscf_asn1wr_write_uint16((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint32 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    jint ret = vscf_asn1wr_write_uint32((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUint64 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    jint ret = vscf_asn1wr_write_uint64((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeBool (JNIEnv *jenv, jobject jobj, jlong c_ctx, jboolean jvalue) {
    jint ret = vscf_asn1wr_write_bool((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jvalue /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeNull (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_asn1wr_write_null((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeOctetStr (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jvalue) {
    // Wrap input data
    vsc_data_t value = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jvalue, NULL),
        (*jenv)->GetArrayLength(jenv, jvalue));

    jint ret = vscf_asn1wr_write_octet_str((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, value /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeOctetStrAsBitstring (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jvalue) {
    // Wrap input data
    vsc_data_t value = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jvalue, NULL),
        (*jenv)->GetArrayLength(jenv, jvalue));

    jint ret = vscf_asn1wr_write_octet_str_as_bitstring((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, value /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    jint ret = vscf_asn1wr_write_data((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, data /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeUtf8Str (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jvalue) {
    // Wrap input data
    vsc_data_t value = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jvalue, NULL),
        (*jenv)->GetArrayLength(jenv, jvalue));

    jint ret = vscf_asn1wr_write_utf8_str((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, value /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeOid (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jvalue) {
    // Wrap input data
    vsc_data_t value = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jvalue, NULL),
        (*jenv)->GetArrayLength(jenv, jvalue));

    jint ret = vscf_asn1wr_write_oid((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, value /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeSequence (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    jint ret = vscf_asn1wr_write_sequence((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jlen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_asn1wr_1writeSet (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    jint ret = vscf_asn1wr_write_set((vscf_asn1wr_t /*7*/ *) c_ctx /*1*/, jlen /*4*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        printf("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        printf("Class 'Hash' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ hash = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);

    vscf_rsa_public_key_release_hash((vscf_impl_t */*6*/ *) c_ctx);
    vscf_rsa_public_key_use_hash((vscf_impl_t */*6*/ *) c_ctx, hash);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vscf_rsa_public_key_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vscf_rsa_public_key_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setAsn1rd (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1rd) {
    jclass asn1rd_cls = (*jenv)->GetObjectClass(jenv, jasn1rd);
    if (NULL == asn1rd_cls) {
        printf("Class Asn1Reader not found.");
    }
    jfieldID asn1rd_fidCtx = (*jenv)->GetFieldID(jenv, asn1rd_cls, "cCtx", "J");
    if (NULL == asn1rd_fidCtx) {
        printf("Class 'Asn1Reader' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1rd = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1rd, asn1rd_fidCtx);

    vscf_rsa_public_key_release_asn1rd((vscf_impl_t */*6*/ *) c_ctx);
    vscf_rsa_public_key_use_asn1rd((vscf_impl_t */*6*/ *) c_ctx, asn1rd);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setAsn1wr (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1wr) {
    jclass asn1wr_cls = (*jenv)->GetObjectClass(jenv, jasn1wr);
    if (NULL == asn1wr_cls) {
        printf("Class Asn1Writer not found.");
    }
    jfieldID asn1wr_fidCtx = (*jenv)->GetFieldID(jenv, asn1wr_cls, "cCtx", "J");
    if (NULL == asn1wr_fidCtx) {
        printf("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1wr = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1wr, asn1wr_fidCtx);

    vscf_rsa_public_key_release_asn1wr((vscf_impl_t */*6*/ *) c_ctx);
    vscf_rsa_public_key_use_asn1wr((vscf_impl_t */*6*/ *) c_ctx, asn1wr);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_rsa_public_key_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_rsa_public_key_delete((vscf_rsa_public_key_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_rsa_public_key_setup_defaults((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_rsa_public_key_alg_id((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_rsa_public_key_produce_alg_info((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_rsa_public_key_restore_alg_info((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1keyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_rsa_public_key_key_len((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1keyBitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_rsa_public_key_key_bitlen((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_rsa_public_key_encrypted_len((vscf_rsa_public_key_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_rsa_public_key_encrypt((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_rsa_public_key_encrypted_len((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1verifyHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jhashDigest, jobject jhashId, jbyteArray jsignature) {
    // Wrap input data
    vsc_data_t hash_digest = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jhashDigest, NULL),
        (*jenv)->GetArrayLength(jenv, jhashDigest));

    vsc_data_t signature = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jsignature, NULL),
        (*jenv)->GetArrayLength(jenv, jsignature));

    jboolean ret = vscf_rsa_public_key_verify_hash((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/, hash_digest /*1*/, /* !enum! */ 1, signature /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_rsa_public_key_exported_public_key_len((vscf_rsa_public_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_rsa_public_key_export_public_key((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1exportedPublicKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_rsa_public_key_exported_public_key_len((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_status_t status = vscf_rsa_public_key_import_public_key((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPublicKey_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    vscf_impl_t */*6*/ proxyResult = vscf_rsa_public_key_generate_ephemeral_key((vscf_rsa_public_key_t /*7*/ *) c_ctx /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    // TDB interface
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vscf_rsa_private_key_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vscf_rsa_private_key_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setAsn1rd (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1rd) {
    jclass asn1rd_cls = (*jenv)->GetObjectClass(jenv, jasn1rd);
    if (NULL == asn1rd_cls) {
        printf("Class Asn1Reader not found.");
    }
    jfieldID asn1rd_fidCtx = (*jenv)->GetFieldID(jenv, asn1rd_cls, "cCtx", "J");
    if (NULL == asn1rd_fidCtx) {
        printf("Class 'Asn1Reader' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1rd = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1rd, asn1rd_fidCtx);

    vscf_rsa_private_key_release_asn1rd((vscf_impl_t */*6*/ *) c_ctx);
    vscf_rsa_private_key_use_asn1rd((vscf_impl_t */*6*/ *) c_ctx, asn1rd);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setAsn1wr (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1wr) {
    jclass asn1wr_cls = (*jenv)->GetObjectClass(jenv, jasn1wr);
    if (NULL == asn1wr_cls) {
        printf("Class Asn1Writer not found.");
    }
    jfieldID asn1wr_fidCtx = (*jenv)->GetFieldID(jenv, asn1wr_cls, "cCtx", "J");
    if (NULL == asn1wr_fidCtx) {
        printf("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1wr = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1wr, asn1wr_fidCtx);

    vscf_rsa_private_key_release_asn1wr((vscf_impl_t */*6*/ *) c_ctx);
    vscf_rsa_private_key_use_asn1wr((vscf_impl_t */*6*/ *) c_ctx, asn1wr);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setKeygenParams (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jbitlen, jint jexponent) {
    vscf_rsa_private_key_set_keygen_params((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/, jbitlen /*4*/, jexponent /*4*/);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_rsa_private_key_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_rsa_private_key_delete((vscf_rsa_private_key_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_rsa_private_key_setup_defaults((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_rsa_private_key_alg_id((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_rsa_private_key_produce_alg_info((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_rsa_private_key_restore_alg_info((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1keyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_rsa_private_key_key_len((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1keyBitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_rsa_private_key_key_bitlen((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1generateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_rsa_private_key_generate_key((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_rsa_private_key_decrypted_len((vscf_rsa_private_key_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_rsa_private_key_decrypt((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_rsa_private_key_decrypted_len((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_rsa_private_key_signature_len((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1signHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jhashDigest, jobject jhashId) {
    // Wrap input data
    vsc_data_t hash_digest = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jhashDigest, NULL),
        (*jenv)->GetArrayLength(jenv, jhashDigest));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_rsa_private_key_signature_len((vscf_rsa_private_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_rsa_private_key_sign_hash((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/, hash_digest /*1*/, /* !enum! */ 1, signature /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), vsc_buffer_bytes(signature));
    // Free resources
    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1extractPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_rsa_private_key_extract_public_key((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_rsa_private_key_exported_private_key_len((vscf_rsa_private_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_rsa_private_key_export_private_key((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1exportedPrivateKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_rsa_private_key_exported_private_key_len((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_rsaPrivateKey_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_status_t status = vscf_rsa_private_key_import_private_key((vscf_rsa_private_key_t /*7*/ *) c_ctx /*1*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1addSource (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jsource, jint jthreshold) {
    // Wrap Java interfaces
    jclass source_cls = (*jenv)->GetObjectClass(jenv, jsource);
    if (NULL == source_cls) {
        printf("Class EntropySource not found.");
    }
    jfieldID source_fidCtx = (*jenv)->GetFieldID(jenv, source_cls, "cCtx", "J");
    if (NULL == source_fidCtx) {
        printf("Class 'EntropySource' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ source = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jsource, source_fidCtx);

    vscf_entropy_accumulator_add_source((vscf_entropy_accumulator_t /*7*/ *) c_ctx /*1*/, source /*3*/, jthreshold /*4*/);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_entropy_accumulator_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_entropy_accumulator_delete((vscf_entropy_accumulator_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_entropy_accumulator_setup_defaults((vscf_entropy_accumulator_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1isStrong (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_entropy_accumulator_is_strong((vscf_entropy_accumulator_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_entropyAccumulator_1gather (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(jlen);

    vscf_status_t status = vscf_entropy_accumulator_gather((vscf_entropy_accumulator_t /*7*/ *) c_ctx /*1*/, jlen /*4*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1setEntropySource (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jentropySource) {
    jclass entropy_source_cls = (*jenv)->GetObjectClass(jenv, jentropySource);
    if (NULL == entropy_source_cls) {
        printf("Class EntropySource not found.");
    }
    jfieldID entropy_source_fidCtx = (*jenv)->GetFieldID(jenv, entropy_source_cls, "cCtx", "J");
    if (NULL == entropy_source_fidCtx) {
        printf("Class 'EntropySource' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ entropy_source = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jentropySource, entropy_source_fidCtx);

    vscf_ctr_drbg_release_entropy_source((vscf_impl_t */*6*/ *) c_ctx);
    vscf_status_t status = vscf_ctr_drbg_use_entropy_source((vscf_impl_t */*6*/ *) c_ctx, entropy_source);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1enablePredictionResistance (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ctr_drbg_enable_prediction_resistance((vscf_ctr_drbg_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1setReseedInterval (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jinterval) {
    vscf_ctr_drbg_set_reseed_interval((vscf_ctr_drbg_t /*7*/ *) c_ctx /*1*/, jinterval /*4*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1setEntropyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    vscf_ctr_drbg_set_entropy_len((vscf_ctr_drbg_t /*7*/ *) c_ctx /*1*/, jlen /*4*/);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_ctr_drbg_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ctr_drbg_delete((vscf_ctr_drbg_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_ctr_drbg_setup_defaults((vscf_ctr_drbg_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1random (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Wrap input buffers
    vsc_buffer_t *data = vsc_buffer_new_with_capacity(jdataLen);

    vscf_status_t status = vscf_ctr_drbg_random((vscf_ctr_drbg_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), vsc_buffer_bytes(data));
    // Free resources
    vsc_buffer_delete(data);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ctrDrbg_1reseed (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_ctr_drbg_reseed((vscf_ctr_drbg_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        printf("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        printf("Class 'Hash' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ hash = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);

    vscf_hmac_release_hash((vscf_impl_t */*6*/ *) c_ctx);
    vscf_hmac_use_hash((vscf_impl_t */*6*/ *) c_ctx, hash);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_hmac_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_hmac_delete((vscf_hmac_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_hmac_alg_id((vscf_hmac_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_hmac_produce_alg_info((vscf_hmac_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_hmac_restore_alg_info((vscf_hmac_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1digestLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_hmac_digest_len((vscf_hmac_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1mac (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *mac = vsc_buffer_new_with_capacity(vscf_hmac_digest_len((vscf_hmac_t /*7*/ *) c_ctx /*3*/));

    vscf_hmac_mac((vscf_hmac_t /*7*/ *) c_ctx /*1*/, key /*1*/, data /*1*/, mac /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(mac));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(mac), vsc_buffer_bytes(mac));
    // Free resources
    vsc_buffer_delete(mac);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Wrap input data
    vsc_data_t key = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jkey, NULL),
        (*jenv)->GetArrayLength(jenv, jkey));

    vscf_hmac_start((vscf_hmac_t /*7*/ *) c_ctx /*1*/, key /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_hmac_update((vscf_hmac_t /*7*/ *) c_ctx /*1*/, data /*1*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *mac = vsc_buffer_new_with_capacity(vscf_hmac_digest_len((vscf_hmac_t /*7*/ *) c_ctx /*3*/));

    vscf_hmac_finish((vscf_hmac_t /*7*/ *) c_ctx /*1*/, mac /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(mac));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(mac), vsc_buffer_bytes(mac));
    // Free resources
    vsc_buffer_delete(mac);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hmac_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_hmac_reset((vscf_hmac_t /*7*/ *) c_ctx /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        printf("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        printf("Class 'Hash' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ hash = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);

    vscf_hkdf_release_hash((vscf_impl_t */*6*/ *) c_ctx);
    vscf_hkdf_use_hash((vscf_impl_t */*6*/ *) c_ctx, hash);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_hkdf_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_hkdf_delete((vscf_hkdf_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_hkdf_alg_id((vscf_hkdf_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_hkdf_produce_alg_info((vscf_hkdf_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_hkdf_restore_alg_info((vscf_hkdf_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1derive (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jint jkeyLen) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(jkeyLen);

    vscf_hkdf_derive((vscf_hkdf_t /*7*/ *) c_ctx /*1*/, data /*1*/, jkeyLen /*4*/, key /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), vsc_buffer_bytes(key));
    // Free resources
    vsc_buffer_delete(key);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsalt, jint jiterationCount) {
    // Wrap input data
    vsc_data_t salt = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jsalt, NULL),
        (*jenv)->GetArrayLength(jenv, jsalt));

    vscf_hkdf_reset((vscf_hkdf_t /*7*/ *) c_ctx /*1*/, salt /*1*/, jiterationCount /*4*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hkdf_1setInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jinfo) {
    // Wrap input data
    vsc_data_t info = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jinfo, NULL),
        (*jenv)->GetArrayLength(jenv, jinfo));

    vscf_hkdf_set_info((vscf_hkdf_t /*7*/ *) c_ctx /*1*/, info /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        printf("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        printf("Class 'Hash' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ hash = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);

    vscf_kdf1_release_hash((vscf_impl_t */*6*/ *) c_ctx);
    vscf_kdf1_use_hash((vscf_impl_t */*6*/ *) c_ctx, hash);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_kdf1_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_kdf1_delete((vscf_kdf1_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_kdf1_alg_id((vscf_kdf1_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_kdf1_produce_alg_info((vscf_kdf1_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_kdf1_restore_alg_info((vscf_kdf1_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf1_1derive (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jint jkeyLen) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(jkeyLen);

    vscf_kdf1_derive((vscf_kdf1_t /*7*/ *) c_ctx /*1*/, data /*1*/, jkeyLen /*4*/, key /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), vsc_buffer_bytes(key));
    // Free resources
    vsc_buffer_delete(key);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        printf("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        printf("Class 'Hash' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ hash = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);

    vscf_kdf2_release_hash((vscf_impl_t */*6*/ *) c_ctx);
    vscf_kdf2_use_hash((vscf_impl_t */*6*/ *) c_ctx, hash);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_kdf2_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_kdf2_delete((vscf_kdf2_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_kdf2_alg_id((vscf_kdf2_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_kdf2_produce_alg_info((vscf_kdf2_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_kdf2_restore_alg_info((vscf_kdf2_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_kdf2_1derive (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jint jkeyLen) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(jkeyLen);

    vscf_kdf2_derive((vscf_kdf2_t /*7*/ *) c_ctx /*1*/, data /*1*/, jkeyLen /*4*/, key /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), vsc_buffer_bytes(key));
    // Free resources
    vsc_buffer_delete(key);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1setupSourceByte (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyte jbyteSource) {
    vscf_fake_random_setup_source_byte((vscf_fake_random_t /*7*/ *) c_ctx /*1*/, jbyteSource /*4*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1setupSourceData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdataSource) {
    // Wrap input data
    vsc_data_t data_source = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdataSource, NULL),
        (*jenv)->GetArrayLength(jenv, jdataSource));

    vscf_fake_random_setup_source_data((vscf_fake_random_t /*7*/ *) c_ctx /*1*/, data_source /*1*/);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_fake_random_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_fake_random_delete((vscf_fake_random_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1random (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Wrap input buffers
    vsc_buffer_t *data = vsc_buffer_new_with_capacity(jdataLen);

    vscf_status_t status = vscf_fake_random_random((vscf_fake_random_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), vsc_buffer_bytes(data));
    // Free resources
    vsc_buffer_delete(data);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1reseed (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_fake_random_reseed((vscf_fake_random_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1isStrong (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jboolean ret = vscf_fake_random_is_strong((vscf_fake_random_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_fakeRandom_1gather (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(jlen);

    vscf_status_t status = vscf_fake_random_gather((vscf_fake_random_t /*7*/ *) c_ctx /*1*/, jlen /*4*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setHmac (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhmac) {
    jclass hmac_cls = (*jenv)->GetObjectClass(jenv, jhmac);
    if (NULL == hmac_cls) {
        printf("Class Mac not found.");
    }
    jfieldID hmac_fidCtx = (*jenv)->GetFieldID(jenv, hmac_cls, "cCtx", "J");
    if (NULL == hmac_fidCtx) {
        printf("Class 'Mac' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ hmac = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jhmac, hmac_fidCtx);

    vscf_pkcs5_pbkdf2_release_hmac((vscf_impl_t */*6*/ *) c_ctx);
    vscf_pkcs5_pbkdf2_use_hmac((vscf_impl_t */*6*/ *) c_ctx, hmac);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_pkcs5_pbkdf2_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pkcs5_pbkdf2_delete((vscf_pkcs5_pbkdf2_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_pkcs5_pbkdf2_setup_defaults((vscf_pkcs5_pbkdf2_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_pkcs5_pbkdf2_alg_id((vscf_pkcs5_pbkdf2_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_pkcs5_pbkdf2_produce_alg_info((vscf_pkcs5_pbkdf2_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_pkcs5_pbkdf2_restore_alg_info((vscf_pkcs5_pbkdf2_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1derive (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jint jkeyLen) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(jkeyLen);

    vscf_pkcs5_pbkdf2_derive((vscf_pkcs5_pbkdf2_t /*7*/ *) c_ctx /*1*/, data /*1*/, jkeyLen /*4*/, key /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), vsc_buffer_bytes(key));
    // Free resources
    vsc_buffer_delete(key);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsalt, jint jiterationCount) {
    // Wrap input data
    vsc_data_t salt = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jsalt, NULL),
        (*jenv)->GetArrayLength(jenv, jsalt));

    vscf_pkcs5_pbkdf2_reset((vscf_pkcs5_pbkdf2_t /*7*/ *) c_ctx /*1*/, salt /*1*/, jiterationCount /*4*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jinfo) {
    // Wrap input data
    vsc_data_t info = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jinfo, NULL),
        (*jenv)->GetArrayLength(jenv, jinfo));

    vscf_pkcs5_pbkdf2_set_info((vscf_pkcs5_pbkdf2_t /*7*/ *) c_ctx /*1*/, info /*1*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1setKdf (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkdf) {
    jclass kdf_cls = (*jenv)->GetObjectClass(jenv, jkdf);
    if (NULL == kdf_cls) {
        printf("Class SaltedKdf not found.");
    }
    jfieldID kdf_fidCtx = (*jenv)->GetFieldID(jenv, kdf_cls, "cCtx", "J");
    if (NULL == kdf_fidCtx) {
        printf("Class 'SaltedKdf' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ kdf = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jkdf, kdf_fidCtx);

    vscf_pkcs5_pbes2_release_kdf((vscf_impl_t */*6*/ *) c_ctx);
    vscf_pkcs5_pbes2_use_kdf((vscf_impl_t */*6*/ *) c_ctx, kdf);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1setCipher (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jcipher) {
    jclass cipher_cls = (*jenv)->GetObjectClass(jenv, jcipher);
    if (NULL == cipher_cls) {
        printf("Class Cipher not found.");
    }
    jfieldID cipher_fidCtx = (*jenv)->GetFieldID(jenv, cipher_cls, "cCtx", "J");
    if (NULL == cipher_fidCtx) {
        printf("Class 'Cipher' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ cipher = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jcipher, cipher_fidCtx);

    vscf_pkcs5_pbes2_release_cipher((vscf_impl_t */*6*/ *) c_ctx);
    vscf_pkcs5_pbes2_use_cipher((vscf_impl_t */*6*/ *) c_ctx, cipher);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpwd) {
    // Wrap input data
    vsc_data_t pwd = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpwd, NULL),
        (*jenv)->GetArrayLength(jenv, jpwd));

    vscf_pkcs5_pbes2_reset((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*1*/, pwd /*1*/);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_pkcs5_pbes2_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pkcs5_pbes2_delete((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_pkcs5_pbes2_alg_id((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_pkcs5_pbes2_produce_alg_info((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_pkcs5_pbes2_restore_alg_info((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs5_pbes2_encrypted_len((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_pkcs5_pbes2_encrypt((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_pkcs5_pbes2_encrypted_len((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs5_pbes2_decrypted_len((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_pkcs5_pbes2_decrypt((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs5Pbes2_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_pkcs5_pbes2_decrypted_len((vscf_pkcs5_pbes2_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1setAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Writer) {
    jclass asn1_writer_cls = (*jenv)->GetObjectClass(jenv, jasn1Writer);
    if (NULL == asn1_writer_cls) {
        printf("Class Asn1Writer not found.");
    }
    jfieldID asn1_writer_fidCtx = (*jenv)->GetFieldID(jenv, asn1_writer_cls, "cCtx", "J");
    if (NULL == asn1_writer_fidCtx) {
        printf("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1_writer = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1Writer, asn1_writer_fidCtx);

    vscf_pkcs8_der_serializer_release_asn1_writer((vscf_impl_t */*6*/ *) c_ctx);
    vscf_pkcs8_der_serializer_use_asn1_writer((vscf_impl_t */*6*/ *) c_ctx, asn1_writer);
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializePublicKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);// Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        printf("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        printf("Class 'PublicKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ public_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);

    jint ret = vscf_pkcs8_der_serializer_serialize_public_key_inplace((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*1*/, public_key /*3*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializePrivateKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);// Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        printf("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        printf("Class 'PrivateKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ private_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);

    jint ret = vscf_pkcs8_der_serializer_serialize_private_key_inplace((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*1*/, private_key /*3*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_pkcs8_der_serializer_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pkcs8_der_serializer_delete((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_pkcs8_der_serializer_setup_defaults((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializedPublicKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        printf("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        printf("Class 'PublicKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ public_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);

    jint ret = vscf_pkcs8_der_serializer_serialized_public_key_len((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*1*/, public_key /*3*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        printf("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        printf("Class 'PublicKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ public_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs8_der_serializer_serialized_public_key_len((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*3*/, public_key/*a*/));

    vscf_status_t status = vscf_pkcs8_der_serializer_serialize_public_key((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*1*/, public_key /*3*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializedPrivateKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        printf("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        printf("Class 'PrivateKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ private_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);

    jint ret = vscf_pkcs8_der_serializer_serialized_private_key_len((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*1*/, private_key /*3*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerSerializer_1serializePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        printf("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        printf("Class 'PrivateKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ private_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs8_der_serializer_serialized_private_key_len((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_pkcs8_der_serializer_serialize_private_key((vscf_pkcs8_der_serializer_t /*7*/ *) c_ctx /*1*/, private_key /*3*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1setAsn1Reader (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Reader) {
    jclass asn1_reader_cls = (*jenv)->GetObjectClass(jenv, jasn1Reader);
    if (NULL == asn1_reader_cls) {
        printf("Class Asn1Reader not found.");
    }
    jfieldID asn1_reader_fidCtx = (*jenv)->GetFieldID(jenv, asn1_reader_cls, "cCtx", "J");
    if (NULL == asn1_reader_fidCtx) {
        printf("Class 'Asn1Reader' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1_reader = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1Reader, asn1_reader_fidCtx);

    vscf_pkcs8_der_deserializer_release_asn1_reader((vscf_impl_t */*6*/ *) c_ctx);
    vscf_pkcs8_der_deserializer_use_asn1_reader((vscf_impl_t */*6*/ *) c_ctx, asn1_reader);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1deserializePublicKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    vscf_raw_key_t * /*5*/ proxyResult = vscf_pkcs8_der_deserializer_deserialize_public_key_inplace((vscf_pkcs8_der_deserializer_t /*7*/ *) c_ctx /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/RawKey");
    if (NULL == result_cls) {
        printf("Class RawKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class RawKey has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1deserializePrivateKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    vscf_raw_key_t * /*5*/ proxyResult = vscf_pkcs8_der_deserializer_deserialize_private_key_inplace((vscf_pkcs8_der_deserializer_t /*7*/ *) c_ctx /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/RawKey");
    if (NULL == result_cls) {
        printf("Class RawKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class RawKey has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_pkcs8_der_deserializer_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pkcs8_der_deserializer_delete((vscf_pkcs8_der_deserializer_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_pkcs8_der_deserializer_setup_defaults((vscf_pkcs8_der_deserializer_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1deserializePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpublicKeyData) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t public_key_data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpublicKeyData, NULL),
        (*jenv)->GetArrayLength(jenv, jpublicKeyData));

    vscf_raw_key_t * /*5*/ proxyResult = vscf_pkcs8_der_deserializer_deserialize_public_key((vscf_pkcs8_der_deserializer_t /*7*/ *) c_ctx /*1*/, public_key_data /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/RawKey");
    if (NULL == result_cls) {
        printf("Class RawKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class RawKey has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8DerDeserializer_1deserializePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jprivateKeyData) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t private_key_data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jprivateKeyData, NULL),
        (*jenv)->GetArrayLength(jenv, jprivateKeyData));

    vscf_raw_key_t * /*5*/ proxyResult = vscf_pkcs8_der_deserializer_deserialize_private_key((vscf_pkcs8_der_deserializer_t /*7*/ *) c_ctx /*1*/, private_key_data /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/RawKey");
    if (NULL == result_cls) {
        printf("Class RawKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class RawKey has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1setAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Writer) {
    jclass asn1_writer_cls = (*jenv)->GetObjectClass(jenv, jasn1Writer);
    if (NULL == asn1_writer_cls) {
        printf("Class Asn1Writer not found.");
    }
    jfieldID asn1_writer_fidCtx = (*jenv)->GetFieldID(jenv, asn1_writer_cls, "cCtx", "J");
    if (NULL == asn1_writer_fidCtx) {
        printf("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1_writer = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1Writer, asn1_writer_fidCtx);

    vscf_pkcs8_serializer_release_asn1_writer((vscf_impl_t */*6*/ *) c_ctx);
    vscf_pkcs8_serializer_use_asn1_writer((vscf_impl_t */*6*/ *) c_ctx, asn1_writer);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1setDerSerializer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jderSerializer) {
    jclass der_serializer_cls = (*jenv)->GetObjectClass(jenv, jderSerializer);
    if (NULL == der_serializer_cls) {
        printf("Class KeySerializer not found.");
    }
    jfieldID der_serializer_fidCtx = (*jenv)->GetFieldID(jenv, der_serializer_cls, "cCtx", "J");
    if (NULL == der_serializer_fidCtx) {
        printf("Class 'KeySerializer' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ der_serializer = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jderSerializer, der_serializer_fidCtx);

    vscf_pkcs8_serializer_release_der_serializer((vscf_impl_t */*6*/ *) c_ctx);
    vscf_pkcs8_serializer_use_der_serializer((vscf_impl_t */*6*/ *) c_ctx, der_serializer);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_pkcs8_serializer_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pkcs8_serializer_delete((vscf_pkcs8_serializer_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_pkcs8_serializer_setup_defaults((vscf_pkcs8_serializer_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializedPublicKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        printf("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        printf("Class 'PublicKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ public_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);

    jint ret = vscf_pkcs8_serializer_serialized_public_key_len((vscf_pkcs8_serializer_t /*7*/ *) c_ctx /*1*/, public_key /*3*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        printf("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        printf("Class 'PublicKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ public_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs8_serializer_serialized_public_key_len((vscf_pkcs8_serializer_t /*7*/ *) c_ctx /*3*/, public_key/*a*/));

    vscf_status_t status = vscf_pkcs8_serializer_serialize_public_key((vscf_pkcs8_serializer_t /*7*/ *) c_ctx /*1*/, public_key /*3*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializedPrivateKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        printf("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        printf("Class 'PrivateKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ private_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);

    jint ret = vscf_pkcs8_serializer_serialized_private_key_len((vscf_pkcs8_serializer_t /*7*/ *) c_ctx /*1*/, private_key /*3*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        printf("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        printf("Class 'PrivateKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ private_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs8_serializer_serialized_private_key_len((vscf_pkcs8_serializer_t /*7*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_pkcs8_serializer_serialize_private_key((vscf_pkcs8_serializer_t /*7*/ *) c_ctx /*1*/, private_key /*3*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1setAsn1Reader (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Reader) {
    jclass asn1_reader_cls = (*jenv)->GetObjectClass(jenv, jasn1Reader);
    if (NULL == asn1_reader_cls) {
        printf("Class Asn1Reader not found.");
    }
    jfieldID asn1_reader_fidCtx = (*jenv)->GetFieldID(jenv, asn1_reader_cls, "cCtx", "J");
    if (NULL == asn1_reader_fidCtx) {
        printf("Class 'Asn1Reader' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1_reader = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1Reader, asn1_reader_fidCtx);

    vscf_pkcs8_deserializer_release_asn1_reader((vscf_impl_t */*6*/ *) c_ctx);
    vscf_pkcs8_deserializer_use_asn1_reader((vscf_impl_t */*6*/ *) c_ctx, asn1_reader);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1setDerDeserializer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jderDeserializer) {
    jclass der_deserializer_cls = (*jenv)->GetObjectClass(jenv, jderDeserializer);
    if (NULL == der_deserializer_cls) {
        printf("Class KeyDeserializer not found.");
    }
    jfieldID der_deserializer_fidCtx = (*jenv)->GetFieldID(jenv, der_deserializer_cls, "cCtx", "J");
    if (NULL == der_deserializer_fidCtx) {
        printf("Class 'KeyDeserializer' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ der_deserializer = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jderDeserializer, der_deserializer_fidCtx);

    vscf_pkcs8_deserializer_release_der_deserializer((vscf_impl_t */*6*/ *) c_ctx);
    vscf_pkcs8_deserializer_use_der_deserializer((vscf_impl_t */*6*/ *) c_ctx, der_deserializer);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_pkcs8_deserializer_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pkcs8_deserializer_delete((vscf_pkcs8_deserializer_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_pkcs8_deserializer_setup_defaults((vscf_pkcs8_deserializer_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1deserializePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpublicKeyData) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t public_key_data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jpublicKeyData, NULL),
        (*jenv)->GetArrayLength(jenv, jpublicKeyData));

    vscf_raw_key_t * /*5*/ proxyResult = vscf_pkcs8_deserializer_deserialize_public_key((vscf_pkcs8_deserializer_t /*7*/ *) c_ctx /*1*/, public_key_data /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/RawKey");
    if (NULL == result_cls) {
        printf("Class RawKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class RawKey has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pkcs8Deserializer_1deserializePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jprivateKeyData) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t private_key_data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jprivateKeyData, NULL),
        (*jenv)->GetArrayLength(jenv, jprivateKeyData));

    vscf_raw_key_t * /*5*/ proxyResult = vscf_pkcs8_deserializer_deserialize_private_key((vscf_pkcs8_deserializer_t /*7*/ *) c_ctx /*1*/, private_key_data /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/RawKey");
    if (NULL == result_cls) {
        printf("Class RawKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class RawKey has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vscf_ed25519_public_key_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ed25519_public_key_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1setEcies (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jecies) {
    jclass ecies_cls = (*jenv)->GetObjectClass(jenv, jecies);
    if (NULL == ecies_cls) {
        printf("Class Ecies not found.");
    }
    jfieldID ecies_fidCtx = (*jenv)->GetFieldID(jenv, ecies_cls, "cCtx", "J");
    if (NULL == ecies_fidCtx) {
        printf("Class 'Ecies' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ ecies = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jecies, ecies_fidCtx);

    vscf_ed25519_public_key_release_ecies((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ed25519_public_key_use_ecies((vscf_impl_t */*6*/ *) c_ctx, ecies);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_ed25519_public_key_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ed25519_public_key_delete((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_ed25519_public_key_setup_defaults((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_ed25519_public_key_alg_id((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_ed25519_public_key_produce_alg_info((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_ed25519_public_key_restore_alg_info((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1keyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_ed25519_public_key_key_len((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1keyBitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_ed25519_public_key_key_bitlen((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ed25519_public_key_encrypted_len((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_ed25519_public_key_encrypt((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_ed25519_public_key_encrypted_len((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1verifyHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jhashDigest, jobject jhashId, jbyteArray jsignature) {
    // Wrap input data
    vsc_data_t hash_digest = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jhashDigest, NULL),
        (*jenv)->GetArrayLength(jenv, jhashDigest));

    vsc_data_t signature = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jsignature, NULL),
        (*jenv)->GetArrayLength(jenv, jsignature));

    jboolean ret = vscf_ed25519_public_key_verify_hash((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/, hash_digest /*1*/, /* !enum! */ 1, signature /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ed25519_public_key_exported_public_key_len((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_ed25519_public_key_export_public_key((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1exportedPublicKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_ed25519_public_key_exported_public_key_len((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_status_t status = vscf_ed25519_public_key_import_public_key((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PublicKey_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    vscf_impl_t */*6*/ proxyResult = vscf_ed25519_public_key_generate_ephemeral_key((vscf_ed25519_public_key_t /*7*/ *) c_ctx /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    // TDB interface
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vscf_ed25519_private_key_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ed25519_private_key_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1setEcies (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jecies) {
    jclass ecies_cls = (*jenv)->GetObjectClass(jenv, jecies);
    if (NULL == ecies_cls) {
        printf("Class Ecies not found.");
    }
    jfieldID ecies_fidCtx = (*jenv)->GetFieldID(jenv, ecies_cls, "cCtx", "J");
    if (NULL == ecies_fidCtx) {
        printf("Class 'Ecies' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ ecies = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jecies, ecies_fidCtx);

    vscf_ed25519_private_key_release_ecies((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ed25519_private_key_use_ecies((vscf_impl_t */*6*/ *) c_ctx, ecies);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_ed25519_private_key_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ed25519_private_key_delete((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_ed25519_private_key_setup_defaults((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_ed25519_private_key_alg_id((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_ed25519_private_key_produce_alg_info((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_ed25519_private_key_restore_alg_info((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1keyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_ed25519_private_key_key_len((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1keyBitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_ed25519_private_key_key_bitlen((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1generateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_ed25519_private_key_generate_key((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ed25519_private_key_decrypted_len((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_ed25519_private_key_decrypt((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_ed25519_private_key_decrypted_len((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_ed25519_private_key_signature_len((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1signHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jhashDigest, jobject jhashId) {
    // Wrap input data
    vsc_data_t hash_digest = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jhashDigest, NULL),
        (*jenv)->GetArrayLength(jenv, jhashDigest));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_ed25519_private_key_signature_len((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_ed25519_private_key_sign_hash((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/, hash_digest /*1*/, /* !enum! */ 1, signature /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), vsc_buffer_bytes(signature));
    // Free resources
    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1extractPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_ed25519_private_key_extract_public_key((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ed25519_private_key_exported_private_key_len((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_ed25519_private_key_export_private_key((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1exportedPrivateKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_ed25519_private_key_exported_private_key_len((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_status_t status = vscf_ed25519_private_key_import_private_key((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1computeSharedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        printf("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        printf("Class 'PublicKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ public_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_ed25519_private_key_shared_key_len((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_ed25519_private_key_compute_shared_key((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/, public_key /*3*/, shared_key /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), vsc_buffer_bytes(shared_key));
    // Free resources
    vsc_buffer_delete(shared_key);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ed25519PrivateKey_1sharedKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_ed25519_private_key_shared_key_len((vscf_ed25519_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vscf_curve25519_public_key_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vscf_curve25519_public_key_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1setEcies (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jecies) {
    jclass ecies_cls = (*jenv)->GetObjectClass(jenv, jecies);
    if (NULL == ecies_cls) {
        printf("Class Ecies not found.");
    }
    jfieldID ecies_fidCtx = (*jenv)->GetFieldID(jenv, ecies_cls, "cCtx", "J");
    if (NULL == ecies_fidCtx) {
        printf("Class 'Ecies' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ ecies = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jecies, ecies_fidCtx);

    vscf_curve25519_public_key_release_ecies((vscf_impl_t */*6*/ *) c_ctx);
    vscf_curve25519_public_key_use_ecies((vscf_impl_t */*6*/ *) c_ctx, ecies);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_curve25519_public_key_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_curve25519_public_key_delete((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_curve25519_public_key_setup_defaults((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_curve25519_public_key_alg_id((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_curve25519_public_key_produce_alg_info((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_curve25519_public_key_restore_alg_info((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1keyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_curve25519_public_key_key_len((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1keyBitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_curve25519_public_key_key_bitlen((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_curve25519_public_key_encrypted_len((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_curve25519_public_key_encrypt((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_curve25519_public_key_encrypted_len((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_curve25519_public_key_exported_public_key_len((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_curve25519_public_key_export_public_key((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1exportedPublicKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_curve25519_public_key_exported_public_key_len((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_status_t status = vscf_curve25519_public_key_import_public_key((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PublicKey_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    vscf_impl_t */*6*/ proxyResult = vscf_curve25519_public_key_generate_ephemeral_key((vscf_curve25519_public_key_t /*7*/ *) c_ctx /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    // TDB interface
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vscf_curve25519_private_key_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vscf_curve25519_private_key_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1setEcies (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jecies) {
    jclass ecies_cls = (*jenv)->GetObjectClass(jenv, jecies);
    if (NULL == ecies_cls) {
        printf("Class Ecies not found.");
    }
    jfieldID ecies_fidCtx = (*jenv)->GetFieldID(jenv, ecies_cls, "cCtx", "J");
    if (NULL == ecies_fidCtx) {
        printf("Class 'Ecies' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ ecies = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jecies, ecies_fidCtx);

    vscf_curve25519_private_key_release_ecies((vscf_impl_t */*6*/ *) c_ctx);
    vscf_curve25519_private_key_use_ecies((vscf_impl_t */*6*/ *) c_ctx, ecies);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_curve25519_private_key_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_curve25519_private_key_delete((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_curve25519_private_key_setup_defaults((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_curve25519_private_key_alg_id((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_curve25519_private_key_produce_alg_info((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    vscf_status_t status = vscf_curve25519_private_key_restore_alg_info((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1keyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_curve25519_private_key_key_len((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1keyBitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_curve25519_private_key_key_bitlen((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1generateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_curve25519_private_key_generate_key((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_curve25519_private_key_decrypted_len((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_curve25519_private_key_decrypt((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_curve25519_private_key_decrypted_len((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1extractPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_curve25519_private_key_extract_public_key((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_curve25519_private_key_exported_private_key_len((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_curve25519_private_key_export_private_key((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1exportedPrivateKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_curve25519_private_key_exported_private_key_len((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_status_t status = vscf_curve25519_private_key_import_private_key((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/, data /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1computeSharedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        printf("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        printf("Class 'PublicKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ public_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_curve25519_private_key_shared_key_len((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_curve25519_private_key_compute_shared_key((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/, public_key /*3*/, shared_key /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), vsc_buffer_bytes(shared_key));
    // Free resources
    vsc_buffer_delete(shared_key);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_curve25519PrivateKey_1sharedKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_curve25519_private_key_shared_key_len((vscf_curve25519_private_key_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        printf("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        printf("Class 'Random' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ random = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);

    vscf_ecies_release_random((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ecies_use_random((vscf_impl_t */*6*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setCipher (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jcipher) {
    jclass cipher_cls = (*jenv)->GetObjectClass(jenv, jcipher);
    if (NULL == cipher_cls) {
        printf("Class Cipher not found.");
    }
    jfieldID cipher_fidCtx = (*jenv)->GetFieldID(jenv, cipher_cls, "cCtx", "J");
    if (NULL == cipher_fidCtx) {
        printf("Class 'Cipher' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ cipher = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jcipher, cipher_fidCtx);

    vscf_ecies_release_cipher((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ecies_use_cipher((vscf_impl_t */*6*/ *) c_ctx, cipher);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setMac (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmac) {
    jclass mac_cls = (*jenv)->GetObjectClass(jenv, jmac);
    if (NULL == mac_cls) {
        printf("Class Mac not found.");
    }
    jfieldID mac_fidCtx = (*jenv)->GetFieldID(jenv, mac_cls, "cCtx", "J");
    if (NULL == mac_fidCtx) {
        printf("Class 'Mac' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ mac = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jmac, mac_fidCtx);

    vscf_ecies_release_mac((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ecies_use_mac((vscf_impl_t */*6*/ *) c_ctx, mac);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setKdf (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkdf) {
    jclass kdf_cls = (*jenv)->GetObjectClass(jenv, jkdf);
    if (NULL == kdf_cls) {
        printf("Class Kdf not found.");
    }
    jfieldID kdf_fidCtx = (*jenv)->GetFieldID(jenv, kdf_cls, "cCtx", "J");
    if (NULL == kdf_fidCtx) {
        printf("Class 'Kdf' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ kdf = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jkdf, kdf_fidCtx);

    vscf_ecies_release_kdf((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ecies_use_kdf((vscf_impl_t */*6*/ *) c_ctx, kdf);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setEncryptionKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jencryptionKey) {
    jclass encryption_key_cls = (*jenv)->GetObjectClass(jenv, jencryptionKey);
    if (NULL == encryption_key_cls) {
        printf("Class PublicKey not found.");
    }
    jfieldID encryption_key_fidCtx = (*jenv)->GetFieldID(jenv, encryption_key_cls, "cCtx", "J");
    if (NULL == encryption_key_fidCtx) {
        printf("Class 'PublicKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ encryption_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jencryptionKey, encryption_key_fidCtx);

    vscf_ecies_release_encryption_key((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ecies_use_encryption_key((vscf_impl_t */*6*/ *) c_ctx, encryption_key);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setDecryptionKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jdecryptionKey) {
    jclass decryption_key_cls = (*jenv)->GetObjectClass(jenv, jdecryptionKey);
    if (NULL == decryption_key_cls) {
        printf("Class PrivateKey not found.");
    }
    jfieldID decryption_key_fidCtx = (*jenv)->GetFieldID(jenv, decryption_key_cls, "cCtx", "J");
    if (NULL == decryption_key_fidCtx) {
        printf("Class 'PrivateKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ decryption_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jdecryptionKey, decryption_key_fidCtx);

    vscf_ecies_release_decryption_key((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ecies_use_decryption_key((vscf_impl_t */*6*/ *) c_ctx, decryption_key);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jephemeralKey) {
    jclass ephemeral_key_cls = (*jenv)->GetObjectClass(jenv, jephemeralKey);
    if (NULL == ephemeral_key_cls) {
        printf("Class PrivateKey not found.");
    }
    jfieldID ephemeral_key_fidCtx = (*jenv)->GetFieldID(jenv, ephemeral_key_cls, "cCtx", "J");
    if (NULL == ephemeral_key_fidCtx) {
        printf("Class 'PrivateKey' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ ephemeral_key = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jephemeralKey, ephemeral_key_fidCtx);

    vscf_ecies_release_ephemeral_key((vscf_impl_t */*6*/ *) c_ctx);
    vscf_ecies_use_ephemeral_key((vscf_impl_t */*6*/ *) c_ctx, ephemeral_key);
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_ecies_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ecies_delete((vscf_ecies_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_ecies_setup_defaults((vscf_ecies_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecies_encrypted_len((vscf_ecies_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_ecies_encrypt((vscf_ecies_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_ecies_encrypted_len((vscf_ecies_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecies_decrypted_len((vscf_ecies_t /*7*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_ecies_decrypt((vscf_ecies_t /*7*/ *) c_ctx /*1*/, data /*1*/, out /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_ecies_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    jint ret = vscf_ecies_decrypted_len((vscf_ecies_t /*7*/ *) c_ctx /*1*/, jdataLen /*4*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_simpleAlgInfo_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_simple_alg_info_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_simpleAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_simple_alg_info_delete((vscf_simple_alg_info_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_simpleAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_simple_alg_info_alg_id((vscf_simple_alg_info_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1hashAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_hash_based_alg_info_hash_alg_info((vscf_hash_based_alg_info_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_hash_based_alg_info_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_hash_based_alg_info_delete((vscf_hash_based_alg_info_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_hash_based_alg_info_alg_id((vscf_hash_based_alg_info_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_cipherAlgInfo_1nonce (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_cipher_alg_info_nonce((vscf_cipher_alg_info_t /*7*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_cipherAlgInfo_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_cipher_alg_info_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_cipherAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_cipher_alg_info_delete((vscf_cipher_alg_info_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_cipherAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_cipher_alg_info_alg_id((vscf_cipher_alg_info_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1hashAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_salted_kdf_alg_info_hash_alg_info((vscf_salted_kdf_alg_info_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1salt (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vsc_data_t /*3*/ proxyResult = vscf_salted_kdf_alg_info_salt((vscf_salted_kdf_alg_info_t /*7*/ *) c_ctx /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, proxyResult.bytes);
    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1iterationCount (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    jint ret = vscf_salted_kdf_alg_info_iteration_count((vscf_salted_kdf_alg_info_t /*7*/ *) c_ctx /*1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_salted_kdf_alg_info_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_salted_kdf_alg_info_delete((vscf_salted_kdf_alg_info_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_salted_kdf_alg_info_alg_id((vscf_salted_kdf_alg_info_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1kdfAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_pbe_alg_info_kdf_alg_info((vscf_pbe_alg_info_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1cipherAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_impl_t */*6*/ proxyResult = vscf_pbe_alg_info_cipher_alg_info((vscf_pbe_alg_info_t /*7*/ *) c_ctx /*1*/);
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_pbe_alg_info_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pbe_alg_info_delete((vscf_pbe_alg_info_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_pbeAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_id_t proxyResult = vscf_pbe_alg_info_alg_id((vscf_pbe_alg_info_t /*7*/ *) c_ctx /*1*/);
    jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/AlgId");
    if (NULL == cls) {
        printf("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lvirgil/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        printf("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1setAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Writer) {
    jclass asn1_writer_cls = (*jenv)->GetObjectClass(jenv, jasn1Writer);
    if (NULL == asn1_writer_cls) {
        printf("Class Asn1Writer not found.");
    }
    jfieldID asn1_writer_fidCtx = (*jenv)->GetFieldID(jenv, asn1_writer_cls, "cCtx", "J");
    if (NULL == asn1_writer_fidCtx) {
        printf("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1_writer = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1Writer, asn1_writer_fidCtx);

    vscf_alg_info_der_serializer_release_asn1_writer((vscf_impl_t */*6*/ *) c_ctx);
    vscf_alg_info_der_serializer_use_asn1_writer((vscf_impl_t */*6*/ *) c_ctx, asn1_writer);
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serializeInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    jint ret = vscf_alg_info_der_serializer_serialize_inplace((vscf_alg_info_der_serializer_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_alg_info_der_serializer_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_info_der_serializer_delete((vscf_alg_info_der_serializer_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_alg_info_der_serializer_setup_defaults((vscf_alg_info_der_serializer_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serializedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    jint ret = vscf_alg_info_der_serializer_serialized_len((vscf_alg_info_der_serializer_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        printf("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        printf("Class 'AlgInfo' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ alg_info = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_alg_info_der_serializer_serialized_len((vscf_alg_info_der_serializer_t /*7*/ *) c_ctx /*3*/, alg_info/*a*/));

    vscf_alg_info_der_serializer_serialize((vscf_alg_info_der_serializer_t /*7*/ *) c_ctx /*1*/, alg_info /*3*/, out /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1setAsn1Reader (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Reader) {
    jclass asn1_reader_cls = (*jenv)->GetObjectClass(jenv, jasn1Reader);
    if (NULL == asn1_reader_cls) {
        printf("Class Asn1Reader not found.");
    }
    jfieldID asn1_reader_fidCtx = (*jenv)->GetFieldID(jenv, asn1_reader_cls, "cCtx", "J");
    if (NULL == asn1_reader_fidCtx) {
        printf("Class 'Asn1Reader' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1_reader = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1Reader, asn1_reader_fidCtx);

    vscf_alg_info_der_deserializer_release_asn1_reader((vscf_impl_t */*6*/ *) c_ctx);
    vscf_alg_info_der_deserializer_use_asn1_reader((vscf_impl_t */*6*/ *) c_ctx, asn1_reader);
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1deserializeInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_inplace((vscf_alg_info_der_deserializer_t /*7*/ *) c_ctx /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_alg_info_der_deserializer_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_info_der_deserializer_delete((vscf_alg_info_der_deserializer_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_alg_info_der_deserializer_setup_defaults((vscf_alg_info_der_deserializer_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1deserialize (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize((vscf_alg_info_der_deserializer_t /*7*/ *) c_ctx /*1*/, data /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    // TDB interface
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setAsn1Reader (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Reader) {
    jclass asn1_reader_cls = (*jenv)->GetObjectClass(jenv, jasn1Reader);
    if (NULL == asn1_reader_cls) {
        printf("Class Asn1Reader not found.");
    }
    jfieldID asn1_reader_fidCtx = (*jenv)->GetFieldID(jenv, asn1_reader_cls, "cCtx", "J");
    if (NULL == asn1_reader_fidCtx) {
        printf("Class 'Asn1Reader' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1_reader = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1Reader, asn1_reader_fidCtx);

    vscf_message_info_der_serializer_release_asn1_reader((vscf_impl_t */*6*/ *) c_ctx);
    vscf_status_t status = vscf_message_info_der_serializer_use_asn1_reader((vscf_impl_t */*6*/ *) c_ctx, asn1_reader);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Writer) {
    jclass asn1_writer_cls = (*jenv)->GetObjectClass(jenv, jasn1Writer);
    if (NULL == asn1_writer_cls) {
        printf("Class Asn1Writer not found.");
    }
    jfieldID asn1_writer_fidCtx = (*jenv)->GetFieldID(jenv, asn1_writer_cls, "cCtx", "J");
    if (NULL == asn1_writer_fidCtx) {
        printf("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    vscf_impl_t */*6*/ asn1_writer = (vscf_impl_t */*6*/) (*jenv)->GetLongField(jenv, jasn1Writer, asn1_writer_fidCtx);

    vscf_message_info_der_serializer_release_asn1_writer((vscf_impl_t */*6*/ *) c_ctx);
    vscf_status_t status = vscf_message_info_der_serializer_use_asn1_writer((vscf_impl_t */*6*/ *) c_ctx, asn1_writer);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jlong JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1new (JNIEnv *jenv, jobject jobj) {
    return (jlong) vscf_message_info_der_serializer_new();
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_der_serializer_delete((vscf_message_info_der_serializer_t /*7*/ *) c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_status_t status = vscf_message_info_der_serializer_setup_defaults((vscf_message_info_der_serializer_t /*7*/ *) c_ctx /*1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serializedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessageInfo) {
    // Wrap Java classes
    jclass message_info_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/MessageInfo");
    if (NULL == message_info_cls) {
        printf("Class MessageInfo not found.");
    }
    jfieldID message_info_fidCtx = (*jenv)->GetFieldID(jenv, message_info_cls, "cCtx", "J");
    if (NULL == message_info_fidCtx) {
        printf("Class 'MessageInfo' has no field 'cCtx'.");
    }
    vscf_message_info_t * /*5*/ message_info = (vscf_message_info_t * /*5*/) (*jenv)->GetLongField(jenv, jmessageInfo, message_info_fidCtx);

    jint ret = vscf_message_info_der_serializer_serialized_len((vscf_message_info_der_serializer_t /*7*/ *) c_ctx /*1*/, message_info /*3*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessageInfo) {
    // Wrap Java classes
    jclass message_info_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/MessageInfo");
    if (NULL == message_info_cls) {
        printf("Class MessageInfo not found.");
    }
    jfieldID message_info_fidCtx = (*jenv)->GetFieldID(jenv, message_info_cls, "cCtx", "J");
    if (NULL == message_info_fidCtx) {
        printf("Class 'MessageInfo' has no field 'cCtx'.");
    }
    vscf_message_info_t * /*5*/ message_info = (vscf_message_info_t * /*5*/) (*jenv)->GetLongField(jenv, jmessageInfo, message_info_fidCtx);

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_len((vscf_message_info_der_serializer_t /*7*/ *) c_ctx /*3*/, message_info/*a*/));

    vscf_message_info_der_serializer_serialize((vscf_message_info_der_serializer_t /*7*/ *) c_ctx /*1*/, message_info /*3*/, out /*1*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1readPrefix (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    jint ret = vscf_message_info_der_serializer_read_prefix((vscf_message_info_der_serializer_t /*7*/ *) c_ctx /*1*/, data /*1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_virgil_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1deserialize (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    vsc_data_t data = vsc_data(
        (*jenv)->GetByteArrayElements(jenv, jdata, NULL),
        (*jenv)->GetArrayLength(jenv, jdata));

    vscf_message_info_t * /*5*/ proxyResult = vscf_message_info_der_serializer_deserialize((vscf_message_info_der_serializer_t /*7*/ *) c_ctx /*1*/, data /*1*/, &error /*2*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "virgil/crypto/foundation/MessageInfo");
    if (NULL == result_cls) {
        printf("Class MessageInfo not found.");
    }
    jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "(J)V");
    if (NULL == result_methodID) {
        printf("Class MessageInfo has no constructor with C context parameter.");
    }
    jobject ret = (*jenv)->NewObject(jenv, result_cls, result_methodID, proxyResult);
    return ret;
}

