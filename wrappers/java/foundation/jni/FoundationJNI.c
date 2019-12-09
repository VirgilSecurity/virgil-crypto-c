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

#include "FoundationJNI.h"

#include "vscf_foundation_public.h"

#include <string.h>

jint throwFoundationException (JNIEnv *jenv, jobject jobj, jint statusCode) {
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/FoundationException");
    if (NULL == cls) {
        VSCF_ASSERT("Class PheException not found.");
        return 0;
    }

    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");
    if (NULL == methodID) {
        VSCF_ASSERT("Class com/virgilsecurity/crypto/foundation/FoundationException has no constructor.");
        return 0;
    }
    jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);
    if (NULL == obj) {
        VSCF_ASSERT("Can't instantiate com/virgilsecurity/crypto/foundation/FoundationException.");
        return 0;
    }
    return (*jenv)->Throw(jenv, obj);
}

char* getAlgClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_alg_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Alg.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
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
    case vscf_impl_tag_RSA:
        strcat (classFullName, "Rsa");
        break;
    case vscf_impl_tag_ECC:
        strcat (classFullName, "Ecc");
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
    case vscf_impl_tag_ED25519:
        strcat (classFullName, "Ed25519");
        break;
    case vscf_impl_tag_CURVE25519:
        strcat (classFullName, "Curve25519");
        break;
    case vscf_impl_tag_FALCON:
        strcat (classFullName, "Falcon");
        break;
    case vscf_impl_tag_ROUND5:
        strcat (classFullName, "Round5");
        break;
    case vscf_impl_tag_COMPOUND_KEY_ALG:
        strcat (classFullName, "CompoundKeyAlg");
        break;
    case vscf_impl_tag_CHAINED_KEY_ALG:
        strcat (classFullName, "ChainedKeyAlg");
        break;
    case vscf_impl_tag_RANDOM_PADDING:
        strcat (classFullName, "RandomPadding");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAlg (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getAlgClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getHashClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_hash_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Hash.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
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
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapHash (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getHashClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getEncryptClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_encrypt_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Encrypt.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    case vscf_impl_tag_AES256_CBC:
        strcat (classFullName, "Aes256Cbc");
        break;
    case vscf_impl_tag_PKCS5_PBES2:
        strcat (classFullName, "Pkcs5Pbes2");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapEncrypt (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getEncryptClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getDecryptClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_decrypt_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Decrypt.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    case vscf_impl_tag_AES256_CBC:
        strcat (classFullName, "Aes256Cbc");
        break;
    case vscf_impl_tag_PKCS5_PBES2:
        strcat (classFullName, "Pkcs5Pbes2");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapDecrypt (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getDecryptClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getCipherInfoClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_cipher_info_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface CipherInfo.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    case vscf_impl_tag_AES256_CBC:
        strcat (classFullName, "Aes256Cbc");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapCipherInfo (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getCipherInfoClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getCipherClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_cipher_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Cipher.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    case vscf_impl_tag_AES256_CBC:
        strcat (classFullName, "Aes256Cbc");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapCipher (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getCipherClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getCipherAuthInfoClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_cipher_auth_info_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface CipherAuthInfo.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapCipherAuthInfo (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getCipherAuthInfoClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getAuthEncryptClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_auth_encrypt_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface AuthEncrypt.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAuthEncrypt (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getAuthEncryptClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getAuthDecryptClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_auth_decrypt_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface AuthDecrypt.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAuthDecrypt (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getAuthDecryptClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getCipherAuthClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_cipher_auth_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface CipherAuth.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_AES256_GCM:
        strcat (classFullName, "Aes256Gcm");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapCipherAuth (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getCipherAuthClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getAsn1ReaderClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_asn1_reader_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Asn1Reader.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_ASN1RD:
        strcat (classFullName, "Asn1rd");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAsn1Reader (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getAsn1ReaderClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getAsn1WriterClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_asn1_writer_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Asn1Writer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_ASN1WR:
        strcat (classFullName, "Asn1wr");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAsn1Writer (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getAsn1WriterClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getKeyClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_key_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Key.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        strcat (classFullName, "RsaPublicKey");
        break;
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        strcat (classFullName, "RsaPrivateKey");
        break;
    case vscf_impl_tag_ECC_PUBLIC_KEY:
        strcat (classFullName, "EccPublicKey");
        break;
    case vscf_impl_tag_ECC_PRIVATE_KEY:
        strcat (classFullName, "EccPrivateKey");
        break;
    case vscf_impl_tag_RAW_PUBLIC_KEY:
        strcat (classFullName, "RawPublicKey");
        break;
    case vscf_impl_tag_RAW_PRIVATE_KEY:
        strcat (classFullName, "RawPrivateKey");
        break;
    case vscf_impl_tag_COMPOUND_PUBLIC_KEY:
        strcat (classFullName, "CompoundPublicKey");
        break;
    case vscf_impl_tag_COMPOUND_PRIVATE_KEY:
        strcat (classFullName, "CompoundPrivateKey");
        break;
    case vscf_impl_tag_CHAINED_PUBLIC_KEY:
        strcat (classFullName, "ChainedPublicKey");
        break;
    case vscf_impl_tag_CHAINED_PRIVATE_KEY:
        strcat (classFullName, "ChainedPrivateKey");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKey (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getKeyClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getPublicKeyClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_public_key_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface PublicKey.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        strcat (classFullName, "RsaPublicKey");
        break;
    case vscf_impl_tag_ECC_PUBLIC_KEY:
        strcat (classFullName, "EccPublicKey");
        break;
    case vscf_impl_tag_RAW_PUBLIC_KEY:
        strcat (classFullName, "RawPublicKey");
        break;
    case vscf_impl_tag_COMPOUND_PUBLIC_KEY:
        strcat (classFullName, "CompoundPublicKey");
        break;
    case vscf_impl_tag_CHAINED_PUBLIC_KEY:
        strcat (classFullName, "ChainedPublicKey");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapPublicKey (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getPublicKeyClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getPrivateKeyClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_private_key_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface PrivateKey.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        strcat (classFullName, "RsaPrivateKey");
        break;
    case vscf_impl_tag_ECC_PRIVATE_KEY:
        strcat (classFullName, "EccPrivateKey");
        break;
    case vscf_impl_tag_RAW_PRIVATE_KEY:
        strcat (classFullName, "RawPrivateKey");
        break;
    case vscf_impl_tag_COMPOUND_PRIVATE_KEY:
        strcat (classFullName, "CompoundPrivateKey");
        break;
    case vscf_impl_tag_CHAINED_PRIVATE_KEY:
        strcat (classFullName, "ChainedPrivateKey");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapPrivateKey (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getPrivateKeyClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getKeyAlgClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_key_alg_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface KeyAlg.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_RSA:
        strcat (classFullName, "Rsa");
        break;
    case vscf_impl_tag_ECC:
        strcat (classFullName, "Ecc");
        break;
    case vscf_impl_tag_ED25519:
        strcat (classFullName, "Ed25519");
        break;
    case vscf_impl_tag_CURVE25519:
        strcat (classFullName, "Curve25519");
        break;
    case vscf_impl_tag_FALCON:
        strcat (classFullName, "Falcon");
        break;
    case vscf_impl_tag_ROUND5:
        strcat (classFullName, "Round5");
        break;
    case vscf_impl_tag_COMPOUND_KEY_ALG:
        strcat (classFullName, "CompoundKeyAlg");
        break;
    case vscf_impl_tag_CHAINED_KEY_ALG:
        strcat (classFullName, "ChainedKeyAlg");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKeyAlg (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getKeyAlgClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getKeyCipherClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_key_cipher_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface KeyCipher.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_RSA:
        strcat (classFullName, "Rsa");
        break;
    case vscf_impl_tag_ECC:
        strcat (classFullName, "Ecc");
        break;
    case vscf_impl_tag_ED25519:
        strcat (classFullName, "Ed25519");
        break;
    case vscf_impl_tag_CURVE25519:
        strcat (classFullName, "Curve25519");
        break;
    case vscf_impl_tag_ROUND5:
        strcat (classFullName, "Round5");
        break;
    case vscf_impl_tag_COMPOUND_KEY_ALG:
        strcat (classFullName, "CompoundKeyAlg");
        break;
    case vscf_impl_tag_CHAINED_KEY_ALG:
        strcat (classFullName, "ChainedKeyAlg");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKeyCipher (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getKeyCipherClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getKeySignerClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_key_signer_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface KeySigner.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_RSA:
        strcat (classFullName, "Rsa");
        break;
    case vscf_impl_tag_ECC:
        strcat (classFullName, "Ecc");
        break;
    case vscf_impl_tag_ED25519:
        strcat (classFullName, "Ed25519");
        break;
    case vscf_impl_tag_FALCON:
        strcat (classFullName, "Falcon");
        break;
    case vscf_impl_tag_COMPOUND_KEY_ALG:
        strcat (classFullName, "CompoundKeyAlg");
        break;
    case vscf_impl_tag_CHAINED_KEY_ALG:
        strcat (classFullName, "ChainedKeyAlg");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKeySigner (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getKeySignerClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getComputeSharedKeyClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_compute_shared_key_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface ComputeSharedKey.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_ECC:
        strcat (classFullName, "Ecc");
        break;
    case vscf_impl_tag_ED25519:
        strcat (classFullName, "Ed25519");
        break;
    case vscf_impl_tag_CURVE25519:
        strcat (classFullName, "Curve25519");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapComputeSharedKey (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getComputeSharedKeyClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getEntropySourceClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_entropy_source_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface EntropySource.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_ENTROPY_ACCUMULATOR:
        strcat (classFullName, "EntropyAccumulator");
        break;
    case vscf_impl_tag_FAKE_RANDOM:
        strcat (classFullName, "FakeRandom");
        break;
    case vscf_impl_tag_SEED_ENTROPY_SOURCE:
        strcat (classFullName, "SeedEntropySource");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapEntropySource (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getEntropySourceClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getRandomClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_random_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Random.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_CTR_DRBG:
        strcat (classFullName, "CtrDrbg");
        break;
    case vscf_impl_tag_FAKE_RANDOM:
        strcat (classFullName, "FakeRandom");
        break;
    case vscf_impl_tag_KEY_MATERIAL_RNG:
        strcat (classFullName, "KeyMaterialRng");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapRandom (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getRandomClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getMacClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_mac_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Mac.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_HMAC:
        strcat (classFullName, "Hmac");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapMac (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getMacClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getKdfClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_kdf_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Kdf.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
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
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKdf (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getKdfClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getSaltedKdfClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_salted_kdf_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface SaltedKdf.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_HKDF:
        strcat (classFullName, "Hkdf");
        break;
    case vscf_impl_tag_PKCS5_PBKDF2:
        strcat (classFullName, "Pkcs5Pbkdf2");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapSaltedKdf (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getSaltedKdfClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getKeySerializerClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_key_serializer_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface KeySerializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_PKCS8_SERIALIZER:
        strcat (classFullName, "Pkcs8Serializer");
        break;
    case vscf_impl_tag_SEC1_SERIALIZER:
        strcat (classFullName, "Sec1Serializer");
        break;
    case vscf_impl_tag_KEY_ASN1_SERIALIZER:
        strcat (classFullName, "KeyAsn1Serializer");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKeySerializer (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getKeySerializerClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getKeyDeserializerClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_key_deserializer_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface KeyDeserializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_KEY_ASN1_DESERIALIZER:
        strcat (classFullName, "KeyAsn1Deserializer");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapKeyDeserializer (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getKeyDeserializerClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getAlgInfoClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_alg_info_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface AlgInfo.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_COMPOUND_KEY_ALG_INFO:
        strcat (classFullName, "CompoundKeyAlgInfo");
        break;
    case vscf_impl_tag_CHAINED_KEY_ALG_INFO:
        strcat (classFullName, "ChainedKeyAlgInfo");
        break;
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
    case vscf_impl_tag_ECC_ALG_INFO:
        strcat (classFullName, "EccAlgInfo");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAlgInfo (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getAlgInfoClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getAlgInfoSerializerClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_alg_info_serializer_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface AlgInfoSerializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
        strcat (classFullName, "AlgInfoDerSerializer");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAlgInfoSerializer (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getAlgInfoSerializerClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getAlgInfoDeserializerClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_alg_info_deserializer_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface AlgInfoDeserializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
        strcat (classFullName, "AlgInfoDerDeserializer");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapAlgInfoDeserializer (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getAlgInfoDeserializerClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getMessageInfoSerializerClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_message_info_serializer_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface MessageInfoSerializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        strcat (classFullName, "MessageInfoDerSerializer");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapMessageInfoSerializer (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getMessageInfoSerializerClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getMessageInfoFooterSerializerClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_message_info_footer_serializer_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface MessageInfoFooterSerializer.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        strcat (classFullName, "MessageInfoDerSerializer");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapMessageInfoFooterSerializer (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getMessageInfoFooterSerializerClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

char* getPaddingClassName (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    if (!vscf_padding_is_implemented(c_obj)) {
        VSCF_ASSERT("Given C implementation does not implement interface Padding.");
    }
    char *classFullName = malloc(200);
    strcpy (classFullName, "com/virgilsecurity/crypto/foundation/");
    vscf_impl_tag_t implTag = vscf_impl_tag(c_obj);
    switch(implTag) {
    case vscf_impl_tag_RANDOM_PADDING:
        strcat (classFullName, "RandomPadding");
        break;
    default:
        free(classFullName);
        VSCF_ASSERT("Unexpected C implementation cast to the Java implementation.");
    }
    return classFullName;
}

jobject wrapPadding (JNIEnv *jenv, jobject jobj, const vscf_impl_t /*1*/* c_obj) {
    char *classFullName = getPaddingClassName(jenv, jobj, c_obj);
    jclass cls = (*jenv)->FindClass(jenv, classFullName);
    if (NULL == cls) {
        free(classFullName);
        VSCF_ASSERT("Class not found.");
    }

    char *methodSig = malloc(200);
    strcpy (methodSig, "(J)L");
    strcat (methodSig, classFullName);
    strcat (methodSig, ";");
    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);
    free(classFullName);
    free (methodSig);
    if (NULL == methodID) {
        VSCF_ASSERT("Class has no 'getInstance' method.");
    }

    jlong c_ctx = 0;
    *(const vscf_impl_t /*1*/**) &c_ctx = c_obj;
    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1fromAlgId (JNIEnv *jenv, jobject jobj, jobject jalgId) {
    // Wrap enums
    jclass alg_id_cls = (*jenv)->GetObjectClass(jenv, jalgId);
    jmethodID alg_id_methodID = (*jenv)->GetMethodID(jenv, alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, alg_id_methodID);

    const vsc_data_t /*3*/ proxyResult = vscf_oid_from_alg_id(alg_id /*a7*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1toAlgId (JNIEnv *jenv, jobject jobj, jbyteArray joid) {
    // Wrap input data
    byte* oid_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, joid, NULL);
    vsc_data_t oid = vsc_data(oid_arr, (*jenv)->GetArrayLength(jenv, joid));

    const vscf_alg_id_t proxyResult = vscf_oid_to_alg_id(oid /*a3*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, joid, (jbyte*) oid_arr, 0);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1fromId (JNIEnv *jenv, jobject jobj, jobject joidId) {
    // Wrap enums
    jclass oid_id_cls = (*jenv)->GetObjectClass(jenv, joidId);
    jmethodID oid_id_methodID = (*jenv)->GetMethodID(jenv, oid_id_cls, "getCode", "()I");
    vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oid_id_methodID);

    const vsc_data_t /*3*/ proxyResult = vscf_oid_from_id(oid_id /*a7*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1toId (JNIEnv *jenv, jobject jobj, jbyteArray joid) {
    // Wrap input data
    byte* oid_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, joid, NULL);
    vsc_data_t oid = vsc_data(oid_arr, (*jenv)->GetArrayLength(jenv, joid));

    const vscf_oid_id_t proxyResult = vscf_oid_to_id(oid /*a3*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/OidId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum OidId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/OidId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum OidId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, joid, (jbyte*) oid_arr, 0);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1idToAlgId (JNIEnv *jenv, jobject jobj, jobject joidId) {
    // Wrap enums
    jclass oid_id_cls = (*jenv)->GetObjectClass(jenv, joidId);
    jmethodID oid_id_methodID = (*jenv)->GetMethodID(jenv, oid_id_cls, "getCode", "()I");
    vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oid_id_methodID);

    const vscf_alg_id_t proxyResult = vscf_oid_id_to_alg_id(oid_id /*a7*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_oid_1equal (JNIEnv *jenv, jobject jobj, jbyteArray jlhs, jbyteArray jrhs) {
    // Wrap input data
    byte* lhs_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jlhs, NULL);
    vsc_data_t lhs = vsc_data(lhs_arr, (*jenv)->GetArrayLength(jenv, jlhs));

    byte* rhs_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrhs, NULL);
    vsc_data_t rhs = vsc_data(rhs_arr, (*jenv)->GetArrayLength(jenv, jrhs));

    jboolean ret = (jboolean) vscf_oid_equal(lhs /*a3*/, rhs /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jlhs, (jbyte*) lhs_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jrhs, (jbyte*) rhs_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_base64_1encodedLen (JNIEnv *jenv, jobject jobj, jint jdataLen) {
    jint ret = (jint) vscf_base64_encoded_len(jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_base64_1encode (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *str = vsc_buffer_new_with_capacity(vscf_base64_encoded_len(data.len/*a*/));

    vscf_base64_encode(data /*a3*/, str /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(str));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(str), (jbyte*) vsc_buffer_bytes(str));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(str);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_base64_1decodedLen (JNIEnv *jenv, jobject jobj, jint jstrLen) {
    jint ret = (jint) vscf_base64_decoded_len(jstrLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_base64_1decode (JNIEnv *jenv, jobject jobj, jbyteArray jstr) {
    // Wrap input data
    byte* str_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jstr, NULL);
    vsc_data_t str = vsc_data(str_arr, (*jenv)->GetArrayLength(jenv, jstr));

    vsc_buffer_t *data = vsc_buffer_new_with_capacity(vscf_base64_decoded_len(str.len/*a*/));

    vscf_status_t status = vscf_base64_decode(str /*a3*/, data /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), (jbyte*) vsc_buffer_bytes(data));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jstr, (jbyte*) str_arr, 0);

    vsc_buffer_delete(data);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1wrappedLen (JNIEnv *jenv, jobject jobj, jstring jtitle, jint jdataLen) {
    // Wrap Java strings
    const char *title = (*jenv)->GetStringUTFChars(jenv, jtitle, NULL);

    jint ret = (jint) vscf_pem_wrapped_len(title /*a8*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1wrap (JNIEnv *jenv, jobject jobj, jstring jtitle, jbyteArray jdata) {
    // Wrap Java strings
    const char *title = (*jenv)->GetStringUTFChars(jenv, jtitle, NULL);

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *pem = vsc_buffer_new_with_capacity(vscf_pem_wrapped_len(title/*a*/, data.len/*a*/));

    vscf_pem_wrap(title /*a8*/, data /*a3*/, pem /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(pem));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(pem), (jbyte*) vsc_buffer_bytes(pem));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(pem);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1unwrappedLen (JNIEnv *jenv, jobject jobj, jint jpemLen) {
    jint ret = (jint) vscf_pem_unwrapped_len(jpemLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1unwrap (JNIEnv *jenv, jobject jobj, jbyteArray jpem) {
    // Wrap input data
    byte* pem_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpem, NULL);
    vsc_data_t pem = vsc_data(pem_arr, (*jenv)->GetArrayLength(jenv, jpem));

    vsc_buffer_t *data = vsc_buffer_new_with_capacity(vscf_pem_unwrapped_len(pem.len/*a*/));

    vscf_status_t status = vscf_pem_unwrap(pem /*a3*/, data /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), (jbyte*) vsc_buffer_bytes(data));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpem, (jbyte*) pem_arr, 0);

    vsc_buffer_delete(data);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pem_1title (JNIEnv *jenv, jobject jobj, jbyteArray jpem) {
    // Wrap input data
    byte* pem_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpem, NULL);
    vsc_data_t pem = vsc_data(pem_arr, (*jenv)->GetArrayLength(jenv, jpem));

    const vsc_data_t /*3*/ proxyResult = vscf_pem_title(pem /*a3*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpem, (jbyte*) pem_arr, 0);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_message_info_t **)&c_ctx = vscf_message_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_delete(*(vscf_message_info_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1dataEncryptionAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_message_info_data_encryption_alg_info(message_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1keyRecipientInfoList (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    const vscf_key_recipient_info_list_t */*5*/ proxyResult = vscf_message_info_key_recipient_info_list(message_info_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/KeyRecipientInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class KeyRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/KeyRecipientInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class KeyRecipientInfoList has no 'getInstance' method.");
    }
    vscf_key_recipient_info_list_shallow_copy((vscf_key_recipient_info_list_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1passwordRecipientInfoList (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    const vscf_password_recipient_info_list_t */*5*/ proxyResult = vscf_message_info_password_recipient_info_list(message_info_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/PasswordRecipientInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class PasswordRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/PasswordRecipientInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class PasswordRecipientInfoList has no 'getInstance' method.");
    }
    vscf_password_recipient_info_list_shallow_copy((vscf_password_recipient_info_list_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1hasCustomParams (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_message_info_has_custom_params(message_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1customParams (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    const vscf_message_info_custom_params_t */*5*/ proxyResult = vscf_message_info_custom_params(message_info_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/MessageInfoCustomParams");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class MessageInfoCustomParams not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/MessageInfoCustomParams;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class MessageInfoCustomParams has no 'getInstance' method.");
    }
    vscf_message_info_custom_params_shallow_copy((vscf_message_info_custom_params_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1hasCipherKdfAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_message_info_has_cipher_kdf_alg_info(message_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1cipherKdfAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_message_info_cipher_kdf_alg_info(message_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1hasCipherPaddingAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_message_info_has_cipher_padding_alg_info(message_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1cipherPaddingAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_message_info_cipher_padding_alg_info(message_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1hasFooterInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_message_info_has_footer_info(message_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1footerInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    const vscf_footer_info_t */*5*/ proxyResult = vscf_message_info_footer_info(message_info_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/FooterInfo");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class FooterInfo not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/FooterInfo;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class FooterInfo has no 'getInstance' method.");
    }
    vscf_footer_info_shallow_copy((vscf_footer_info_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfo_1clear (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

    vscf_message_info_clear(message_info_ctx /*a1*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_key_recipient_info_t **)&c_ctx = vscf_key_recipient_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_recipient_info_delete(*(vscf_key_recipient_info_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1new___3BLcom_virgilsecurity_crypto_foundation_AlgInfo_2_3B (JNIEnv *jenv, jobject jobj, jbyteArray jrecipientId, jobject jkeyEncryptionAlgorithm, jbyteArray jencryptedKey) {
    // Wrap Java interfaces
    jclass key_encryption_algorithm_cls = (*jenv)->GetObjectClass(jenv, jkeyEncryptionAlgorithm);
    if (NULL == key_encryption_algorithm_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID key_encryption_algorithm_fidCtx = (*jenv)->GetFieldID(jenv, key_encryption_algorithm_cls, "cCtx", "J");
    if (NULL == key_encryption_algorithm_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong key_encryption_algorithm_c_ctx = (*jenv)->GetLongField(jenv, jkeyEncryptionAlgorithm, key_encryption_algorithm_fidCtx);
    vscf_impl_t */*6*/ key_encryption_algorithm = *(vscf_impl_t */*6*/*)&key_encryption_algorithm_c_ctx;

    // Wrap input data
    byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
    vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

    byte* encrypted_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jencryptedKey, NULL);
    vsc_data_t encrypted_key = vsc_data(encrypted_key_arr, (*jenv)->GetArrayLength(jenv, jencryptedKey));

    jlong proxyResult = (jlong) vscf_key_recipient_info_new_with_data(recipient_id /*a3*/, key_encryption_algorithm /*a6*/, encrypted_key /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jencryptedKey, (jbyte*) encrypted_key_arr, 0);

    return proxyResult;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1recipientId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_t /*2*/* key_recipient_info_ctx = *(vscf_key_recipient_info_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_key_recipient_info_recipient_id(key_recipient_info_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1keyEncryptionAlgorithm (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_t /*2*/* key_recipient_info_ctx = *(vscf_key_recipient_info_t /*2*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_key_recipient_info_key_encryption_algorithm(key_recipient_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfo_1encryptedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_t /*2*/* key_recipient_info_ctx = *(vscf_key_recipient_info_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_key_recipient_info_encrypted_key(key_recipient_info_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_key_recipient_info_list_t **)&c_ctx = vscf_key_recipient_info_list_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_recipient_info_list_delete(*(vscf_key_recipient_info_list_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasItem (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_recipient_info_list_has_item(key_recipient_info_list_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1item (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

    const vscf_key_recipient_info_t */*5*/ proxyResult = vscf_key_recipient_info_list_item(key_recipient_info_list_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/KeyRecipientInfo");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class KeyRecipientInfo not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/KeyRecipientInfo;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class KeyRecipientInfo has no 'getInstance' method.");
    }
    vscf_key_recipient_info_shallow_copy((vscf_key_recipient_info_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasNext (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_recipient_info_list_has_next(key_recipient_info_list_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1next (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

    const vscf_key_recipient_info_list_t */*5*/ proxyResult = vscf_key_recipient_info_list_next(key_recipient_info_list_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/KeyRecipientInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class KeyRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/KeyRecipientInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class KeyRecipientInfoList has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1hasPrev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_recipient_info_list_has_prev(key_recipient_info_list_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1prev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

    const vscf_key_recipient_info_list_t */*5*/ proxyResult = vscf_key_recipient_info_list_prev(key_recipient_info_list_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/KeyRecipientInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class KeyRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/KeyRecipientInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class KeyRecipientInfoList has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyRecipientInfoList_1clear (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

    vscf_key_recipient_info_list_clear(key_recipient_info_list_ctx /*a1*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_password_recipient_info_t **)&c_ctx = vscf_password_recipient_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_password_recipient_info_delete(*(vscf_password_recipient_info_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgInfo_2_3B (JNIEnv *jenv, jobject jobj, jobject jkeyEncryptionAlgorithm, jbyteArray jencryptedKey) {
    // Wrap Java interfaces
    jclass key_encryption_algorithm_cls = (*jenv)->GetObjectClass(jenv, jkeyEncryptionAlgorithm);
    if (NULL == key_encryption_algorithm_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID key_encryption_algorithm_fidCtx = (*jenv)->GetFieldID(jenv, key_encryption_algorithm_cls, "cCtx", "J");
    if (NULL == key_encryption_algorithm_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong key_encryption_algorithm_c_ctx = (*jenv)->GetLongField(jenv, jkeyEncryptionAlgorithm, key_encryption_algorithm_fidCtx);
    vscf_impl_t */*6*/ key_encryption_algorithm = *(vscf_impl_t */*6*/*)&key_encryption_algorithm_c_ctx;

    // Wrap input data
    byte* encrypted_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jencryptedKey, NULL);
    vsc_data_t encrypted_key = vsc_data(encrypted_key_arr, (*jenv)->GetArrayLength(jenv, jencryptedKey));

    //Shallow copy
    vscf_impl_t */*6*/ key_encryption_algorithm_copy = vscf_impl_shallow_copy(key_encryption_algorithm);
    jlong proxyResult = (jlong) vscf_password_recipient_info_new_with_members(&key_encryption_algorithm_copy /*a5*/, encrypted_key /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jencryptedKey, (jbyte*) encrypted_key_arr, 0);

    return proxyResult;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1keyEncryptionAlgorithm (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_password_recipient_info_t /*2*/* password_recipient_info_ctx = *(vscf_password_recipient_info_t /*2*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_password_recipient_info_key_encryption_algorithm(password_recipient_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfo_1encryptedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_password_recipient_info_t /*2*/* password_recipient_info_ctx = *(vscf_password_recipient_info_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_password_recipient_info_encrypted_key(password_recipient_info_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_password_recipient_info_list_t **)&c_ctx = vscf_password_recipient_info_list_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_password_recipient_info_list_delete(*(vscf_password_recipient_info_list_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasItem (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_password_recipient_info_list_has_item(password_recipient_info_list_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1item (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

    const vscf_password_recipient_info_t */*5*/ proxyResult = vscf_password_recipient_info_list_item(password_recipient_info_list_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/PasswordRecipientInfo");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class PasswordRecipientInfo not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/PasswordRecipientInfo;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class PasswordRecipientInfo has no 'getInstance' method.");
    }
    vscf_password_recipient_info_shallow_copy((vscf_password_recipient_info_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasNext (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_password_recipient_info_list_has_next(password_recipient_info_list_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1next (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

    const vscf_password_recipient_info_list_t */*5*/ proxyResult = vscf_password_recipient_info_list_next(password_recipient_info_list_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/PasswordRecipientInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class PasswordRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/PasswordRecipientInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class PasswordRecipientInfoList has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1hasPrev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_password_recipient_info_list_has_prev(password_recipient_info_list_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1prev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

    const vscf_password_recipient_info_list_t */*5*/ proxyResult = vscf_password_recipient_info_list_prev(password_recipient_info_list_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/PasswordRecipientInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class PasswordRecipientInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/PasswordRecipientInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class PasswordRecipientInfoList has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_passwordRecipientInfoList_1clear (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

    vscf_password_recipient_info_list_clear(password_recipient_info_list_ctx /*a1*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createHashFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_hash_from_info(alg_info /*a6*/);
    jobject ret = wrapHash(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createMacFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_mac_from_info(alg_info /*a6*/);
    jobject ret = wrapMac(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createKdfFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_kdf_from_info(alg_info /*a6*/);
    jobject ret = wrapKdf(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createSaltedKdfFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_salted_kdf_from_info(alg_info /*a6*/);
    jobject ret = wrapSaltedKdf(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createCipherFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_cipher_from_info(alg_info /*a6*/);
    jobject ret = wrapCipher(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algFactory_1createPaddingFromInfo (JNIEnv *jenv, jobject jobj, jobject jalgInfo, jobject jrandom) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*)&random_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_padding_from_info(alg_info /*a6*/, random /*a6*/);
    jobject ret = wrapPadding(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAlgFactory_1createFromAlgId (JNIEnv *jenv, jobject jobj, jobject jalgId, jobject jrandom) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap enums
    jclass alg_id_cls = (*jenv)->GetObjectClass(jenv, jalgId);
    jmethodID alg_id_methodID = (*jenv)->GetMethodID(jenv, alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, alg_id_methodID);
    // Wrap Java interfaces
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*)&random_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_key_alg_factory_create_from_alg_id(alg_id /*a7*/, random /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapKeyAlg(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAlgFactory_1createFromKey (JNIEnv *jenv, jobject jobj, jobject jkey, jobject jrandom) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);// Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*)&random_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_key_alg_factory_create_from_key(key /*a6*/, random /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapKeyAlg(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAlgFactory_1createFromRawPublicKey (JNIEnv *jenv, jobject jobj, jobject jpublicKey, jobject jrandom) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);// Wrap Java interfaces
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*)&random_c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t */*5*/ public_key = *(vscf_raw_public_key_t */*5*/*) &public_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_key_alg_factory_create_from_raw_public_key(public_key /*a6*/, random /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapKeyAlg(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAlgFactory_1createFromRawPrivateKey (JNIEnv *jenv, jobject jobj, jobject jprivateKey, jobject jrandom) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);// Wrap Java interfaces
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*)&random_c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t */*5*/ private_key = *(vscf_raw_private_key_t */*5*/*) &private_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_key_alg_factory_create_from_raw_private_key(private_key /*a6*/, random /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapKeyAlg(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_ecies_t **)&c_ctx = vscf_ecies_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ecies_delete(*(vscf_ecies_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_ecies_release_random((vscf_ecies_t /*2*/ *) c_ctx);
    vscf_ecies_use_random((vscf_ecies_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setCipher (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jcipher) {
    jclass cipher_cls = (*jenv)->GetObjectClass(jenv, jcipher);
    if (NULL == cipher_cls) {
        VSCF_ASSERT("Class Cipher not found.");
    }
    jfieldID cipher_fidCtx = (*jenv)->GetFieldID(jenv, cipher_cls, "cCtx", "J");
    if (NULL == cipher_fidCtx) {
        VSCF_ASSERT("Class 'Cipher' has no field 'cCtx'.");
    }
    jlong cipher_c_ctx = (*jenv)->GetLongField(jenv, jcipher, cipher_fidCtx);
    vscf_impl_t */*6*/ cipher = *(vscf_impl_t */*6*/*) &cipher_c_ctx;

    vscf_ecies_release_cipher((vscf_ecies_t /*2*/ *) c_ctx);
    vscf_ecies_use_cipher((vscf_ecies_t /*2*/ *) c_ctx, cipher);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setMac (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmac) {
    jclass mac_cls = (*jenv)->GetObjectClass(jenv, jmac);
    if (NULL == mac_cls) {
        VSCF_ASSERT("Class Mac not found.");
    }
    jfieldID mac_fidCtx = (*jenv)->GetFieldID(jenv, mac_cls, "cCtx", "J");
    if (NULL == mac_fidCtx) {
        VSCF_ASSERT("Class 'Mac' has no field 'cCtx'.");
    }
    jlong mac_c_ctx = (*jenv)->GetLongField(jenv, jmac, mac_fidCtx);
    vscf_impl_t */*6*/ mac = *(vscf_impl_t */*6*/*) &mac_c_ctx;

    vscf_ecies_release_mac((vscf_ecies_t /*2*/ *) c_ctx);
    vscf_ecies_use_mac((vscf_ecies_t /*2*/ *) c_ctx, mac);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setKdf (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkdf) {
    jclass kdf_cls = (*jenv)->GetObjectClass(jenv, jkdf);
    if (NULL == kdf_cls) {
        VSCF_ASSERT("Class Kdf not found.");
    }
    jfieldID kdf_fidCtx = (*jenv)->GetFieldID(jenv, kdf_cls, "cCtx", "J");
    if (NULL == kdf_fidCtx) {
        VSCF_ASSERT("Class 'Kdf' has no field 'cCtx'.");
    }
    jlong kdf_c_ctx = (*jenv)->GetLongField(jenv, jkdf, kdf_fidCtx);
    vscf_impl_t */*6*/ kdf = *(vscf_impl_t */*6*/*) &kdf_c_ctx;

    vscf_ecies_release_kdf((vscf_ecies_t /*2*/ *) c_ctx);
    vscf_ecies_use_kdf((vscf_ecies_t /*2*/ *) c_ctx, kdf);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jephemeralKey) {
    jclass ephemeral_key_cls = (*jenv)->GetObjectClass(jenv, jephemeralKey);
    if (NULL == ephemeral_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID ephemeral_key_fidCtx = (*jenv)->GetFieldID(jenv, ephemeral_key_cls, "cCtx", "J");
    if (NULL == ephemeral_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong ephemeral_key_c_ctx = (*jenv)->GetLongField(jenv, jephemeralKey, ephemeral_key_fidCtx);
    vscf_impl_t */*6*/ ephemeral_key = *(vscf_impl_t */*6*/*) &ephemeral_key_c_ctx;

    vscf_ecies_release_ephemeral_key((vscf_ecies_t /*2*/ *) c_ctx);
    vscf_ecies_use_ephemeral_key((vscf_ecies_t /*2*/ *) c_ctx, ephemeral_key);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setKeyAlg (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkeyAlg) {
    // Cast class context
    vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_alg_cls = (*jenv)->GetObjectClass(jenv, jkeyAlg);
    if (NULL == key_alg_cls) {
        VSCF_ASSERT("Class KeyAlg not found.");
    }
    jfieldID key_alg_fidCtx = (*jenv)->GetFieldID(jenv, key_alg_cls, "cCtx", "J");
    if (NULL == key_alg_fidCtx) {
        VSCF_ASSERT("Class 'KeyAlg' has no field 'cCtx'.");
    }
    jlong key_alg_c_ctx = (*jenv)->GetLongField(jenv, jkeyAlg, key_alg_fidCtx);
    vscf_impl_t */*6*/ key_alg = *(vscf_impl_t */*6*/*)&key_alg_c_ctx;

    vscf_ecies_set_key_alg(ecies_ctx /*a1*/, key_alg /*a6*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1releaseKeyAlg (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

    vscf_ecies_release_key_alg(ecies_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

    vscf_status_t status = vscf_ecies_setup_defaults(ecies_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1setupDefaultsNoRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

    vscf_ecies_setup_defaults_no_random(ecies_ctx /*a1*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jint ret = (jint) vscf_ecies_encrypted_len(ecies_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jbyteArray jdata) {
    // Cast class context
    vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecies_encrypted_len((vscf_ecies_t /*2*/ *) c_ctx /*3*/, public_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_ecies_encrypt(ecies_ctx /*a1*/, public_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_ecies_decrypted_len(ecies_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecies_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jbyteArray jdata) {
    // Cast class context
    vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecies_decrypted_len((vscf_ecies_t /*2*/ *) c_ctx /*3*/, private_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_ecies_decrypt(ecies_ctx /*a1*/, private_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_recipient_cipher_t **)&c_ctx = vscf_recipient_cipher_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_recipient_cipher_delete(*(vscf_recipient_cipher_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_recipient_cipher_release_random((vscf_recipient_cipher_t /*2*/ *) c_ctx);
    vscf_recipient_cipher_use_random((vscf_recipient_cipher_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setEncryptionCipher (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jencryptionCipher) {
    jclass encryption_cipher_cls = (*jenv)->GetObjectClass(jenv, jencryptionCipher);
    if (NULL == encryption_cipher_cls) {
        VSCF_ASSERT("Class Cipher not found.");
    }
    jfieldID encryption_cipher_fidCtx = (*jenv)->GetFieldID(jenv, encryption_cipher_cls, "cCtx", "J");
    if (NULL == encryption_cipher_fidCtx) {
        VSCF_ASSERT("Class 'Cipher' has no field 'cCtx'.");
    }
    jlong encryption_cipher_c_ctx = (*jenv)->GetLongField(jenv, jencryptionCipher, encryption_cipher_fidCtx);
    vscf_impl_t */*6*/ encryption_cipher = *(vscf_impl_t */*6*/*) &encryption_cipher_c_ctx;

    vscf_recipient_cipher_release_encryption_cipher((vscf_recipient_cipher_t /*2*/ *) c_ctx);
    vscf_recipient_cipher_use_encryption_cipher((vscf_recipient_cipher_t /*2*/ *) c_ctx, encryption_cipher);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setEncryptionPadding (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jencryptionPadding) {
    jclass encryption_padding_cls = (*jenv)->GetObjectClass(jenv, jencryptionPadding);
    if (NULL == encryption_padding_cls) {
        VSCF_ASSERT("Class Padding not found.");
    }
    jfieldID encryption_padding_fidCtx = (*jenv)->GetFieldID(jenv, encryption_padding_cls, "cCtx", "J");
    if (NULL == encryption_padding_fidCtx) {
        VSCF_ASSERT("Class 'Padding' has no field 'cCtx'.");
    }
    jlong encryption_padding_c_ctx = (*jenv)->GetLongField(jenv, jencryptionPadding, encryption_padding_fidCtx);
    vscf_impl_t */*6*/ encryption_padding = *(vscf_impl_t */*6*/*) &encryption_padding_c_ctx;

    vscf_recipient_cipher_release_encryption_padding((vscf_recipient_cipher_t /*2*/ *) c_ctx);
    vscf_recipient_cipher_use_encryption_padding((vscf_recipient_cipher_t /*2*/ *) c_ctx, encryption_padding);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setPaddingParams (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpaddingParams) {
    jclass padding_params_cls = (*jenv)->GetObjectClass(jenv, jpaddingParams);
    if (NULL == padding_params_cls) {
        VSCF_ASSERT("Class PaddingParams not found.");
    }
    jfieldID padding_params_fidCtx = (*jenv)->GetFieldID(jenv, padding_params_cls, "cCtx", "J");
    if (NULL == padding_params_fidCtx) {
        VSCF_ASSERT("Class 'PaddingParams' has no field 'cCtx'.");
    }
    jlong padding_params_c_ctx = (*jenv)->GetLongField(jenv, jpaddingParams, padding_params_fidCtx);
    vscf_padding_params_t */*5*/ padding_params = *(vscf_padding_params_t */*5*/*) &padding_params_c_ctx;

    vscf_recipient_cipher_release_padding_params((vscf_recipient_cipher_t /*2*/ *) c_ctx);
    vscf_recipient_cipher_use_padding_params((vscf_recipient_cipher_t /*2*/ *) c_ctx, padding_params);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1setSignerHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jsignerHash) {
    jclass signer_hash_cls = (*jenv)->GetObjectClass(jenv, jsignerHash);
    if (NULL == signer_hash_cls) {
        VSCF_ASSERT("Class Hash not found.");
    }
    jfieldID signer_hash_fidCtx = (*jenv)->GetFieldID(jenv, signer_hash_cls, "cCtx", "J");
    if (NULL == signer_hash_fidCtx) {
        VSCF_ASSERT("Class 'Hash' has no field 'cCtx'.");
    }
    jlong signer_hash_c_ctx = (*jenv)->GetLongField(jenv, jsignerHash, signer_hash_fidCtx);
    vscf_impl_t */*6*/ signer_hash = *(vscf_impl_t */*6*/*) &signer_hash_c_ctx;

    vscf_recipient_cipher_release_signer_hash((vscf_recipient_cipher_t /*2*/ *) c_ctx);
    vscf_recipient_cipher_use_signer_hash((vscf_recipient_cipher_t /*2*/ *) c_ctx, signer_hash);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1hasKeyRecipient (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jrecipientId) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
    vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

    jboolean ret = (jboolean) vscf_recipient_cipher_has_key_recipient(recipient_cipher_ctx /*a1*/, recipient_id /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1addKeyRecipient (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jrecipientId, jobject jpublicKey) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
    vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

    vscf_recipient_cipher_add_key_recipient(recipient_cipher_ctx /*a1*/, recipient_id /*a3*/, public_key /*a6*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1clearRecipients (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    vscf_recipient_cipher_clear_recipients(recipient_cipher_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1addSigner (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsignerId, jobject jprivateKey) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* signer_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignerId, NULL);
    vsc_data_t signer_id = vsc_data(signer_id_arr, (*jenv)->GetArrayLength(jenv, jsignerId));

    vscf_status_t status = vscf_recipient_cipher_add_signer(recipient_cipher_ctx /*a1*/, signer_id /*a3*/, private_key /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsignerId, (jbyte*) signer_id_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1clearSigners (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    vscf_recipient_cipher_clear_signers(recipient_cipher_ctx /*a1*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1customParams (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    const vscf_message_info_custom_params_t */*5*/ proxyResult = vscf_recipient_cipher_custom_params(recipient_cipher_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/MessageInfoCustomParams");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class MessageInfoCustomParams not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/MessageInfoCustomParams;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class MessageInfoCustomParams has no 'getInstance' method.");
    }
    vscf_message_info_custom_params_shallow_copy((vscf_message_info_custom_params_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1startEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    vscf_status_t status = vscf_recipient_cipher_start_encryption(recipient_cipher_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1startSignedEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataSize) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    vscf_status_t status = vscf_recipient_cipher_start_signed_encryption(recipient_cipher_ctx /*a1*/, jdataSize /*a9*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1messageInfoLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_recipient_cipher_message_info_len(recipient_cipher_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1packMessageInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *message_info = vsc_buffer_new_with_capacity(vscf_recipient_cipher_message_info_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/));

    vscf_recipient_cipher_pack_message_info(recipient_cipher_ctx /*a1*/, message_info /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(message_info));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(message_info), (jbyte*) vsc_buffer_bytes(message_info));
    // Free resources
    vsc_buffer_delete(message_info);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1encryptionOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_recipient_cipher_encryption_out_len(recipient_cipher_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1processEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_encryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_recipient_cipher_process_encryption(recipient_cipher_ctx /*a1*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1finishEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_encryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/, 0/*b*/));

    vscf_status_t status = vscf_recipient_cipher_finish_encryption(recipient_cipher_ctx /*a1*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1startDecryptionWithKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jrecipientId, jobject jprivateKey, jbyteArray jmessageInfo) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
    vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

    byte* message_info_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmessageInfo, NULL);
    vsc_data_t message_info = vsc_data(message_info_arr, (*jenv)->GetArrayLength(jenv, jmessageInfo));

    vscf_status_t status = vscf_recipient_cipher_start_decryption_with_key(recipient_cipher_ctx /*a1*/, recipient_id /*a3*/, private_key /*a6*/, message_info /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jmessageInfo, (jbyte*) message_info_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1startVerifiedDecryptionWithKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jrecipientId, jobject jprivateKey, jbyteArray jmessageInfo, jbyteArray jmessageInfoFooter) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
    vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

    byte* message_info_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmessageInfo, NULL);
    vsc_data_t message_info = vsc_data(message_info_arr, (*jenv)->GetArrayLength(jenv, jmessageInfo));

    byte* message_info_footer_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmessageInfoFooter, NULL);
    vsc_data_t message_info_footer = vsc_data(message_info_footer_arr, (*jenv)->GetArrayLength(jenv, jmessageInfoFooter));

    vscf_status_t status = vscf_recipient_cipher_start_verified_decryption_with_key(recipient_cipher_ctx /*a1*/, recipient_id /*a3*/, private_key /*a6*/, message_info /*a3*/, message_info_footer /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jmessageInfo, (jbyte*) message_info_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jmessageInfoFooter, (jbyte*) message_info_footer_arr, 0);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1decryptionOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_recipient_cipher_decryption_out_len(recipient_cipher_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1processDecryption (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_recipient_cipher_process_decryption(recipient_cipher_ctx /*a1*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1finishDecryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/, 0/*b*/));

    vscf_status_t status = vscf_recipient_cipher_finish_decryption(recipient_cipher_ctx /*a1*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1isDataSigned (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_recipient_cipher_is_data_signed(recipient_cipher_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1signerInfos (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    const vscf_signer_info_list_t */*5*/ proxyResult = vscf_recipient_cipher_signer_infos(recipient_cipher_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/SignerInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class SignerInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/SignerInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class SignerInfoList has no 'getInstance' method.");
    }
    vscf_signer_info_list_shallow_copy((vscf_signer_info_list_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1verifySignerInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jsignerInfo, jobject jpublicKey) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;
    // Wrap Java classes
    jclass signer_info_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/SignerInfo");
    if (NULL == signer_info_cls) {
        VSCF_ASSERT("Class SignerInfo not found.");
    }
    jfieldID signer_info_fidCtx = (*jenv)->GetFieldID(jenv, signer_info_cls, "cCtx", "J");
    if (NULL == signer_info_fidCtx) {
        VSCF_ASSERT("Class 'SignerInfo' has no field 'cCtx'.");
    }
    jlong signer_info_c_ctx = (*jenv)->GetLongField(jenv, jsignerInfo, signer_info_fidCtx);
    vscf_signer_info_t */*5*/ signer_info = *(vscf_signer_info_t */*5*/*) &signer_info_c_ctx;

    jboolean ret = (jboolean) vscf_recipient_cipher_verify_signer_info(recipient_cipher_ctx /*a1*/, signer_info /*a6*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1messageInfoFooterLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_recipient_cipher_message_info_footer_len(recipient_cipher_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_recipientCipher_1packMessageInfoFooter (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_message_info_footer_len((vscf_recipient_cipher_t /*2*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_recipient_cipher_pack_message_info_footer(recipient_cipher_ctx /*a1*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_message_info_custom_params_t **)&c_ctx = vscf_message_info_custom_params_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_custom_params_delete(*(vscf_message_info_custom_params_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addInt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey, jint jvalue) {
    // Cast class context
    vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    vscf_message_info_custom_params_add_int(message_info_custom_params_ctx /*a1*/, key /*a3*/, jvalue /*a9*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addString (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey, jbyteArray jvalue) {
    // Cast class context
    vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
    vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

    vscf_message_info_custom_params_add_string(message_info_custom_params_ctx /*a1*/, key /*a3*/, value /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1addData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey, jbyteArray jvalue) {
    // Cast class context
    vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
    vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

    vscf_message_info_custom_params_add_data(message_info_custom_params_ctx /*a1*/, key /*a3*/, value /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1clear (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

    vscf_message_info_custom_params_clear(message_info_custom_params_ctx /*a1*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findInt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    jint ret = (jint) vscf_message_info_custom_params_find_int(message_info_custom_params_ctx /*a1*/, key /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return 0;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findString (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    const vsc_data_t /*3*/ proxyResult = vscf_message_info_custom_params_find_string(message_info_custom_params_ctx /*a1*/, key /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1findData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    const vsc_data_t /*3*/ proxyResult = vscf_message_info_custom_params_find_data(message_info_custom_params_ctx /*a1*/, key /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoCustomParams_1hasParams (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_message_info_custom_params_has_params(message_info_custom_params_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_key_provider_t **)&c_ctx = vscf_key_provider_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_provider_delete(*(vscf_key_provider_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_key_provider_release_random((vscf_key_provider_t /*2*/ *) c_ctx);
    vscf_key_provider_use_random((vscf_key_provider_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1setRsaParams (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jbitlen) {
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

    vscf_key_provider_set_rsa_params(key_provider_ctx /*a1*/, jbitlen /*a9*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generatePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgId) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

    // Wrap enums
    jclass alg_id_cls = (*jenv)->GetObjectClass(jenv, jalgId);
    jmethodID alg_id_methodID = (*jenv)->GetMethodID(jenv, alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, alg_id_methodID);

    const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_private_key(key_provider_ctx /*a1*/, alg_id /*a7*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generatePostQuantumPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_post_quantum_private_key(key_provider_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generateCompoundPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jcipherAlgId, jobject jsignerAlgId) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

    // Wrap enums
    jclass cipher_alg_id_cls = (*jenv)->GetObjectClass(jenv, jcipherAlgId);
    jmethodID cipher_alg_id_methodID = (*jenv)->GetMethodID(jenv, cipher_alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ cipher_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jcipherAlgId, cipher_alg_id_methodID);

    jclass signer_alg_id_cls = (*jenv)->GetObjectClass(jenv, jsignerAlgId);
    jmethodID signer_alg_id_methodID = (*jenv)->GetMethodID(jenv, signer_alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ signer_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jsignerAlgId, signer_alg_id_methodID);

    const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_compound_private_key(key_provider_ctx /*a1*/, cipher_alg_id /*a7*/, signer_alg_id /*a7*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generateChainedPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jl1AlgId, jobject jl2AlgId) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

    // Wrap enums
    jclass l1_alg_id_cls = (*jenv)->GetObjectClass(jenv, jl1AlgId);
    jmethodID l1_alg_id_methodID = (*jenv)->GetMethodID(jenv, l1_alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ l1_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jl1AlgId, l1_alg_id_methodID);

    jclass l2_alg_id_cls = (*jenv)->GetObjectClass(jenv, jl2AlgId);
    jmethodID l2_alg_id_methodID = (*jenv)->GetMethodID(jenv, l2_alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ l2_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jl2AlgId, l2_alg_id_methodID);

    const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_chained_private_key(key_provider_ctx /*a1*/, l1_alg_id /*a7*/, l2_alg_id /*a7*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1generateCompoundChainedPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jcipherL1AlgId, jobject jcipherL2AlgId, jobject jsignerL1AlgId, jobject jsignerL2AlgId) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

    // Wrap enums
    jclass cipher_l1_alg_id_cls = (*jenv)->GetObjectClass(jenv, jcipherL1AlgId);
    jmethodID cipher_l1_alg_id_methodID = (*jenv)->GetMethodID(jenv, cipher_l1_alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ cipher_l1_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jcipherL1AlgId, cipher_l1_alg_id_methodID);

    jclass cipher_l2_alg_id_cls = (*jenv)->GetObjectClass(jenv, jcipherL2AlgId);
    jmethodID cipher_l2_alg_id_methodID = (*jenv)->GetMethodID(jenv, cipher_l2_alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ cipher_l2_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jcipherL2AlgId, cipher_l2_alg_id_methodID);

    jclass signer_l1_alg_id_cls = (*jenv)->GetObjectClass(jenv, jsignerL1AlgId);
    jmethodID signer_l1_alg_id_methodID = (*jenv)->GetMethodID(jenv, signer_l1_alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ signer_l1_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jsignerL1AlgId, signer_l1_alg_id_methodID);

    jclass signer_l2_alg_id_cls = (*jenv)->GetObjectClass(jenv, jsignerL2AlgId);
    jmethodID signer_l2_alg_id_methodID = (*jenv)->GetMethodID(jenv, signer_l2_alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ signer_l2_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jsignerL2AlgId, signer_l2_alg_id_methodID);

    const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_compound_chained_private_key(key_provider_ctx /*a1*/, cipher_l1_alg_id /*a7*/, cipher_l2_alg_id /*a7*/, signer_l1_alg_id /*a7*/, signer_l2_alg_id /*a7*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkeyData) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* key_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkeyData, NULL);
    vsc_data_t key_data = vsc_data(key_data_arr, (*jenv)->GetArrayLength(jenv, jkeyData));

    const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_import_private_key(key_provider_ctx /*a1*/, key_data /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkeyData, (jbyte*) key_data_arr, 0);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkeyData) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* key_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkeyData, NULL);
    vsc_data_t key_data = vsc_data(key_data_arr, (*jenv)->GetArrayLength(jenv, jkeyData));

    const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_import_public_key(key_provider_ctx /*a1*/, key_data /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkeyData, (jbyte*) key_data_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1exportedPublicKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jint ret = (jint) vscf_key_provider_exported_public_key_len(key_provider_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_key_provider_exported_public_key_len((vscf_key_provider_t /*2*/ *) c_ctx /*3*/, public_key/*a*/));

    vscf_status_t status = vscf_key_provider_export_public_key(key_provider_ctx /*a1*/, public_key /*a6*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1exportedPrivateKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_key_provider_exported_private_key_len(key_provider_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyProvider_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_key_provider_exported_private_key_len((vscf_key_provider_t /*2*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_key_provider_export_private_key(key_provider_ctx /*a1*/, private_key /*a6*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_signer_t **)&c_ctx = vscf_signer_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_signer_delete(*(vscf_signer_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        VSCF_ASSERT("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        VSCF_ASSERT("Class 'Hash' has no field 'cCtx'.");
    }
    jlong hash_c_ctx = (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);
    vscf_impl_t */*6*/ hash = *(vscf_impl_t */*6*/*) &hash_c_ctx;

    vscf_signer_release_hash((vscf_signer_t /*2*/ *) c_ctx);
    vscf_signer_use_hash((vscf_signer_t /*2*/ *) c_ctx, hash);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_signer_release_random((vscf_signer_t /*2*/ *) c_ctx);
    vscf_signer_use_random((vscf_signer_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_t /*2*/* signer_ctx = *(vscf_signer_t /*2*/**) &c_ctx;

    vscf_signer_reset(signer_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1appendData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_signer_t /*2*/* signer_ctx = *(vscf_signer_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vscf_signer_append_data(signer_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_signer_t /*2*/* signer_ctx = *(vscf_signer_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_signer_signature_len(signer_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signer_1sign (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_signer_t /*2*/* signer_ctx = *(vscf_signer_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_signer_signature_len((vscf_signer_t /*2*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_signer_sign(signer_ctx /*a1*/, private_key /*a6*/, signature /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), (jbyte*) vsc_buffer_bytes(signature));
    // Free resources
    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_verifier_t **)&c_ctx = vscf_verifier_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_verifier_delete(*(vscf_verifier_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsignature) {
    // Cast class context
    vscf_verifier_t /*2*/* verifier_ctx = *(vscf_verifier_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
    vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

    vscf_status_t status = vscf_verifier_reset(verifier_ctx /*a1*/, signature /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1appendData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_verifier_t /*2*/* verifier_ctx = *(vscf_verifier_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vscf_verifier_append_data(verifier_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_verifier_1verify (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_verifier_t /*2*/* verifier_ctx = *(vscf_verifier_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_verifier_verify(verifier_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_brainkey_client_t **)&c_ctx = vscf_brainkey_client_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_brainkey_client_delete(*(vscf_brainkey_client_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_brainkey_client_release_random((vscf_brainkey_client_t /*2*/ *) c_ctx);
    vscf_brainkey_client_use_random((vscf_brainkey_client_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1setOperationRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject joperationRandom) {
    jclass operation_random_cls = (*jenv)->GetObjectClass(jenv, joperationRandom);
    if (NULL == operation_random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID operation_random_fidCtx = (*jenv)->GetFieldID(jenv, operation_random_cls, "cCtx", "J");
    if (NULL == operation_random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong operation_random_c_ctx = (*jenv)->GetLongField(jenv, joperationRandom, operation_random_fidCtx);
    vscf_impl_t */*6*/ operation_random = *(vscf_impl_t */*6*/*) &operation_random_c_ctx;

    vscf_brainkey_client_release_operation_random((vscf_brainkey_client_t /*2*/ *) c_ctx);
    vscf_brainkey_client_use_operation_random((vscf_brainkey_client_t /*2*/ *) c_ctx, operation_random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_brainkey_client_t /*2*/* brainkey_client_ctx = *(vscf_brainkey_client_t /*2*/**) &c_ctx;

    vscf_status_t status = vscf_brainkey_client_setup_defaults(brainkey_client_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1blind (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword) {
    // Cast class context
    vscf_brainkey_client_t /*2*/* brainkey_client_ctx = *(vscf_brainkey_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
    vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vscf_brainkey_client_MPI_LEN);

    vsc_buffer_t *blinded_point = vsc_buffer_new_with_capacity(vscf_brainkey_client_POINT_LEN);

    vscf_status_t status = vscf_brainkey_client_blind(brainkey_client_ctx /*a1*/, password /*a3*/, deblind_factor /*a3*/, blinded_point /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/BrainkeyClientBlindResult");
    if (NULL == cls) {
        VSCF_ASSERT("Class BrainkeyClientBlindResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidDeblindFactor = (*jenv)->GetFieldID(jenv, cls, "deblindFactor", "[B");
    jbyteArray jDeblindFactorArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(deblind_factor));
    (*jenv)->SetByteArrayRegion (jenv, jDeblindFactorArr, 0, vsc_buffer_len(deblind_factor), (jbyte*) vsc_buffer_bytes(deblind_factor));
    (*jenv)->SetObjectField(jenv, newObj, fidDeblindFactor, jDeblindFactorArr);
    jfieldID fidBlindedPoint = (*jenv)->GetFieldID(jenv, cls, "blindedPoint", "[B");
    jbyteArray jBlindedPointArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(blinded_point));
    (*jenv)->SetByteArrayRegion (jenv, jBlindedPointArr, 0, vsc_buffer_len(blinded_point), (jbyte*) vsc_buffer_bytes(blinded_point));
    (*jenv)->SetObjectField(jenv, newObj, fidBlindedPoint, jBlindedPointArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

    vsc_buffer_delete(deblind_factor);

    vsc_buffer_delete(blinded_point);

    return newObj;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyClient_1deblind (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword, jbyteArray jhardenedPoint, jbyteArray jdeblindFactor, jbyteArray jkeyName) {
    // Cast class context
    vscf_brainkey_client_t /*2*/* brainkey_client_ctx = *(vscf_brainkey_client_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
    vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

    byte* hardened_point_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jhardenedPoint, NULL);
    vsc_data_t hardened_point = vsc_data(hardened_point_arr, (*jenv)->GetArrayLength(jenv, jhardenedPoint));

    byte* deblind_factor_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdeblindFactor, NULL);
    vsc_data_t deblind_factor = vsc_data(deblind_factor_arr, (*jenv)->GetArrayLength(jenv, jdeblindFactor));

    byte* key_name_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkeyName, NULL);
    vsc_data_t key_name = vsc_data(key_name_arr, (*jenv)->GetArrayLength(jenv, jkeyName));

    vsc_buffer_t *seed = vsc_buffer_new_with_capacity(vscf_brainkey_client_POINT_LEN);

    vscf_status_t status = vscf_brainkey_client_deblind(brainkey_client_ctx /*a1*/, password /*a3*/, hardened_point /*a3*/, deblind_factor /*a3*/, key_name /*a3*/, seed /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(seed));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(seed), (jbyte*) vsc_buffer_bytes(seed));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jhardenedPoint, (jbyte*) hardened_point_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jdeblindFactor, (jbyte*) deblind_factor_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jkeyName, (jbyte*) key_name_arr, 0);

    vsc_buffer_delete(seed);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_brainkey_server_t **)&c_ctx = vscf_brainkey_server_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_brainkey_server_delete(*(vscf_brainkey_server_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_brainkey_server_release_random((vscf_brainkey_server_t /*2*/ *) c_ctx);
    vscf_brainkey_server_use_random((vscf_brainkey_server_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1setOperationRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject joperationRandom) {
    jclass operation_random_cls = (*jenv)->GetObjectClass(jenv, joperationRandom);
    if (NULL == operation_random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID operation_random_fidCtx = (*jenv)->GetFieldID(jenv, operation_random_cls, "cCtx", "J");
    if (NULL == operation_random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong operation_random_c_ctx = (*jenv)->GetLongField(jenv, joperationRandom, operation_random_fidCtx);
    vscf_impl_t */*6*/ operation_random = *(vscf_impl_t */*6*/*) &operation_random_c_ctx;

    vscf_brainkey_server_release_operation_random((vscf_brainkey_server_t /*2*/ *) c_ctx);
    vscf_brainkey_server_use_operation_random((vscf_brainkey_server_t /*2*/ *) c_ctx, operation_random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_brainkey_server_t /*2*/* brainkey_server_ctx = *(vscf_brainkey_server_t /*2*/**) &c_ctx;

    vscf_status_t status = vscf_brainkey_server_setup_defaults(brainkey_server_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1generateIdentitySecret (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_brainkey_server_t /*2*/* brainkey_server_ctx = *(vscf_brainkey_server_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *identity_secret = vsc_buffer_new_with_capacity(vscf_brainkey_server_MPI_LEN);

    vscf_status_t status = vscf_brainkey_server_generate_identity_secret(brainkey_server_ctx /*a1*/, identity_secret /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(identity_secret));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(identity_secret), (jbyte*) vsc_buffer_bytes(identity_secret));
    // Free resources
    vsc_buffer_delete(identity_secret);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_brainkeyServer_1harden (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jidentitySecret, jbyteArray jblindedPoint) {
    // Cast class context
    vscf_brainkey_server_t /*2*/* brainkey_server_ctx = *(vscf_brainkey_server_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* identity_secret_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jidentitySecret, NULL);
    vsc_data_t identity_secret = vsc_data(identity_secret_arr, (*jenv)->GetArrayLength(jenv, jidentitySecret));

    byte* blinded_point_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jblindedPoint, NULL);
    vsc_data_t blinded_point = vsc_data(blinded_point_arr, (*jenv)->GetArrayLength(jenv, jblindedPoint));

    vsc_buffer_t *hardened_point = vsc_buffer_new_with_capacity(vscf_brainkey_server_POINT_LEN);

    vscf_status_t status = vscf_brainkey_server_harden(brainkey_server_ctx /*a1*/, identity_secret /*a3*/, blinded_point /*a3*/, hardened_point /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(hardened_point));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(hardened_point), (jbyte*) vsc_buffer_bytes(hardened_point));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jidentitySecret, (jbyte*) identity_secret_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jblindedPoint, (jbyte*) blinded_point_arr, 0);

    vsc_buffer_delete(hardened_point);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_group_session_message_t **)&c_ctx = vscf_group_session_message_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_group_session_message_delete(*(vscf_group_session_message_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1getType (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_message_t /*2*/* group_session_message_ctx = *(vscf_group_session_message_t /*2*/**) &c_ctx;

    const vscf_group_msg_type_t proxyResult = vscf_group_session_message_get_type(group_session_message_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/GroupMsgType");
    if (NULL == cls) {
        VSCF_ASSERT("Enum GroupMsgType not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/GroupMsgType;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum GroupMsgType has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1getSessionId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_message_t /*2*/* group_session_message_ctx = *(vscf_group_session_message_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_group_session_message_get_session_id(group_session_message_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1getEpoch (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_message_t /*2*/* group_session_message_ctx = *(vscf_group_session_message_t /*2*/**) &c_ctx;

    jlong ret = (jlong) vscf_group_session_message_get_epoch(group_session_message_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1serializeLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_message_t /*2*/* group_session_message_ctx = *(vscf_group_session_message_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_group_session_message_serialize_len(group_session_message_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_message_t /*2*/* group_session_message_ctx = *(vscf_group_session_message_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *output = vsc_buffer_new_with_capacity(vscf_group_session_message_serialize_len((vscf_group_session_message_t /*2*/ *) c_ctx /*3*/));

    vscf_group_session_message_serialize(group_session_message_ctx /*a1*/, output /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(output));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(output), (jbyte*) vsc_buffer_bytes(output));
    // Free resources
    vsc_buffer_delete(output);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionMessage_1deserialize (JNIEnv *jenv, jobject jobj, jbyteArray jinput) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Wrap input data
    byte* input_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinput, NULL);
    vsc_data_t input = vsc_data(input_arr, (*jenv)->GetArrayLength(jenv, jinput));

    const vscf_group_session_message_t */*5*/ proxyResult = vscf_group_session_message_deserialize(input /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/GroupSessionMessage");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class GroupSessionMessage not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/GroupSessionMessage;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class GroupSessionMessage has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jinput, (jbyte*) input_arr, 0);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_group_session_ticket_t **)&c_ctx = vscf_group_session_ticket_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_group_session_ticket_delete(*(vscf_group_session_ticket_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1setRng (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrng) {
    jclass rng_cls = (*jenv)->GetObjectClass(jenv, jrng);
    if (NULL == rng_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID rng_fidCtx = (*jenv)->GetFieldID(jenv, rng_cls, "cCtx", "J");
    if (NULL == rng_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong rng_c_ctx = (*jenv)->GetLongField(jenv, jrng, rng_fidCtx);
    vscf_impl_t */*6*/ rng = *(vscf_impl_t */*6*/*) &rng_c_ctx;

    vscf_group_session_ticket_release_rng((vscf_group_session_ticket_t /*2*/ *) c_ctx);
    vscf_group_session_ticket_use_rng((vscf_group_session_ticket_t /*2*/ *) c_ctx, rng);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_ticket_t /*2*/* group_session_ticket_ctx = *(vscf_group_session_ticket_t /*2*/**) &c_ctx;

    vscf_status_t status = vscf_group_session_ticket_setup_defaults(group_session_ticket_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1setupTicketAsNew (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsessionId) {
    // Cast class context
    vscf_group_session_ticket_t /*2*/* group_session_ticket_ctx = *(vscf_group_session_ticket_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* session_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsessionId, NULL);
    vsc_data_t session_id = vsc_data(session_id_arr, (*jenv)->GetArrayLength(jenv, jsessionId));

    vscf_status_t status = vscf_group_session_ticket_setup_ticket_as_new(group_session_ticket_ctx /*a1*/, session_id /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsessionId, (jbyte*) session_id_arr, 0);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSessionTicket_1getTicketMessage (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_ticket_t /*2*/* group_session_ticket_ctx = *(vscf_group_session_ticket_t /*2*/**) &c_ctx;

    const vscf_group_session_message_t */*5*/ proxyResult = vscf_group_session_ticket_get_ticket_message(group_session_ticket_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/GroupSessionMessage");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class GroupSessionMessage not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/GroupSessionMessage;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class GroupSessionMessage has no 'getInstance' method.");
    }
    vscf_group_session_message_shallow_copy((vscf_group_session_message_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_group_session_t **)&c_ctx = vscf_group_session_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_group_session_delete(*(vscf_group_session_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1setRng (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrng) {
    jclass rng_cls = (*jenv)->GetObjectClass(jenv, jrng);
    if (NULL == rng_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID rng_fidCtx = (*jenv)->GetFieldID(jenv, rng_cls, "cCtx", "J");
    if (NULL == rng_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong rng_c_ctx = (*jenv)->GetLongField(jenv, jrng, rng_fidCtx);
    vscf_impl_t */*6*/ rng = *(vscf_impl_t */*6*/*) &rng_c_ctx;

    vscf_group_session_release_rng((vscf_group_session_t /*2*/ *) c_ctx);
    vscf_group_session_use_rng((vscf_group_session_t /*2*/ *) c_ctx, rng);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1getCurrentEpoch (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

    jlong ret = (jlong) vscf_group_session_get_current_epoch(group_session_ctx /*a1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

    vscf_status_t status = vscf_group_session_setup_defaults(group_session_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1getSessionId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_group_session_get_session_id(group_session_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1addEpoch (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage) {
    // Cast class context
    vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/GroupSessionMessage");
    if (NULL == message_cls) {
        VSCF_ASSERT("Class GroupSessionMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCF_ASSERT("Class 'GroupSessionMessage' has no field 'cCtx'.");
    }
    jlong message_c_ctx = (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);
    vscf_group_session_message_t */*5*/ message = *(vscf_group_session_message_t */*5*/*) &message_c_ctx;

    vscf_status_t status = vscf_group_session_add_epoch(group_session_ctx /*a1*/, message /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jplainText, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* plain_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jplainText, NULL);
    vsc_data_t plain_text = vsc_data(plain_text_arr, (*jenv)->GetArrayLength(jenv, jplainText));

    const vscf_group_session_message_t */*5*/ proxyResult = vscf_group_session_encrypt(group_session_ctx /*a1*/, plain_text /*a3*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/GroupSessionMessage");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class GroupSessionMessage not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/GroupSessionMessage;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class GroupSessionMessage has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jplainText, (jbyte*) plain_text_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1decryptLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage) {
    // Cast class context
    vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/GroupSessionMessage");
    if (NULL == message_cls) {
        VSCF_ASSERT("Class GroupSessionMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCF_ASSERT("Class 'GroupSessionMessage' has no field 'cCtx'.");
    }
    jlong message_c_ctx = (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);
    vscf_group_session_message_t */*5*/ message = *(vscf_group_session_message_t */*5*/*) &message_c_ctx;

    jint ret = (jint) vscf_group_session_decrypt_len(group_session_ctx /*a1*/, message /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessage, jobject jpublicKey) {
    // Cast class context
    vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;
    // Wrap Java classes
    jclass message_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/GroupSessionMessage");
    if (NULL == message_cls) {
        VSCF_ASSERT("Class GroupSessionMessage not found.");
    }
    jfieldID message_fidCtx = (*jenv)->GetFieldID(jenv, message_cls, "cCtx", "J");
    if (NULL == message_fidCtx) {
        VSCF_ASSERT("Class 'GroupSessionMessage' has no field 'cCtx'.");
    }
    jlong message_c_ctx = (*jenv)->GetLongField(jenv, jmessage, message_fidCtx);
    vscf_group_session_message_t */*5*/ message = *(vscf_group_session_message_t */*5*/*) &message_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vscf_group_session_decrypt_len((vscf_group_session_t /*2*/ *) c_ctx /*3*/, message/*a*/));

    vscf_status_t status = vscf_group_session_decrypt(group_session_ctx /*a1*/, message /*a6*/, public_key /*a6*/, plain_text /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), (jbyte*) vsc_buffer_bytes(plain_text));
    // Free resources
    vsc_buffer_delete(plain_text);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_groupSession_1createGroupTicket (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

    const vscf_group_session_ticket_t */*5*/ proxyResult = vscf_group_session_create_group_ticket(group_session_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/GroupSessionTicket");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class GroupSessionTicket not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/GroupSessionTicket;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class GroupSessionTicket has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_message_info_editor_t **)&c_ctx = vscf_message_info_editor_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_editor_delete(*(vscf_message_info_editor_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_message_info_editor_release_random((vscf_message_info_editor_t /*2*/ *) c_ctx);
    vscf_message_info_editor_use_random((vscf_message_info_editor_t /*2*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

    vscf_status_t status = vscf_message_info_editor_setup_defaults(message_info_editor_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1unpack (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jmessageInfoData) {
    // Cast class context
    vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* message_info_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmessageInfoData, NULL);
    vsc_data_t message_info_data = vsc_data(message_info_data_arr, (*jenv)->GetArrayLength(jenv, jmessageInfoData));

    vscf_status_t status = vscf_message_info_editor_unpack(message_info_editor_ctx /*a1*/, message_info_data /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jmessageInfoData, (jbyte*) message_info_data_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1unlock (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jownerRecipientId, jobject jownerPrivateKey) {
    // Cast class context
    vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass owner_private_key_cls = (*jenv)->GetObjectClass(jenv, jownerPrivateKey);
    if (NULL == owner_private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID owner_private_key_fidCtx = (*jenv)->GetFieldID(jenv, owner_private_key_cls, "cCtx", "J");
    if (NULL == owner_private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong owner_private_key_c_ctx = (*jenv)->GetLongField(jenv, jownerPrivateKey, owner_private_key_fidCtx);
    vscf_impl_t */*6*/ owner_private_key = *(vscf_impl_t */*6*/*)&owner_private_key_c_ctx;

    // Wrap input data
    byte* owner_recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jownerRecipientId, NULL);
    vsc_data_t owner_recipient_id = vsc_data(owner_recipient_id_arr, (*jenv)->GetArrayLength(jenv, jownerRecipientId));

    vscf_status_t status = vscf_message_info_editor_unlock(message_info_editor_ctx /*a1*/, owner_recipient_id /*a3*/, owner_private_key /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jownerRecipientId, (jbyte*) owner_recipient_id_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1addKeyRecipient (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jrecipientId, jobject jpublicKey) {
    // Cast class context
    vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
    vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

    vscf_status_t status = vscf_message_info_editor_add_key_recipient(message_info_editor_ctx /*a1*/, recipient_id /*a3*/, public_key /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1removeKeyRecipient (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jrecipientId) {
    // Cast class context
    vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

    // Wrap input data
    byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
    vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

    jboolean ret = (jboolean) vscf_message_info_editor_remove_key_recipient(message_info_editor_ctx /*a1*/, recipient_id /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1removeAll (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

    vscf_message_info_editor_remove_all(message_info_editor_ctx /*a1*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1packedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_message_info_editor_packed_len(message_info_editor_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoEditor_1pack (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *message_info = vsc_buffer_new_with_capacity(vscf_message_info_editor_packed_len((vscf_message_info_editor_t /*2*/ *) c_ctx /*3*/));

    vscf_message_info_editor_pack(message_info_editor_ctx /*a1*/, message_info /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(message_info));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(message_info), (jbyte*) vsc_buffer_bytes(message_info));
    // Free resources
    vsc_buffer_delete(message_info);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_signer_info_t **)&c_ctx = vscf_signer_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_signer_info_delete(*(vscf_signer_info_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1signerId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_t /*2*/* signer_info_ctx = *(vscf_signer_info_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_signer_info_signer_id(signer_info_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1signerAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_t /*2*/* signer_info_ctx = *(vscf_signer_info_t /*2*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_signer_info_signer_alg_info(signer_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfo_1signature (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_t /*2*/* signer_info_ctx = *(vscf_signer_info_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_signer_info_signature(signer_info_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_signer_info_list_t **)&c_ctx = vscf_signer_info_list_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_signer_info_list_delete(*(vscf_signer_info_list_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1hasItem (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_signer_info_list_has_item(signer_info_list_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1item (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

    const vscf_signer_info_t */*5*/ proxyResult = vscf_signer_info_list_item(signer_info_list_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/SignerInfo");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class SignerInfo not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/SignerInfo;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class SignerInfo has no 'getInstance' method.");
    }
    vscf_signer_info_shallow_copy((vscf_signer_info_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1hasNext (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_signer_info_list_has_next(signer_info_list_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1next (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

    const vscf_signer_info_list_t */*5*/ proxyResult = vscf_signer_info_list_next(signer_info_list_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/SignerInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class SignerInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/SignerInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class SignerInfoList has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1hasPrev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_signer_info_list_has_prev(signer_info_list_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1prev (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

    const vscf_signer_info_list_t */*5*/ proxyResult = vscf_signer_info_list_prev(signer_info_list_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/SignerInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class SignerInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/SignerInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class SignerInfoList has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signerInfoList_1clear (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

    vscf_signer_info_list_clear(signer_info_list_ctx /*a1*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_message_info_footer_t **)&c_ctx = vscf_message_info_footer_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_footer_delete(*(vscf_message_info_footer_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1hasSignerInfos (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_footer_t /*2*/* message_info_footer_ctx = *(vscf_message_info_footer_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_message_info_footer_has_signer_infos(message_info_footer_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1signerInfos (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_footer_t /*2*/* message_info_footer_ctx = *(vscf_message_info_footer_t /*2*/**) &c_ctx;

    const vscf_signer_info_list_t */*5*/ proxyResult = vscf_message_info_footer_signer_infos(message_info_footer_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/SignerInfoList");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class SignerInfoList not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/SignerInfoList;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class SignerInfoList has no 'getInstance' method.");
    }
    vscf_signer_info_list_shallow_copy((vscf_signer_info_list_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1signerHashAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_footer_t /*2*/* message_info_footer_ctx = *(vscf_message_info_footer_t /*2*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_message_info_footer_signer_hash_alg_info(message_info_footer_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoFooter_1signerDigest (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_footer_t /*2*/* message_info_footer_ctx = *(vscf_message_info_footer_t /*2*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_message_info_footer_signer_digest(message_info_footer_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signedDataInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_signed_data_info_t **)&c_ctx = vscf_signed_data_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signedDataInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_signed_data_info_delete(*(vscf_signed_data_info_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_signedDataInfo_1hashAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_signed_data_info_t /*2*/* signed_data_info_ctx = *(vscf_signed_data_info_t /*2*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_signed_data_info_hash_alg_info(signed_data_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_footer_info_t **)&c_ctx = vscf_footer_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_footer_info_delete(*(vscf_footer_info_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1hasSignedDataInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_footer_info_t /*2*/* footer_info_ctx = *(vscf_footer_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_footer_info_has_signed_data_info(footer_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1signedDataInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_footer_info_t /*2*/* footer_info_ctx = *(vscf_footer_info_t /*2*/**) &c_ctx;

    const vscf_signed_data_info_t */*5*/ proxyResult = vscf_footer_info_signed_data_info(footer_info_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/SignedDataInfo");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class SignedDataInfo not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/SignedDataInfo;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class SignedDataInfo has no 'getInstance' method.");
    }
    vscf_signed_data_info_shallow_copy((vscf_signed_data_info_t */*5*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1setDataSize (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataSize) {
    // Cast class context
    vscf_footer_info_t /*2*/* footer_info_ctx = *(vscf_footer_info_t /*2*/**) &c_ctx;

    vscf_footer_info_set_data_size(footer_info_ctx /*a1*/, jdataSize /*a9*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_footerInfo_1dataSize (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_footer_info_t /*2*/* footer_info_ctx = *(vscf_footer_info_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_footer_info_data_size(footer_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_key_info_t **)&c_ctx = vscf_key_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_info_delete(*(vscf_key_info_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgInfo_2 (JNIEnv *jenv, jobject jobj, jobject jalgInfo) {
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    jlong proxyResult = (jlong) vscf_key_info_new_with_alg_info(alg_info /*a6*/);
    return proxyResult;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isCompound (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_info_is_compound(key_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isChained (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_info_is_chained(key_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isCompoundChained (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_info_is_compound_chained(key_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isCompoundChainedCipher (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_info_is_compound_chained_cipher(key_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isCompoundChainedSigner (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_info_is_compound_chained_signer(key_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isHybridPostQuantum (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_info_is_hybrid_post_quantum(key_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isHybridPostQuantumCipher (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_info_is_hybrid_post_quantum_cipher(key_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1isHybridPostQuantumSigner (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_key_info_is_hybrid_post_quantum_signer(key_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_key_info_alg_id(key_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundCipherAlgId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_key_info_compound_cipher_alg_id(key_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundSignerAlgId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_key_info_compound_signer_alg_id(key_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1chainedL1AlgId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_key_info_chained_l1_alg_id(key_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1chainedL2AlgId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_key_info_chained_l2_alg_id(key_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundCipherL1AlgId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_key_info_compound_cipher_l1_alg_id(key_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundCipherL2AlgId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_key_info_compound_cipher_l2_alg_id(key_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundSignerL1AlgId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_key_info_compound_signer_l1_alg_id(key_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyInfo_1compoundSignerL2AlgId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_key_info_compound_signer_l2_alg_id(key_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_padding_params_t **)&c_ctx = vscf_padding_params_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_padding_params_delete(*(vscf_padding_params_t /*2*/ **) &c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1new__III (JNIEnv *jenv, jobject jobj, jint jframe, jint jframeMin, jint jframeMax) {
    jlong proxyResult = (jlong) vscf_padding_params_new_with_constraints(jframe /*a9*/, jframeMin /*a9*/, jframeMax /*a9*/);
    return proxyResult;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1frame (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_padding_params_t /*2*/* padding_params_ctx = *(vscf_padding_params_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_padding_params_frame(padding_params_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1frameMin (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_padding_params_t /*2*/* padding_params_ctx = *(vscf_padding_params_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_padding_params_frame_min(padding_params_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_paddingParams_1frameMax (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_padding_params_t /*2*/* padding_params_ctx = *(vscf_padding_params_t /*2*/**) &c_ctx;

    jint ret = (jint) vscf_padding_params_frame_max(padding_params_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_sha224_t **)&c_ctx = vscf_sha224_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha224_delete(*(vscf_sha224_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha224_t /*9*/* sha224_ctx = *(vscf_sha224_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_sha224_alg_id(sha224_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha224_t /*9*/* sha224_ctx = *(vscf_sha224_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_sha224_produce_alg_info(sha224_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_sha224_t /*9*/* sha224_ctx = *(vscf_sha224_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_sha224_restore_alg_info(sha224_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1hash (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha224_DIGEST_LEN);

    vscf_sha224_hash(data /*a3*/, digest /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha224_t /*9*/* sha224_ctx = *(vscf_sha224_t /*9*/**) &c_ctx;

    vscf_sha224_start(sha224_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_sha224_t /*9*/* sha224_ctx = *(vscf_sha224_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vscf_sha224_update(sha224_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha224_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha224_t /*9*/* sha224_ctx = *(vscf_sha224_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha224_DIGEST_LEN);

    vscf_sha224_finish(sha224_ctx /*a1*/, digest /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_sha256_t **)&c_ctx = vscf_sha256_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha256_delete(*(vscf_sha256_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha256_t /*9*/* sha256_ctx = *(vscf_sha256_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_sha256_alg_id(sha256_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha256_t /*9*/* sha256_ctx = *(vscf_sha256_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_sha256_produce_alg_info(sha256_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_sha256_t /*9*/* sha256_ctx = *(vscf_sha256_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_sha256_restore_alg_info(sha256_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1hash (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_hash(data /*a3*/, digest /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha256_t /*9*/* sha256_ctx = *(vscf_sha256_t /*9*/**) &c_ctx;

    vscf_sha256_start(sha256_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_sha256_t /*9*/* sha256_ctx = *(vscf_sha256_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vscf_sha256_update(sha256_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha256_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha256_t /*9*/* sha256_ctx = *(vscf_sha256_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_finish(sha256_ctx /*a1*/, digest /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_sha384_t **)&c_ctx = vscf_sha384_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha384_delete(*(vscf_sha384_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha384_t /*9*/* sha384_ctx = *(vscf_sha384_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_sha384_alg_id(sha384_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha384_t /*9*/* sha384_ctx = *(vscf_sha384_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_sha384_produce_alg_info(sha384_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_sha384_t /*9*/* sha384_ctx = *(vscf_sha384_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_sha384_restore_alg_info(sha384_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1hash (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha384_DIGEST_LEN);

    vscf_sha384_hash(data /*a3*/, digest /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha384_t /*9*/* sha384_ctx = *(vscf_sha384_t /*9*/**) &c_ctx;

    vscf_sha384_start(sha384_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_sha384_t /*9*/* sha384_ctx = *(vscf_sha384_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vscf_sha384_update(sha384_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha384_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha384_t /*9*/* sha384_ctx = *(vscf_sha384_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha384_DIGEST_LEN);

    vscf_sha384_finish(sha384_ctx /*a1*/, digest /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_sha512_t **)&c_ctx = vscf_sha512_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sha512_delete(*(vscf_sha512_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha512_t /*9*/* sha512_ctx = *(vscf_sha512_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_sha512_alg_id(sha512_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha512_t /*9*/* sha512_ctx = *(vscf_sha512_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_sha512_produce_alg_info(sha512_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_sha512_t /*9*/* sha512_ctx = *(vscf_sha512_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_sha512_restore_alg_info(sha512_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1hash (JNIEnv *jenv, jobject jobj, jbyteArray jdata) {
    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);

    vscf_sha512_hash(data /*a3*/, digest /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha512_t /*9*/* sha512_ctx = *(vscf_sha512_t /*9*/**) &c_ctx;

    vscf_sha512_start(sha512_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_sha512_t /*9*/* sha512_ctx = *(vscf_sha512_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vscf_sha512_update(sha512_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sha512_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sha512_t /*9*/* sha512_ctx = *(vscf_sha512_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);

    vscf_sha512_finish(sha512_ctx /*a1*/, digest /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
    // Free resources
    vsc_buffer_delete(digest);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_aes256_gcm_t **)&c_ctx = vscf_aes256_gcm_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_aes256_gcm_delete(*(vscf_aes256_gcm_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_aes256_gcm_alg_id(aes256_gcm_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_aes256_gcm_produce_alg_info(aes256_gcm_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_aes256_gcm_restore_alg_info(aes256_gcm_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_encrypted_len((vscf_aes256_gcm_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_gcm_encrypt(aes256_gcm_ctx /*a1*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_gcm_encrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1preciseEncryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_gcm_precise_encrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_decrypted_len((vscf_aes256_gcm_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_gcm_decrypt(aes256_gcm_ctx /*a1*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_gcm_decrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1setNonce (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jnonce) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* nonce_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jnonce, NULL);
    vsc_data_t nonce = vsc_data(nonce_arr, (*jenv)->GetArrayLength(jenv, jnonce));

    vscf_aes256_gcm_set_nonce(aes256_gcm_ctx /*a1*/, nonce /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jnonce, (jbyte*) nonce_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1setKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    vscf_aes256_gcm_set_key(aes256_gcm_ctx /*a1*/, key /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1startEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    vscf_aes256_gcm_start_encryption(aes256_gcm_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1startDecryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    vscf_aes256_gcm_start_decryption(aes256_gcm_ctx /*a1*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len((vscf_aes256_gcm_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_aes256_gcm_update(aes256_gcm_ctx /*a1*/, data /*a3*/, out /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1outLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_gcm_out_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1encryptedOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_gcm_encrypted_out_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1decryptedOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_gcm_decrypted_out_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len((vscf_aes256_gcm_t /*9*/ *) c_ctx /*3*/, 0/*b*/));

    vscf_status_t status = vscf_aes256_gcm_finish(aes256_gcm_ctx /*a1*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1authEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jbyteArray jauthData) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    byte* auth_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jauthData, NULL);
    vsc_data_t auth_data = vsc_data(auth_data_arr, (*jenv)->GetArrayLength(jenv, jauthData));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_auth_encrypted_len((vscf_aes256_gcm_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vsc_buffer_t *tag = vsc_buffer_new_with_capacity(vscf_aes256_gcm_AUTH_TAG_LEN);

    vscf_status_t status = vscf_aes256_gcm_auth_encrypt(aes256_gcm_ctx /*a1*/, data /*a3*/, auth_data /*a3*/, out /*a3*/, tag /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AuthEncryptAuthEncryptResult");
    if (NULL == cls) {
        VSCF_ASSERT("Class AuthEncryptAuthEncryptResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidOut = (*jenv)->GetFieldID(jenv, cls, "out", "[B");
    jbyteArray jOutArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, jOutArr, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    (*jenv)->SetObjectField(jenv, newObj, fidOut, jOutArr);
    jfieldID fidTag = (*jenv)->GetFieldID(jenv, cls, "tag", "[B");
    jbyteArray jTagArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(tag));
    (*jenv)->SetByteArrayRegion (jenv, jTagArr, 0, vsc_buffer_len(tag), (jbyte*) vsc_buffer_bytes(tag));
    (*jenv)->SetObjectField(jenv, newObj, fidTag, jTagArr);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jauthData, (jbyte*) auth_data_arr, 0);

    vsc_buffer_delete(out);

    vsc_buffer_delete(tag);

    return newObj;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1authEncryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_gcm_auth_encrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1authDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jbyteArray jauthData, jbyteArray jtag) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    byte* auth_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jauthData, NULL);
    vsc_data_t auth_data = vsc_data(auth_data_arr, (*jenv)->GetArrayLength(jenv, jauthData));

    byte* tag_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtag, NULL);
    vsc_data_t tag = vsc_data(tag_arr, (*jenv)->GetArrayLength(jenv, jtag));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_auth_decrypted_len((vscf_aes256_gcm_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_gcm_auth_decrypt(aes256_gcm_ctx /*a1*/, data /*a3*/, auth_data /*a3*/, tag /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jauthData, (jbyte*) auth_data_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jtag, (jbyte*) tag_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1authDecryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_gcm_auth_decrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1setAuthData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jauthData) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* auth_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jauthData, NULL);
    vsc_data_t auth_data = vsc_data(auth_data_arr, (*jenv)->GetArrayLength(jenv, jauthData));

    vscf_aes256_gcm_set_auth_data(aes256_gcm_ctx /*a1*/, auth_data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jauthData, (jbyte*) auth_data_arr, 0);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1finishAuthEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len((vscf_aes256_gcm_t /*9*/ *) c_ctx /*3*/, 0/*b*/));

    vsc_buffer_t *tag = vsc_buffer_new_with_capacity(vscf_aes256_gcm_AUTH_TAG_LEN);

    vscf_status_t status = vscf_aes256_gcm_finish_auth_encryption(aes256_gcm_ctx /*a1*/, out /*a3*/, tag /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/CipherAuthFinishAuthEncryptionResult");
    if (NULL == cls) {
        VSCF_ASSERT("Class CipherAuthFinishAuthEncryptionResult not found.");
    }
    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
    jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
    jfieldID fidOut = (*jenv)->GetFieldID(jenv, cls, "out", "[B");
    jbyteArray jOutArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, jOutArr, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    (*jenv)->SetObjectField(jenv, newObj, fidOut, jOutArr);
    jfieldID fidTag = (*jenv)->GetFieldID(jenv, cls, "tag", "[B");
    jbyteArray jTagArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(tag));
    (*jenv)->SetByteArrayRegion (jenv, jTagArr, 0, vsc_buffer_len(tag), (jbyte*) vsc_buffer_bytes(tag));
    (*jenv)->SetObjectField(jenv, newObj, fidTag, jTagArr);
    // Free resources
    vsc_buffer_delete(out);

    vsc_buffer_delete(tag);

    return newObj;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Gcm_1finishAuthDecryption (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jtag) {
    // Cast class context
    vscf_aes256_gcm_t /*9*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* tag_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtag, NULL);
    vsc_data_t tag = vsc_data(tag_arr, (*jenv)->GetArrayLength(jenv, jtag));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len((vscf_aes256_gcm_t /*9*/ *) c_ctx /*3*/, 0/*b*/));

    vscf_status_t status = vscf_aes256_gcm_finish_auth_decryption(aes256_gcm_ctx /*a1*/, tag /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jtag, (jbyte*) tag_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_aes256_cbc_t **)&c_ctx = vscf_aes256_cbc_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_aes256_cbc_delete(*(vscf_aes256_cbc_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_aes256_cbc_alg_id(aes256_cbc_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_aes256_cbc_produce_alg_info(aes256_cbc_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_aes256_cbc_restore_alg_info(aes256_cbc_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_encrypted_len((vscf_aes256_cbc_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_cbc_encrypt(aes256_cbc_ctx /*a1*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_cbc_encrypted_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1preciseEncryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_cbc_precise_encrypted_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_decrypted_len((vscf_aes256_cbc_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_aes256_cbc_decrypt(aes256_cbc_ctx /*a1*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_cbc_decrypted_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1setNonce (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jnonce) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* nonce_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jnonce, NULL);
    vsc_data_t nonce = vsc_data(nonce_arr, (*jenv)->GetArrayLength(jenv, jnonce));

    vscf_aes256_cbc_set_nonce(aes256_cbc_ctx /*a1*/, nonce /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jnonce, (jbyte*) nonce_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1setKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    vscf_aes256_cbc_set_key(aes256_cbc_ctx /*a1*/, key /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1startEncryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    vscf_aes256_cbc_start_encryption(aes256_cbc_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1startDecryption (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    vscf_aes256_cbc_start_decryption(aes256_cbc_ctx /*a1*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_out_len((vscf_aes256_cbc_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_aes256_cbc_update(aes256_cbc_ctx /*a1*/, data /*a3*/, out /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1outLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_cbc_out_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1encryptedOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_cbc_encrypted_out_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1decryptedOutLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_aes256_cbc_decrypted_out_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_aes256Cbc_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_aes256_cbc_t /*9*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_out_len((vscf_aes256_cbc_t /*9*/ *) c_ctx /*3*/, 0/*b*/));

    vscf_status_t status = vscf_aes256_cbc_finish(aes256_cbc_ctx /*a1*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_asn1rd_t **)&c_ctx = vscf_asn1rd_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_asn1rd_delete(*(vscf_asn1rd_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vscf_asn1rd_reset(asn1rd_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1leftLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_left_len(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1hasError (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_asn1rd_has_error(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1status (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_asn1rd_status(asn1rd_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1getTag (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_get_tag(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1getLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_get_len(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1getDataLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_get_data_len(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readTag (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jtag) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_read_tag(asn1rd_ctx /*a1*/, jtag /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readContextTag (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jtag) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_read_context_tag(asn1rd_ctx /*a1*/, jtag /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_read_int(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt8 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_read_int8(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt16 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_read_int16(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt32 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_read_int32(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readInt64 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_read_int64(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jlong ret = (jlong) vscf_asn1rd_read_uint(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint8 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jlong ret = (jlong) vscf_asn1rd_read_uint8(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint16 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jlong ret = (jlong) vscf_asn1rd_read_uint16(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint32 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jlong ret = (jlong) vscf_asn1rd_read_uint32(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUint64 (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jlong ret = (jlong) vscf_asn1rd_read_uint64(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readBool (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_asn1rd_read_bool(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readNull (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    vscf_asn1rd_read_null(asn1rd_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readNullOptional (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    vscf_asn1rd_read_null_optional(asn1rd_ctx /*a1*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readOctetStr (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_octet_str(asn1rd_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readBitstringAsOctetStr (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_bitstring_as_octet_str(asn1rd_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readUtf8Str (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_utf8_str(asn1rd_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readOid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_oid(asn1rd_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_data(asn1rd_ctx /*a1*/, jlen /*a9*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readSequence (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_read_sequence(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1rd_1readSet (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1rd_t /*9*/* asn1rd_ctx = *(vscf_asn1rd_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1rd_read_set(asn1rd_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_asn1wr_t **)&c_ctx = vscf_asn1wr_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_asn1wr_delete(*(vscf_asn1wr_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jout, jint joutLen) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    // Wrap arrays
    byte * out = (byte *) (*jenv)->GetByteArrayElements(jenv, jout, NULL);

    vscf_asn1wr_reset(asn1wr_ctx /*a1*/, out /*a3*/, joutLen /*a9*/);
    // Free resources
    //TODO: Fix out memory leak
    //(*jenv)->ReleaseByteArrayElements(jenv, jout, out, 0);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx, jboolean jdoNotAdjust) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_finish(asn1wr_ctx /*a1*/, jdoNotAdjust /*a9*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1bytes (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jlong ret = (jlong) vscf_asn1wr_bytes(asn1wr_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_len(asn1wr_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writtenLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_written_len(asn1wr_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1unwrittenLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_unwritten_len(asn1wr_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1hasError (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_asn1wr_has_error(asn1wr_ctx /*a1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1status (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_asn1wr_status(asn1wr_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1reserve (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jlong ret = (jlong) vscf_asn1wr_reserve(asn1wr_ctx /*a1*/, jlen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeTag (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jtag) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_tag(asn1wr_ctx /*a1*/, jtag /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeContextTag (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jtag, jint jlen) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_context_tag(asn1wr_ctx /*a1*/, jtag /*a9*/, jlen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_len(asn1wr_ctx /*a1*/, jlen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_int(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt8 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_int8(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt16 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_int16(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt32 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_int32(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeInt64 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_int64(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_uint(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint8 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_uint8(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint16 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_uint16(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint32 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_uint32(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUint64 (JNIEnv *jenv, jobject jobj, jlong c_ctx, jlong jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_uint64(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeBool (JNIEnv *jenv, jobject jobj, jlong c_ctx, jboolean jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_bool(asn1wr_ctx /*a1*/, jvalue /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeNull (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_null(asn1wr_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeOctetStr (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
    vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

    jint ret = (jint) vscf_asn1wr_write_octet_str(asn1wr_ctx /*a1*/, value /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeOctetStrAsBitstring (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
    vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

    jint ret = (jint) vscf_asn1wr_write_octet_str_as_bitstring(asn1wr_ctx /*a1*/, value /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    jint ret = (jint) vscf_asn1wr_write_data(asn1wr_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeUtf8Str (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
    vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

    jint ret = (jint) vscf_asn1wr_write_utf8_str(asn1wr_ctx /*a1*/, value /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeOid (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jvalue) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
    vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

    jint ret = (jint) vscf_asn1wr_write_oid(asn1wr_ctx /*a1*/, value /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeSequence (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_sequence(asn1wr_ctx /*a1*/, jlen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_asn1wr_1writeSet (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Cast class context
    vscf_asn1wr_t /*9*/* asn1wr_ctx = *(vscf_asn1wr_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_asn1wr_write_set(asn1wr_ctx /*a1*/, jlen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1keyExponent (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_public_key_t /*9*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_rsa_public_key_key_exponent(rsa_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_rsa_public_key_t **)&c_ctx = vscf_rsa_public_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_rsa_public_key_delete(*(vscf_rsa_public_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_public_key_t /*9*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_rsa_public_key_alg_id(rsa_public_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_public_key_t /*9*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_rsa_public_key_alg_info(rsa_public_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_public_key_t /*9*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_rsa_public_key_len(rsa_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_public_key_t /*9*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_rsa_public_key_bitlen(rsa_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPublicKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_public_key_t /*9*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_rsa_public_key_is_valid(rsa_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_rsa_private_key_t **)&c_ctx = vscf_rsa_private_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_rsa_private_key_delete(*(vscf_rsa_private_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_private_key_t /*9*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_rsa_private_key_alg_id(rsa_private_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_private_key_t /*9*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_rsa_private_key_alg_info(rsa_private_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_private_key_t /*9*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_rsa_private_key_len(rsa_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_private_key_t /*9*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_rsa_private_key_bitlen(rsa_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_private_key_t /*9*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_rsa_private_key_is_valid(rsa_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsaPrivateKey_1extractPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_private_key_t /*9*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_rsa_private_key_extract_public_key(rsa_private_key_ctx /*a1*/);
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_rsa_release_random((vscf_rsa_t /*9*/ *) c_ctx);
    vscf_rsa_use_random((vscf_rsa_t /*9*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_rsa_setup_defaults(rsa_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1generateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jbitlen) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_rsa_generate_key(rsa_ctx /*a1*/, jbitlen /*a9*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_rsa_t **)&c_ctx = vscf_rsa_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_rsa_delete(*(vscf_rsa_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_rsa_alg_id(rsa_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_rsa_produce_alg_info(rsa_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_rsa_restore_alg_info(rsa_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_rsa_generate_ephemeral_key(rsa_ctx /*a1*/, key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ raw_key = *(vscf_raw_public_key_t * /*7*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_rsa_import_public_key(rsa_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    const vscf_raw_public_key_t */*5*/ proxyResult = vscf_rsa_export_public_key(rsa_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_private_key_t */*5*/ raw_key = *(vscf_raw_private_key_t */*5*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_rsa_import_private_key(rsa_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    const vscf_raw_private_key_t */*5*/ proxyResult = vscf_rsa_export_private_key(rsa_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1canEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_rsa_can_encrypt(rsa_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jint ret = (jint) vscf_rsa_encrypted_len(rsa_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jbyteArray jdata) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_rsa_encrypted_len((vscf_rsa_t /*9*/ *) c_ctx /*3*/, public_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_rsa_encrypt(rsa_ctx /*a1*/, public_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1canDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_rsa_can_decrypt(rsa_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_rsa_decrypted_len(rsa_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jbyteArray jdata) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_rsa_decrypted_len((vscf_rsa_t /*9*/ *) c_ctx /*3*/, private_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_rsa_decrypt(rsa_ctx /*a1*/, private_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1canSign (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_rsa_can_sign(rsa_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_rsa_signature_len(rsa_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1signHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jobject jhashId, jbyteArray jdigest) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_rsa_signature_len((vscf_rsa_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_rsa_sign_hash(rsa_ctx /*a1*/, private_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), (jbyte*) vsc_buffer_bytes(signature));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1canVerify (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_rsa_can_verify(rsa_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rsa_1verifyHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jobject jhashId, jbyteArray jdigest, jbyteArray jsignature) {
    // Cast class context
    vscf_rsa_t /*9*/* rsa_ctx = *(vscf_rsa_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
    vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

    jboolean ret = (jboolean) vscf_rsa_verify_hash(rsa_ctx /*a1*/, public_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_ecc_public_key_t **)&c_ctx = vscf_ecc_public_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ecc_public_key_delete(*(vscf_ecc_public_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_public_key_t /*9*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_ecc_public_key_alg_id(ecc_public_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_public_key_t /*9*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ecc_public_key_alg_info(ecc_public_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_public_key_t /*9*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_ecc_public_key_len(ecc_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_public_key_t /*9*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_ecc_public_key_bitlen(ecc_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPublicKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_public_key_t /*9*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_ecc_public_key_is_valid(ecc_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_ecc_private_key_t **)&c_ctx = vscf_ecc_private_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ecc_private_key_delete(*(vscf_ecc_private_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_private_key_t /*9*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_ecc_private_key_alg_id(ecc_private_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_private_key_t /*9*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ecc_private_key_alg_info(ecc_private_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_private_key_t /*9*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_ecc_private_key_len(ecc_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_private_key_t /*9*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_ecc_private_key_bitlen(ecc_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_private_key_t /*9*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_ecc_private_key_is_valid(ecc_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccPrivateKey_1extractPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_private_key_t /*9*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ecc_private_key_extract_public_key(ecc_private_key_ctx /*a1*/);
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_ecc_release_random((vscf_ecc_t /*9*/ *) c_ctx);
    vscf_ecc_use_random((vscf_ecc_t /*9*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1setEcies (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jecies) {
    jclass ecies_cls = (*jenv)->GetObjectClass(jenv, jecies);
    if (NULL == ecies_cls) {
        VSCF_ASSERT("Class Ecies not found.");
    }
    jfieldID ecies_fidCtx = (*jenv)->GetFieldID(jenv, ecies_cls, "cCtx", "J");
    if (NULL == ecies_fidCtx) {
        VSCF_ASSERT("Class 'Ecies' has no field 'cCtx'.");
    }
    jlong ecies_c_ctx = (*jenv)->GetLongField(jenv, jecies, ecies_fidCtx);
    vscf_ecies_t */*5*/ ecies = *(vscf_ecies_t */*5*/*) &ecies_c_ctx;

    vscf_ecc_release_ecies((vscf_ecc_t /*9*/ *) c_ctx);
    vscf_ecc_use_ecies((vscf_ecc_t /*9*/ *) c_ctx, ecies);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_ecc_setup_defaults(ecc_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1generateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgId) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass alg_id_cls = (*jenv)->GetObjectClass(jenv, jalgId);
    jmethodID alg_id_methodID = (*jenv)->GetMethodID(jenv, alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, alg_id_methodID);

    const vscf_impl_t */*6*/ proxyResult = vscf_ecc_generate_key(ecc_ctx /*a1*/, alg_id /*a7*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_ecc_t **)&c_ctx = vscf_ecc_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ecc_delete(*(vscf_ecc_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_ecc_alg_id(ecc_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ecc_produce_alg_info(ecc_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_ecc_restore_alg_info(ecc_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ecc_generate_ephemeral_key(ecc_ctx /*a1*/, key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ raw_key = *(vscf_raw_public_key_t * /*7*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ecc_import_public_key(ecc_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    const vscf_raw_public_key_t */*5*/ proxyResult = vscf_ecc_export_public_key(ecc_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_private_key_t */*5*/ raw_key = *(vscf_raw_private_key_t */*5*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ecc_import_private_key(ecc_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    const vscf_raw_private_key_t */*5*/ proxyResult = vscf_ecc_export_private_key(ecc_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1canEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_ecc_can_encrypt(ecc_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jint ret = (jint) vscf_ecc_encrypted_len(ecc_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jbyteArray jdata) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecc_encrypted_len((vscf_ecc_t /*9*/ *) c_ctx /*3*/, public_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_ecc_encrypt(ecc_ctx /*a1*/, public_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1canDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_ecc_can_decrypt(ecc_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_ecc_decrypted_len(ecc_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jbyteArray jdata) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecc_decrypted_len((vscf_ecc_t /*9*/ *) c_ctx /*3*/, private_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_ecc_decrypt(ecc_ctx /*a1*/, private_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1canSign (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_ecc_can_sign(ecc_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_ecc_signature_len(ecc_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1signHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jobject jhashId, jbyteArray jdigest) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_ecc_signature_len((vscf_ecc_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_ecc_sign_hash(ecc_ctx /*a1*/, private_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), (jbyte*) vsc_buffer_bytes(signature));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1canVerify (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_ecc_can_verify(ecc_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1verifyHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jobject jhashId, jbyteArray jdigest, jbyteArray jsignature) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
    vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

    jboolean ret = (jboolean) vscf_ecc_verify_hash(ecc_ctx /*a1*/, public_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1computeSharedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jobject jprivateKey) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_ecc_shared_key_len((vscf_ecc_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_ecc_compute_shared_key(ecc_ctx /*a1*/, public_key /*a6*/, private_key /*a6*/, shared_key /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
    // Free resources
    vsc_buffer_delete(shared_key);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ecc_1sharedKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Cast class context
    vscf_ecc_t /*9*/* ecc_ctx = *(vscf_ecc_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    jint ret = (jint) vscf_ecc_shared_key_len(ecc_ctx /*a1*/, key /*a6*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_entropy_accumulator_t /*9*/* entropy_accumulator_ctx = *(vscf_entropy_accumulator_t /*9*/**) &c_ctx;

    vscf_entropy_accumulator_setup_defaults(entropy_accumulator_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1addSource (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jsource, jint jthreshold) {
    // Cast class context
    vscf_entropy_accumulator_t /*9*/* entropy_accumulator_ctx = *(vscf_entropy_accumulator_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass source_cls = (*jenv)->GetObjectClass(jenv, jsource);
    if (NULL == source_cls) {
        VSCF_ASSERT("Class EntropySource not found.");
    }
    jfieldID source_fidCtx = (*jenv)->GetFieldID(jenv, source_cls, "cCtx", "J");
    if (NULL == source_fidCtx) {
        VSCF_ASSERT("Class 'EntropySource' has no field 'cCtx'.");
    }
    jlong source_c_ctx = (*jenv)->GetLongField(jenv, jsource, source_fidCtx);
    vscf_impl_t */*6*/ source = *(vscf_impl_t */*6*/*)&source_c_ctx;

    vscf_entropy_accumulator_add_source(entropy_accumulator_ctx /*a1*/, source /*a6*/, jthreshold /*a9*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_entropy_accumulator_t **)&c_ctx = vscf_entropy_accumulator_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_entropy_accumulator_delete(*(vscf_entropy_accumulator_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1isStrong (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_entropy_accumulator_t /*9*/* entropy_accumulator_ctx = *(vscf_entropy_accumulator_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_entropy_accumulator_is_strong(entropy_accumulator_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_entropyAccumulator_1gather (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Cast class context
    vscf_entropy_accumulator_t /*9*/* entropy_accumulator_ctx = *(vscf_entropy_accumulator_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(jlen);

    vscf_status_t status = vscf_entropy_accumulator_gather(entropy_accumulator_ctx /*a1*/, jlen /*a9*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1setEntropySource (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jentropySource) {
    jclass entropy_source_cls = (*jenv)->GetObjectClass(jenv, jentropySource);
    if (NULL == entropy_source_cls) {
        VSCF_ASSERT("Class EntropySource not found.");
    }
    jfieldID entropy_source_fidCtx = (*jenv)->GetFieldID(jenv, entropy_source_cls, "cCtx", "J");
    if (NULL == entropy_source_fidCtx) {
        VSCF_ASSERT("Class 'EntropySource' has no field 'cCtx'.");
    }
    jlong entropy_source_c_ctx = (*jenv)->GetLongField(jenv, jentropySource, entropy_source_fidCtx);
    vscf_impl_t */*6*/ entropy_source = *(vscf_impl_t */*6*/*) &entropy_source_c_ctx;

    vscf_ctr_drbg_release_entropy_source((vscf_ctr_drbg_t /*9*/ *) c_ctx);
    vscf_status_t status = vscf_ctr_drbg_use_entropy_source((vscf_ctr_drbg_t /*9*/ *) c_ctx, entropy_source);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ctr_drbg_t /*9*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_ctr_drbg_setup_defaults(ctr_drbg_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1enablePredictionResistance (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ctr_drbg_t /*9*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*9*/**) &c_ctx;

    vscf_ctr_drbg_enable_prediction_resistance(ctr_drbg_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1setReseedInterval (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jinterval) {
    // Cast class context
    vscf_ctr_drbg_t /*9*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*9*/**) &c_ctx;

    vscf_ctr_drbg_set_reseed_interval(ctr_drbg_ctx /*a1*/, jinterval /*a9*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1setEntropyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Cast class context
    vscf_ctr_drbg_t /*9*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*9*/**) &c_ctx;

    vscf_ctr_drbg_set_entropy_len(ctr_drbg_ctx /*a1*/, jlen /*a9*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_ctr_drbg_t **)&c_ctx = vscf_ctr_drbg_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ctr_drbg_delete(*(vscf_ctr_drbg_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1random (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_ctr_drbg_t /*9*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *data = vsc_buffer_new_with_capacity(jdataLen);

    vscf_status_t status = vscf_ctr_drbg_random(ctr_drbg_ctx /*a1*/, jdataLen /*a9*/, data /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), (jbyte*) vsc_buffer_bytes(data));
    // Free resources
    vsc_buffer_delete(data);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ctrDrbg_1reseed (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ctr_drbg_t /*9*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_ctr_drbg_reseed(ctr_drbg_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        VSCF_ASSERT("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        VSCF_ASSERT("Class 'Hash' has no field 'cCtx'.");
    }
    jlong hash_c_ctx = (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);
    vscf_impl_t */*6*/ hash = *(vscf_impl_t */*6*/*) &hash_c_ctx;

    vscf_hmac_release_hash((vscf_hmac_t /*9*/ *) c_ctx);
    vscf_hmac_use_hash((vscf_hmac_t /*9*/ *) c_ctx, hash);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_hmac_t **)&c_ctx = vscf_hmac_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_hmac_delete(*(vscf_hmac_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_hmac_t /*9*/* hmac_ctx = *(vscf_hmac_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_hmac_alg_id(hmac_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_hmac_t /*9*/* hmac_ctx = *(vscf_hmac_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_hmac_produce_alg_info(hmac_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_hmac_t /*9*/* hmac_ctx = *(vscf_hmac_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_hmac_restore_alg_info(hmac_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1digestLen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_hmac_t /*9*/* hmac_ctx = *(vscf_hmac_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_hmac_digest_len(hmac_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1mac (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey, jbyteArray jdata) {
    // Cast class context
    vscf_hmac_t /*9*/* hmac_ctx = *(vscf_hmac_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *mac = vsc_buffer_new_with_capacity(vscf_hmac_digest_len((vscf_hmac_t /*9*/ *) c_ctx /*3*/));

    vscf_hmac_mac(hmac_ctx /*a1*/, key /*a3*/, data /*a3*/, mac /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(mac));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(mac), (jbyte*) vsc_buffer_bytes(mac));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(mac);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1start (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkey) {
    // Cast class context
    vscf_hmac_t /*9*/* hmac_ctx = *(vscf_hmac_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
    vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

    vscf_hmac_start(hmac_ctx /*a1*/, key /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1update (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_hmac_t /*9*/* hmac_ctx = *(vscf_hmac_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vscf_hmac_update(hmac_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1finish (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_hmac_t /*9*/* hmac_ctx = *(vscf_hmac_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *mac = vsc_buffer_new_with_capacity(vscf_hmac_digest_len((vscf_hmac_t /*9*/ *) c_ctx /*3*/));

    vscf_hmac_finish(hmac_ctx /*a1*/, mac /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(mac));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(mac), (jbyte*) vsc_buffer_bytes(mac));
    // Free resources
    vsc_buffer_delete(mac);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hmac_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_hmac_t /*9*/* hmac_ctx = *(vscf_hmac_t /*9*/**) &c_ctx;

    vscf_hmac_reset(hmac_ctx /*a1*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        VSCF_ASSERT("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        VSCF_ASSERT("Class 'Hash' has no field 'cCtx'.");
    }
    jlong hash_c_ctx = (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);
    vscf_impl_t */*6*/ hash = *(vscf_impl_t */*6*/*) &hash_c_ctx;

    vscf_hkdf_release_hash((vscf_hkdf_t /*9*/ *) c_ctx);
    vscf_hkdf_use_hash((vscf_hkdf_t /*9*/ *) c_ctx, hash);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_hkdf_t **)&c_ctx = vscf_hkdf_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_hkdf_delete(*(vscf_hkdf_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_hkdf_t /*9*/* hkdf_ctx = *(vscf_hkdf_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_hkdf_alg_id(hkdf_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_hkdf_t /*9*/* hkdf_ctx = *(vscf_hkdf_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_hkdf_produce_alg_info(hkdf_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_hkdf_t /*9*/* hkdf_ctx = *(vscf_hkdf_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_hkdf_restore_alg_info(hkdf_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1derive (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jint jkeyLen) {
    // Cast class context
    vscf_hkdf_t /*9*/* hkdf_ctx = *(vscf_hkdf_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(jkeyLen);

    vscf_hkdf_derive(hkdf_ctx /*a1*/, data /*a3*/, jkeyLen /*a9*/, key /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), (jbyte*) vsc_buffer_bytes(key));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(key);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsalt, jint jiterationCount) {
    // Cast class context
    vscf_hkdf_t /*9*/* hkdf_ctx = *(vscf_hkdf_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* salt_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsalt, NULL);
    vsc_data_t salt = vsc_data(salt_arr, (*jenv)->GetArrayLength(jenv, jsalt));

    vscf_hkdf_reset(hkdf_ctx /*a1*/, salt /*a3*/, jiterationCount /*a9*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsalt, (jbyte*) salt_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hkdf_1setInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jinfo) {
    // Cast class context
    vscf_hkdf_t /*9*/* hkdf_ctx = *(vscf_hkdf_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* info_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinfo, NULL);
    vsc_data_t info = vsc_data(info_arr, (*jenv)->GetArrayLength(jenv, jinfo));

    vscf_hkdf_set_info(hkdf_ctx /*a1*/, info /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jinfo, (jbyte*) info_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        VSCF_ASSERT("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        VSCF_ASSERT("Class 'Hash' has no field 'cCtx'.");
    }
    jlong hash_c_ctx = (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);
    vscf_impl_t */*6*/ hash = *(vscf_impl_t */*6*/*) &hash_c_ctx;

    vscf_kdf1_release_hash((vscf_kdf1_t /*9*/ *) c_ctx);
    vscf_kdf1_use_hash((vscf_kdf1_t /*9*/ *) c_ctx, hash);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_kdf1_t **)&c_ctx = vscf_kdf1_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_kdf1_delete(*(vscf_kdf1_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_kdf1_t /*9*/* kdf1_ctx = *(vscf_kdf1_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_kdf1_alg_id(kdf1_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_kdf1_t /*9*/* kdf1_ctx = *(vscf_kdf1_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_kdf1_produce_alg_info(kdf1_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_kdf1_t /*9*/* kdf1_ctx = *(vscf_kdf1_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_kdf1_restore_alg_info(kdf1_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf1_1derive (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jint jkeyLen) {
    // Cast class context
    vscf_kdf1_t /*9*/* kdf1_ctx = *(vscf_kdf1_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(jkeyLen);

    vscf_kdf1_derive(kdf1_ctx /*a1*/, data /*a3*/, jkeyLen /*a9*/, key /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), (jbyte*) vsc_buffer_bytes(key));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(key);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        VSCF_ASSERT("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        VSCF_ASSERT("Class 'Hash' has no field 'cCtx'.");
    }
    jlong hash_c_ctx = (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);
    vscf_impl_t */*6*/ hash = *(vscf_impl_t */*6*/*) &hash_c_ctx;

    vscf_kdf2_release_hash((vscf_kdf2_t /*9*/ *) c_ctx);
    vscf_kdf2_use_hash((vscf_kdf2_t /*9*/ *) c_ctx, hash);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_kdf2_t **)&c_ctx = vscf_kdf2_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_kdf2_delete(*(vscf_kdf2_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_kdf2_t /*9*/* kdf2_ctx = *(vscf_kdf2_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_kdf2_alg_id(kdf2_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_kdf2_t /*9*/* kdf2_ctx = *(vscf_kdf2_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_kdf2_produce_alg_info(kdf2_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_kdf2_t /*9*/* kdf2_ctx = *(vscf_kdf2_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_kdf2_restore_alg_info(kdf2_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_kdf2_1derive (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jint jkeyLen) {
    // Cast class context
    vscf_kdf2_t /*9*/* kdf2_ctx = *(vscf_kdf2_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(jkeyLen);

    vscf_kdf2_derive(kdf2_ctx /*a1*/, data /*a3*/, jkeyLen /*a9*/, key /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), (jbyte*) vsc_buffer_bytes(key));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(key);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1setupSourceByte (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyte jbyteSource) {
    // Cast class context
    vscf_fake_random_t /*9*/* fake_random_ctx = *(vscf_fake_random_t /*9*/**) &c_ctx;

    vscf_fake_random_setup_source_byte(fake_random_ctx /*a1*/, jbyteSource /*a9*/);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1setupSourceData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdataSource) {
    // Cast class context
    vscf_fake_random_t /*9*/* fake_random_ctx = *(vscf_fake_random_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_source_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdataSource, NULL);
    vsc_data_t data_source = vsc_data(data_source_arr, (*jenv)->GetArrayLength(jenv, jdataSource));

    vscf_fake_random_setup_source_data(fake_random_ctx /*a1*/, data_source /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdataSource, (jbyte*) data_source_arr, 0);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_fake_random_t **)&c_ctx = vscf_fake_random_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_fake_random_delete(*(vscf_fake_random_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1random (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_fake_random_t /*9*/* fake_random_ctx = *(vscf_fake_random_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *data = vsc_buffer_new_with_capacity(jdataLen);

    vscf_status_t status = vscf_fake_random_random(fake_random_ctx /*a1*/, jdataLen /*a9*/, data /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), (jbyte*) vsc_buffer_bytes(data));
    // Free resources
    vsc_buffer_delete(data);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1reseed (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_fake_random_t /*9*/* fake_random_ctx = *(vscf_fake_random_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_fake_random_reseed(fake_random_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1isStrong (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_fake_random_t /*9*/* fake_random_ctx = *(vscf_fake_random_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_fake_random_is_strong(fake_random_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_fakeRandom_1gather (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Cast class context
    vscf_fake_random_t /*9*/* fake_random_ctx = *(vscf_fake_random_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(jlen);

    vscf_status_t status = vscf_fake_random_gather(fake_random_ctx /*a1*/, jlen /*a9*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setHmac (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhmac) {
    jclass hmac_cls = (*jenv)->GetObjectClass(jenv, jhmac);
    if (NULL == hmac_cls) {
        VSCF_ASSERT("Class Mac not found.");
    }
    jfieldID hmac_fidCtx = (*jenv)->GetFieldID(jenv, hmac_cls, "cCtx", "J");
    if (NULL == hmac_fidCtx) {
        VSCF_ASSERT("Class 'Mac' has no field 'cCtx'.");
    }
    jlong hmac_c_ctx = (*jenv)->GetLongField(jenv, jhmac, hmac_fidCtx);
    vscf_impl_t */*6*/ hmac = *(vscf_impl_t */*6*/*) &hmac_c_ctx;

    vscf_pkcs5_pbkdf2_release_hmac((vscf_pkcs5_pbkdf2_t /*9*/ *) c_ctx);
    vscf_pkcs5_pbkdf2_use_hmac((vscf_pkcs5_pbkdf2_t /*9*/ *) c_ctx, hmac);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_pkcs5_pbkdf2_t /*9*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*9*/**) &c_ctx;

    vscf_pkcs5_pbkdf2_setup_defaults(pkcs5_pbkdf2_ctx /*a1*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_pkcs5_pbkdf2_t **)&c_ctx = vscf_pkcs5_pbkdf2_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pkcs5_pbkdf2_delete(*(vscf_pkcs5_pbkdf2_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_pkcs5_pbkdf2_t /*9*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_pkcs5_pbkdf2_alg_id(pkcs5_pbkdf2_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_pkcs5_pbkdf2_t /*9*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_pkcs5_pbkdf2_produce_alg_info(pkcs5_pbkdf2_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_pkcs5_pbkdf2_t /*9*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_pkcs5_pbkdf2_restore_alg_info(pkcs5_pbkdf2_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1derive (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata, jint jkeyLen) {
    // Cast class context
    vscf_pkcs5_pbkdf2_t /*9*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(jkeyLen);

    vscf_pkcs5_pbkdf2_derive(pkcs5_pbkdf2_ctx /*a1*/, data /*a3*/, jkeyLen /*a9*/, key /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), (jbyte*) vsc_buffer_bytes(key));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(key);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jsalt, jint jiterationCount) {
    // Cast class context
    vscf_pkcs5_pbkdf2_t /*9*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* salt_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsalt, NULL);
    vsc_data_t salt = vsc_data(salt_arr, (*jenv)->GetArrayLength(jenv, jsalt));

    vscf_pkcs5_pbkdf2_reset(pkcs5_pbkdf2_ctx /*a1*/, salt /*a3*/, jiterationCount /*a9*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jsalt, (jbyte*) salt_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbkdf2_1setInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jinfo) {
    // Cast class context
    vscf_pkcs5_pbkdf2_t /*9*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* info_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinfo, NULL);
    vsc_data_t info = vsc_data(info_arr, (*jenv)->GetArrayLength(jenv, jinfo));

    vscf_pkcs5_pbkdf2_set_info(pkcs5_pbkdf2_ctx /*a1*/, info /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jinfo, (jbyte*) info_arr, 0);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1setKdf (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkdf) {
    jclass kdf_cls = (*jenv)->GetObjectClass(jenv, jkdf);
    if (NULL == kdf_cls) {
        VSCF_ASSERT("Class SaltedKdf not found.");
    }
    jfieldID kdf_fidCtx = (*jenv)->GetFieldID(jenv, kdf_cls, "cCtx", "J");
    if (NULL == kdf_fidCtx) {
        VSCF_ASSERT("Class 'SaltedKdf' has no field 'cCtx'.");
    }
    jlong kdf_c_ctx = (*jenv)->GetLongField(jenv, jkdf, kdf_fidCtx);
    vscf_impl_t */*6*/ kdf = *(vscf_impl_t */*6*/*) &kdf_c_ctx;

    vscf_pkcs5_pbes2_release_kdf((vscf_pkcs5_pbes2_t /*9*/ *) c_ctx);
    vscf_pkcs5_pbes2_use_kdf((vscf_pkcs5_pbes2_t /*9*/ *) c_ctx, kdf);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1setCipher (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jcipher) {
    jclass cipher_cls = (*jenv)->GetObjectClass(jenv, jcipher);
    if (NULL == cipher_cls) {
        VSCF_ASSERT("Class Cipher not found.");
    }
    jfieldID cipher_fidCtx = (*jenv)->GetFieldID(jenv, cipher_cls, "cCtx", "J");
    if (NULL == cipher_fidCtx) {
        VSCF_ASSERT("Class 'Cipher' has no field 'cCtx'.");
    }
    jlong cipher_c_ctx = (*jenv)->GetLongField(jenv, jcipher, cipher_fidCtx);
    vscf_impl_t */*6*/ cipher = *(vscf_impl_t */*6*/*) &cipher_c_ctx;

    vscf_pkcs5_pbes2_release_cipher((vscf_pkcs5_pbes2_t /*9*/ *) c_ctx);
    vscf_pkcs5_pbes2_use_cipher((vscf_pkcs5_pbes2_t /*9*/ *) c_ctx, cipher);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1reset (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpwd) {
    // Cast class context
    vscf_pkcs5_pbes2_t /*9*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* pwd_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpwd, NULL);
    vsc_data_t pwd = vsc_data(pwd_arr, (*jenv)->GetArrayLength(jenv, jpwd));

    vscf_pkcs5_pbes2_reset(pkcs5_pbes2_ctx /*a1*/, pwd /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpwd, (jbyte*) pwd_arr, 0);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_pkcs5_pbes2_t **)&c_ctx = vscf_pkcs5_pbes2_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pkcs5_pbes2_delete(*(vscf_pkcs5_pbes2_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_pkcs5_pbes2_t /*9*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_pkcs5_pbes2_alg_id(pkcs5_pbes2_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_pkcs5_pbes2_t /*9*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_pkcs5_pbes2_produce_alg_info(pkcs5_pbes2_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_pkcs5_pbes2_t /*9*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_pkcs5_pbes2_restore_alg_info(pkcs5_pbes2_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_pkcs5_pbes2_t /*9*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs5_pbes2_encrypted_len((vscf_pkcs5_pbes2_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_pkcs5_pbes2_encrypt(pkcs5_pbes2_ctx /*a1*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_pkcs5_pbes2_t /*9*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_pkcs5_pbes2_encrypted_len(pkcs5_pbes2_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1preciseEncryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_pkcs5_pbes2_t /*9*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_pkcs5_pbes2_precise_encrypted_len(pkcs5_pbes2_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_pkcs5_pbes2_t /*9*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs5_pbes2_decrypted_len((vscf_pkcs5_pbes2_t /*9*/ *) c_ctx /*3*/, data.len/*a*/));

    vscf_status_t status = vscf_pkcs5_pbes2_decrypt(pkcs5_pbes2_ctx /*a1*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs5Pbes2_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_pkcs5_pbes2_t /*9*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_pkcs5_pbes2_decrypted_len(pkcs5_pbes2_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1resetSeed (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jseed) {
    // Cast class context
    vscf_seed_entropy_source_t /*9*/* seed_entropy_source_ctx = *(vscf_seed_entropy_source_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* seed_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jseed, NULL);
    vsc_data_t seed = vsc_data(seed_arr, (*jenv)->GetArrayLength(jenv, jseed));

    vscf_seed_entropy_source_reset_seed(seed_entropy_source_ctx /*a1*/, seed /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jseed, (jbyte*) seed_arr, 0);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_seed_entropy_source_t **)&c_ctx = vscf_seed_entropy_source_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_seed_entropy_source_delete(*(vscf_seed_entropy_source_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1isStrong (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_seed_entropy_source_t /*9*/* seed_entropy_source_ctx = *(vscf_seed_entropy_source_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_seed_entropy_source_is_strong(seed_entropy_source_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_seedEntropySource_1gather (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jlen) {
    // Cast class context
    vscf_seed_entropy_source_t /*9*/* seed_entropy_source_ctx = *(vscf_seed_entropy_source_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(jlen);

    vscf_status_t status = vscf_seed_entropy_source_gather(seed_entropy_source_ctx /*a1*/, jlen /*a9*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1resetKeyMaterial (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jkeyMaterial) {
    // Cast class context
    vscf_key_material_rng_t /*9*/* key_material_rng_ctx = *(vscf_key_material_rng_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* key_material_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkeyMaterial, NULL);
    vsc_data_t key_material = vsc_data(key_material_arr, (*jenv)->GetArrayLength(jenv, jkeyMaterial));

    vscf_key_material_rng_reset_key_material(key_material_rng_ctx /*a1*/, key_material /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jkeyMaterial, (jbyte*) key_material_arr, 0);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_key_material_rng_t **)&c_ctx = vscf_key_material_rng_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_material_rng_delete(*(vscf_key_material_rng_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1random (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_key_material_rng_t /*9*/* key_material_rng_ctx = *(vscf_key_material_rng_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *data = vsc_buffer_new_with_capacity(jdataLen);

    vscf_status_t status = vscf_key_material_rng_random(key_material_rng_ctx /*a1*/, jdataLen /*a9*/, data /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), (jbyte*) vsc_buffer_bytes(data));
    // Free resources
    vsc_buffer_delete(data);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyMaterialRng_1reseed (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_material_rng_t /*9*/* key_material_rng_ctx = *(vscf_key_material_rng_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_key_material_rng_reseed(key_material_rng_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1data (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_public_key_t /*9*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_raw_public_key_data(raw_public_key_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_raw_public_key_t **)&c_ctx = vscf_raw_public_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_raw_public_key_delete(*(vscf_raw_public_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_public_key_t /*9*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_raw_public_key_alg_id(raw_public_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_public_key_t /*9*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_raw_public_key_alg_info(raw_public_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_public_key_t /*9*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_raw_public_key_len(raw_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_public_key_t /*9*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_raw_public_key_bitlen(raw_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPublicKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_public_key_t /*9*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_raw_public_key_is_valid(raw_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1data (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_raw_private_key_data(raw_private_key_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1hasPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_raw_private_key_has_public_key(raw_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1setPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawPublicKey) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == raw_public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID raw_public_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_public_key_cls, "cCtx", "J");
    if (NULL == raw_public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong raw_public_key_c_ctx = (*jenv)->GetLongField(jenv, jrawPublicKey, raw_public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ raw_public_key = *(vscf_raw_public_key_t * /*7*/*) &raw_public_key_c_ctx;

    //Shallow copy
    vscf_raw_public_key_t * /*7*/ raw_public_key_copy = vscf_raw_public_key_shallow_copy(raw_public_key);
    vscf_raw_private_key_set_public_key(raw_private_key_ctx /*a1*/, &raw_public_key_copy /*a5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1getPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;

    const vscf_raw_public_key_t * /*7*/ proxyResult = vscf_raw_private_key_get_public_key(raw_private_key_ctx /*a1*/);
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }
    vscf_raw_public_key_shallow_copy((vscf_raw_public_key_t * /*7*/) proxyResult);
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_raw_private_key_t **)&c_ctx = vscf_raw_private_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_raw_private_key_delete(*(vscf_raw_private_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_raw_private_key_alg_id(raw_private_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_raw_private_key_alg_info(raw_private_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_raw_private_key_len(raw_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_raw_private_key_bitlen(raw_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_raw_private_key_is_valid(raw_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_rawPrivateKey_1extractPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_raw_private_key_t /*9*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_raw_private_key_extract_public_key(raw_private_key_ctx /*a1*/);
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1setAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Writer) {
    jclass asn1_writer_cls = (*jenv)->GetObjectClass(jenv, jasn1Writer);
    if (NULL == asn1_writer_cls) {
        VSCF_ASSERT("Class Asn1Writer not found.");
    }
    jfieldID asn1_writer_fidCtx = (*jenv)->GetFieldID(jenv, asn1_writer_cls, "cCtx", "J");
    if (NULL == asn1_writer_fidCtx) {
        VSCF_ASSERT("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    jlong asn1_writer_c_ctx = (*jenv)->GetLongField(jenv, jasn1Writer, asn1_writer_fidCtx);
    vscf_impl_t */*6*/ asn1_writer = *(vscf_impl_t */*6*/*) &asn1_writer_c_ctx;

    vscf_pkcs8_serializer_release_asn1_writer((vscf_pkcs8_serializer_t /*9*/ *) c_ctx);
    vscf_pkcs8_serializer_use_asn1_writer((vscf_pkcs8_serializer_t /*9*/ *) c_ctx, asn1_writer);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_pkcs8_serializer_t /*9*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*9*/**) &c_ctx;

    vscf_pkcs8_serializer_setup_defaults(pkcs8_serializer_ctx /*a1*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePublicKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_pkcs8_serializer_t /*9*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ public_key = *(vscf_raw_public_key_t * /*7*/*) &public_key_c_ctx;

    jint ret = (jint) vscf_pkcs8_serializer_serialize_public_key_inplace(pkcs8_serializer_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return 0;
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePrivateKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_pkcs8_serializer_t /*9*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t * /*7*/ private_key = *(vscf_raw_private_key_t * /*7*/*) &private_key_c_ctx;

    jint ret = (jint) vscf_pkcs8_serializer_serialize_private_key_inplace(pkcs8_serializer_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return 0;
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_pkcs8_serializer_t **)&c_ctx = vscf_pkcs8_serializer_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pkcs8_serializer_delete(*(vscf_pkcs8_serializer_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializedPublicKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_pkcs8_serializer_t /*9*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ public_key = *(vscf_raw_public_key_t * /*7*/*) &public_key_c_ctx;

    jint ret = (jint) vscf_pkcs8_serializer_serialized_public_key_len(pkcs8_serializer_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_pkcs8_serializer_t /*9*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ public_key = *(vscf_raw_public_key_t * /*7*/*) &public_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs8_serializer_serialized_public_key_len((vscf_pkcs8_serializer_t /*9*/ *) c_ctx /*3*/, public_key/*a*/));

    vscf_status_t status = vscf_pkcs8_serializer_serialize_public_key(pkcs8_serializer_ctx /*a1*/, public_key /*a6*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializedPrivateKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_pkcs8_serializer_t /*9*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t * /*7*/ private_key = *(vscf_raw_private_key_t * /*7*/*) &private_key_c_ctx;

    jint ret = (jint) vscf_pkcs8_serializer_serialized_private_key_len(pkcs8_serializer_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pkcs8Serializer_1serializePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_pkcs8_serializer_t /*9*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t * /*7*/ private_key = *(vscf_raw_private_key_t * /*7*/*) &private_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs8_serializer_serialized_private_key_len((vscf_pkcs8_serializer_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_pkcs8_serializer_serialize_private_key(pkcs8_serializer_ctx /*a1*/, private_key /*a6*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1setAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Writer) {
    jclass asn1_writer_cls = (*jenv)->GetObjectClass(jenv, jasn1Writer);
    if (NULL == asn1_writer_cls) {
        VSCF_ASSERT("Class Asn1Writer not found.");
    }
    jfieldID asn1_writer_fidCtx = (*jenv)->GetFieldID(jenv, asn1_writer_cls, "cCtx", "J");
    if (NULL == asn1_writer_fidCtx) {
        VSCF_ASSERT("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    jlong asn1_writer_c_ctx = (*jenv)->GetLongField(jenv, jasn1Writer, asn1_writer_fidCtx);
    vscf_impl_t */*6*/ asn1_writer = *(vscf_impl_t */*6*/*) &asn1_writer_c_ctx;

    vscf_sec1_serializer_release_asn1_writer((vscf_sec1_serializer_t /*9*/ *) c_ctx);
    vscf_sec1_serializer_use_asn1_writer((vscf_sec1_serializer_t /*9*/ *) c_ctx, asn1_writer);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_sec1_serializer_t /*9*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*9*/**) &c_ctx;

    vscf_sec1_serializer_setup_defaults(sec1_serializer_ctx /*a1*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializePublicKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_sec1_serializer_t /*9*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ public_key = *(vscf_raw_public_key_t * /*7*/*) &public_key_c_ctx;

    jint ret = (jint) vscf_sec1_serializer_serialize_public_key_inplace(sec1_serializer_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return 0;
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializePrivateKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_sec1_serializer_t /*9*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t * /*7*/ private_key = *(vscf_raw_private_key_t * /*7*/*) &private_key_c_ctx;

    jint ret = (jint) vscf_sec1_serializer_serialize_private_key_inplace(sec1_serializer_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return 0;
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_sec1_serializer_t **)&c_ctx = vscf_sec1_serializer_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_sec1_serializer_delete(*(vscf_sec1_serializer_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializedPublicKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_sec1_serializer_t /*9*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ public_key = *(vscf_raw_public_key_t * /*7*/*) &public_key_c_ctx;

    jint ret = (jint) vscf_sec1_serializer_serialized_public_key_len(sec1_serializer_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_sec1_serializer_t /*9*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ public_key = *(vscf_raw_public_key_t * /*7*/*) &public_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_sec1_serializer_serialized_public_key_len((vscf_sec1_serializer_t /*9*/ *) c_ctx /*3*/, public_key/*a*/));

    vscf_status_t status = vscf_sec1_serializer_serialize_public_key(sec1_serializer_ctx /*a1*/, public_key /*a6*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializedPrivateKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_sec1_serializer_t /*9*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t * /*7*/ private_key = *(vscf_raw_private_key_t * /*7*/*) &private_key_c_ctx;

    jint ret = (jint) vscf_sec1_serializer_serialized_private_key_len(sec1_serializer_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_sec1Serializer_1serializePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_sec1_serializer_t /*9*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t * /*7*/ private_key = *(vscf_raw_private_key_t * /*7*/*) &private_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_sec1_serializer_serialized_private_key_len((vscf_sec1_serializer_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_sec1_serializer_serialize_private_key(sec1_serializer_ctx /*a1*/, private_key /*a6*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1setAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Writer) {
    jclass asn1_writer_cls = (*jenv)->GetObjectClass(jenv, jasn1Writer);
    if (NULL == asn1_writer_cls) {
        VSCF_ASSERT("Class Asn1Writer not found.");
    }
    jfieldID asn1_writer_fidCtx = (*jenv)->GetFieldID(jenv, asn1_writer_cls, "cCtx", "J");
    if (NULL == asn1_writer_fidCtx) {
        VSCF_ASSERT("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    jlong asn1_writer_c_ctx = (*jenv)->GetLongField(jenv, jasn1Writer, asn1_writer_fidCtx);
    vscf_impl_t */*6*/ asn1_writer = *(vscf_impl_t */*6*/*) &asn1_writer_c_ctx;

    vscf_key_asn1_serializer_release_asn1_writer((vscf_key_asn1_serializer_t /*9*/ *) c_ctx);
    vscf_key_asn1_serializer_use_asn1_writer((vscf_key_asn1_serializer_t /*9*/ *) c_ctx, asn1_writer);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_asn1_serializer_t /*9*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*9*/**) &c_ctx;

    vscf_key_asn1_serializer_setup_defaults(key_asn1_serializer_ctx /*a1*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializePublicKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_asn1_serializer_t /*9*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ public_key = *(vscf_raw_public_key_t * /*7*/*) &public_key_c_ctx;

    jint ret = (jint) vscf_key_asn1_serializer_serialize_public_key_inplace(key_asn1_serializer_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return 0;
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializePrivateKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_asn1_serializer_t /*9*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t * /*7*/ private_key = *(vscf_raw_private_key_t * /*7*/*) &private_key_c_ctx;

    jint ret = (jint) vscf_key_asn1_serializer_serialize_private_key_inplace(key_asn1_serializer_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return 0;
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_key_asn1_serializer_t **)&c_ctx = vscf_key_asn1_serializer_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_asn1_serializer_delete(*(vscf_key_asn1_serializer_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializedPublicKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_key_asn1_serializer_t /*9*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ public_key = *(vscf_raw_public_key_t * /*7*/*) &public_key_c_ctx;

    jint ret = (jint) vscf_key_asn1_serializer_serialized_public_key_len(key_asn1_serializer_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_key_asn1_serializer_t /*9*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass public_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ public_key = *(vscf_raw_public_key_t * /*7*/*) &public_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_key_asn1_serializer_serialized_public_key_len((vscf_key_asn1_serializer_t /*9*/ *) c_ctx /*3*/, public_key/*a*/));

    vscf_status_t status = vscf_key_asn1_serializer_serialize_public_key(key_asn1_serializer_ctx /*a1*/, public_key /*a6*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializedPrivateKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_key_asn1_serializer_t /*9*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t * /*7*/ private_key = *(vscf_raw_private_key_t * /*7*/*) &private_key_c_ctx;

    jint ret = (jint) vscf_key_asn1_serializer_serialized_private_key_len(key_asn1_serializer_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Serializer_1serializePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_key_asn1_serializer_t /*9*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass private_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_raw_private_key_t * /*7*/ private_key = *(vscf_raw_private_key_t * /*7*/*) &private_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_key_asn1_serializer_serialized_private_key_len((vscf_key_asn1_serializer_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_key_asn1_serializer_serialize_private_key(key_asn1_serializer_ctx /*a1*/, private_key /*a6*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1setAsn1Reader (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Reader) {
    jclass asn1_reader_cls = (*jenv)->GetObjectClass(jenv, jasn1Reader);
    if (NULL == asn1_reader_cls) {
        VSCF_ASSERT("Class Asn1Reader not found.");
    }
    jfieldID asn1_reader_fidCtx = (*jenv)->GetFieldID(jenv, asn1_reader_cls, "cCtx", "J");
    if (NULL == asn1_reader_fidCtx) {
        VSCF_ASSERT("Class 'Asn1Reader' has no field 'cCtx'.");
    }
    jlong asn1_reader_c_ctx = (*jenv)->GetLongField(jenv, jasn1Reader, asn1_reader_fidCtx);
    vscf_impl_t */*6*/ asn1_reader = *(vscf_impl_t */*6*/*) &asn1_reader_c_ctx;

    vscf_key_asn1_deserializer_release_asn1_reader((vscf_key_asn1_deserializer_t /*9*/ *) c_ctx);
    vscf_key_asn1_deserializer_use_asn1_reader((vscf_key_asn1_deserializer_t /*9*/ *) c_ctx, asn1_reader);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_key_asn1_deserializer_t /*9*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*9*/**) &c_ctx;

    vscf_key_asn1_deserializer_setup_defaults(key_asn1_deserializer_ctx /*a1*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1deserializePublicKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_asn1_deserializer_t /*9*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*9*/**) &c_ctx;

    const vscf_raw_public_key_t * /*7*/ proxyResult = vscf_key_asn1_deserializer_deserialize_public_key_inplace(key_asn1_deserializer_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1deserializePrivateKeyInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_asn1_deserializer_t /*9*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*9*/**) &c_ctx;

    const vscf_raw_private_key_t * /*7*/ proxyResult = vscf_key_asn1_deserializer_deserialize_private_key_inplace(key_asn1_deserializer_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_key_asn1_deserializer_t **)&c_ctx = vscf_key_asn1_deserializer_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_key_asn1_deserializer_delete(*(vscf_key_asn1_deserializer_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1deserializePublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpublicKeyData) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_asn1_deserializer_t /*9*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* public_key_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpublicKeyData, NULL);
    vsc_data_t public_key_data = vsc_data(public_key_data_arr, (*jenv)->GetArrayLength(jenv, jpublicKeyData));

    const vscf_raw_public_key_t * /*7*/ proxyResult = vscf_key_asn1_deserializer_deserialize_public_key(key_asn1_deserializer_ctx /*a1*/, public_key_data /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jpublicKeyData, (jbyte*) public_key_data_arr, 0);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_keyAsn1Deserializer_1deserializePrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jprivateKeyData) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_key_asn1_deserializer_t /*9*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* private_key_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jprivateKeyData, NULL);
    vsc_data_t private_key_data = vsc_data(private_key_data_arr, (*jenv)->GetArrayLength(jenv, jprivateKeyData));

    const vscf_raw_private_key_t * /*7*/ proxyResult = vscf_key_asn1_deserializer_deserialize_private_key(key_asn1_deserializer_ctx /*a1*/, private_key_data /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jprivateKeyData, (jbyte*) private_key_data_arr, 0);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_ed25519_release_random((vscf_ed25519_t /*9*/ *) c_ctx);
    vscf_ed25519_use_random((vscf_ed25519_t /*9*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1setEcies (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jecies) {
    jclass ecies_cls = (*jenv)->GetObjectClass(jenv, jecies);
    if (NULL == ecies_cls) {
        VSCF_ASSERT("Class Ecies not found.");
    }
    jfieldID ecies_fidCtx = (*jenv)->GetFieldID(jenv, ecies_cls, "cCtx", "J");
    if (NULL == ecies_fidCtx) {
        VSCF_ASSERT("Class 'Ecies' has no field 'cCtx'.");
    }
    jlong ecies_c_ctx = (*jenv)->GetLongField(jenv, jecies, ecies_fidCtx);
    vscf_ecies_t */*5*/ ecies = *(vscf_ecies_t */*5*/*) &ecies_c_ctx;

    vscf_ed25519_release_ecies((vscf_ed25519_t /*9*/ *) c_ctx);
    vscf_ed25519_use_ecies((vscf_ed25519_t /*9*/ *) c_ctx, ecies);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_ed25519_setup_defaults(ed25519_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1generateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ed25519_generate_key(ed25519_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_ed25519_t **)&c_ctx = vscf_ed25519_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ed25519_delete(*(vscf_ed25519_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_ed25519_alg_id(ed25519_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ed25519_produce_alg_info(ed25519_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_ed25519_restore_alg_info(ed25519_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ed25519_generate_ephemeral_key(ed25519_ctx /*a1*/, key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ raw_key = *(vscf_raw_public_key_t * /*7*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ed25519_import_public_key(ed25519_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    const vscf_raw_public_key_t */*5*/ proxyResult = vscf_ed25519_export_public_key(ed25519_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_private_key_t */*5*/ raw_key = *(vscf_raw_private_key_t */*5*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_ed25519_import_private_key(ed25519_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    const vscf_raw_private_key_t */*5*/ proxyResult = vscf_ed25519_export_private_key(ed25519_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1canEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_ed25519_can_encrypt(ed25519_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jint ret = (jint) vscf_ed25519_encrypted_len(ed25519_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jbyteArray jdata) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ed25519_encrypted_len((vscf_ed25519_t /*9*/ *) c_ctx /*3*/, public_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_ed25519_encrypt(ed25519_ctx /*a1*/, public_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1canDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_ed25519_can_decrypt(ed25519_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_ed25519_decrypted_len(ed25519_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jbyteArray jdata) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ed25519_decrypted_len((vscf_ed25519_t /*9*/ *) c_ctx /*3*/, private_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_ed25519_decrypt(ed25519_ctx /*a1*/, private_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1canSign (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_ed25519_can_sign(ed25519_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_ed25519_signature_len(ed25519_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1signHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jobject jhashId, jbyteArray jdigest) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_ed25519_signature_len((vscf_ed25519_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_ed25519_sign_hash(ed25519_ctx /*a1*/, private_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), (jbyte*) vsc_buffer_bytes(signature));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1canVerify (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_ed25519_can_verify(ed25519_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1verifyHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jobject jhashId, jbyteArray jdigest, jbyteArray jsignature) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
    vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

    jboolean ret = (jboolean) vscf_ed25519_verify_hash(ed25519_ctx /*a1*/, public_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1computeSharedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jobject jprivateKey) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_ed25519_shared_key_len((vscf_ed25519_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_ed25519_compute_shared_key(ed25519_ctx /*a1*/, public_key /*a6*/, private_key /*a6*/, shared_key /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
    // Free resources
    vsc_buffer_delete(shared_key);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_ed25519_1sharedKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Cast class context
    vscf_ed25519_t /*9*/* ed25519_ctx = *(vscf_ed25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    jint ret = (jint) vscf_ed25519_shared_key_len(ed25519_ctx /*a1*/, key /*a6*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_curve25519_release_random((vscf_curve25519_t /*9*/ *) c_ctx);
    vscf_curve25519_use_random((vscf_curve25519_t /*9*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1setEcies (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jecies) {
    jclass ecies_cls = (*jenv)->GetObjectClass(jenv, jecies);
    if (NULL == ecies_cls) {
        VSCF_ASSERT("Class Ecies not found.");
    }
    jfieldID ecies_fidCtx = (*jenv)->GetFieldID(jenv, ecies_cls, "cCtx", "J");
    if (NULL == ecies_fidCtx) {
        VSCF_ASSERT("Class 'Ecies' has no field 'cCtx'.");
    }
    jlong ecies_c_ctx = (*jenv)->GetLongField(jenv, jecies, ecies_fidCtx);
    vscf_ecies_t */*5*/ ecies = *(vscf_ecies_t */*5*/*) &ecies_c_ctx;

    vscf_curve25519_release_ecies((vscf_curve25519_t /*9*/ *) c_ctx);
    vscf_curve25519_use_ecies((vscf_curve25519_t /*9*/ *) c_ctx, ecies);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_curve25519_setup_defaults(curve25519_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1generateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_curve25519_generate_key(curve25519_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_curve25519_t **)&c_ctx = vscf_curve25519_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_curve25519_delete(*(vscf_curve25519_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_curve25519_alg_id(curve25519_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_curve25519_produce_alg_info(curve25519_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_curve25519_restore_alg_info(curve25519_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_curve25519_generate_ephemeral_key(curve25519_ctx /*a1*/, key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ raw_key = *(vscf_raw_public_key_t * /*7*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_curve25519_import_public_key(curve25519_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    const vscf_raw_public_key_t */*5*/ proxyResult = vscf_curve25519_export_public_key(curve25519_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_private_key_t */*5*/ raw_key = *(vscf_raw_private_key_t */*5*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_curve25519_import_private_key(curve25519_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    const vscf_raw_private_key_t */*5*/ proxyResult = vscf_curve25519_export_private_key(curve25519_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1canEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_curve25519_can_encrypt(curve25519_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jint ret = (jint) vscf_curve25519_encrypted_len(curve25519_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jbyteArray jdata) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_curve25519_encrypted_len((vscf_curve25519_t /*9*/ *) c_ctx /*3*/, public_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_curve25519_encrypt(curve25519_ctx /*a1*/, public_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1canDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_curve25519_can_decrypt(curve25519_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_curve25519_decrypted_len(curve25519_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jbyteArray jdata) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_curve25519_decrypted_len((vscf_curve25519_t /*9*/ *) c_ctx /*3*/, private_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_curve25519_decrypt(curve25519_ctx /*a1*/, private_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1computeSharedKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jobject jprivateKey) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_curve25519_shared_key_len((vscf_curve25519_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_curve25519_compute_shared_key(curve25519_ctx /*a1*/, public_key /*a6*/, private_key /*a6*/, shared_key /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
    // Free resources
    vsc_buffer_delete(shared_key);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_curve25519_1sharedKeyLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Cast class context
    vscf_curve25519_t /*9*/* curve25519_ctx = *(vscf_curve25519_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    jint ret = (jint) vscf_curve25519_shared_key_len(curve25519_ctx /*a1*/, key /*a6*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_falcon_release_random((vscf_falcon_t /*9*/ *) c_ctx);
    vscf_falcon_use_random((vscf_falcon_t /*9*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_falcon_setup_defaults(falcon_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1generateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_falcon_generate_key(falcon_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_falcon_t **)&c_ctx = vscf_falcon_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_falcon_delete(*(vscf_falcon_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_falcon_alg_id(falcon_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_falcon_produce_alg_info(falcon_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_falcon_restore_alg_info(falcon_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_falcon_generate_ephemeral_key(falcon_ctx /*a1*/, key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ raw_key = *(vscf_raw_public_key_t * /*7*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_falcon_import_public_key(falcon_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    const vscf_raw_public_key_t */*5*/ proxyResult = vscf_falcon_export_public_key(falcon_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_private_key_t */*5*/ raw_key = *(vscf_raw_private_key_t */*5*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_falcon_import_private_key(falcon_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    const vscf_raw_private_key_t */*5*/ proxyResult = vscf_falcon_export_private_key(falcon_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1canSign (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_falcon_can_sign(falcon_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_falcon_signature_len(falcon_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1signHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jobject jhashId, jbyteArray jdigest) {
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_falcon_signature_len((vscf_falcon_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_falcon_sign_hash(falcon_ctx /*a1*/, private_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), (jbyte*) vsc_buffer_bytes(signature));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1canVerify (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_falcon_can_verify(falcon_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_falcon_1verifyHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jobject jhashId, jbyteArray jdigest, jbyteArray jsignature) {
    // Cast class context
    vscf_falcon_t /*9*/* falcon_ctx = *(vscf_falcon_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
    vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

    jboolean ret = (jboolean) vscf_falcon_verify_hash(falcon_ctx /*a1*/, public_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_round5_release_random((vscf_round5_t /*9*/ *) c_ctx);
    vscf_round5_use_random((vscf_round5_t /*9*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_round5_setup_defaults(round5_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1generateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_round5_generate_key(round5_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_round5_t **)&c_ctx = vscf_round5_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_round5_delete(*(vscf_round5_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_round5_alg_id(round5_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_round5_produce_alg_info(round5_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_round5_restore_alg_info(round5_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_round5_generate_ephemeral_key(round5_ctx /*a1*/, key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ raw_key = *(vscf_raw_public_key_t * /*7*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_round5_import_public_key(round5_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    const vscf_raw_public_key_t */*5*/ proxyResult = vscf_round5_export_public_key(round5_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_private_key_t */*5*/ raw_key = *(vscf_raw_private_key_t */*5*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_round5_import_private_key(round5_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    const vscf_raw_private_key_t */*5*/ proxyResult = vscf_round5_export_private_key(round5_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1canEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_round5_can_encrypt(round5_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jint ret = (jint) vscf_round5_encrypted_len(round5_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jbyteArray jdata) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_round5_encrypted_len((vscf_round5_t /*9*/ *) c_ctx /*3*/, public_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_round5_encrypt(round5_ctx /*a1*/, public_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1canDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_round5_can_decrypt(round5_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_round5_decrypted_len(round5_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_round5_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jbyteArray jdata) {
    // Cast class context
    vscf_round5_t /*9*/* round5_ctx = *(vscf_round5_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_round5_decrypted_len((vscf_round5_t /*9*/ *) c_ctx /*3*/, private_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_round5_decrypt(round5_ctx /*a1*/, private_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1cipherAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_key_alg_info_t /*9*/* compound_key_alg_info_ctx = *(vscf_compound_key_alg_info_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_info_cipher_alg_info(compound_key_alg_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1signerAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_key_alg_info_t /*9*/* compound_key_alg_info_ctx = *(vscf_compound_key_alg_info_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_info_signer_alg_info(compound_key_alg_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1signerHashAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_key_alg_info_t /*9*/* compound_key_alg_info_ctx = *(vscf_compound_key_alg_info_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_info_signer_hash_alg_info(compound_key_alg_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_compound_key_alg_info_t **)&c_ctx = vscf_compound_key_alg_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_compound_key_alg_info_delete(*(vscf_compound_key_alg_info_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_key_alg_info_t /*9*/* compound_key_alg_info_ctx = *(vscf_compound_key_alg_info_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_compound_key_alg_info_alg_id(compound_key_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1cipherKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_public_key_t /*9*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_public_key_cipher_key(compound_public_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1signerKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_public_key_t /*9*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_public_key_signer_key(compound_public_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1signature (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_public_key_t /*9*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_compound_public_key_signature(compound_public_key_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_compound_public_key_t **)&c_ctx = vscf_compound_public_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_compound_public_key_delete(*(vscf_compound_public_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_public_key_t /*9*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_compound_public_key_alg_id(compound_public_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_public_key_t /*9*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_public_key_alg_info(compound_public_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_public_key_t /*9*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_compound_public_key_len(compound_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_public_key_t /*9*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_compound_public_key_bitlen(compound_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPublicKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_public_key_t /*9*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_compound_public_key_is_valid(compound_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1cipherKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_private_key_t /*9*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_private_key_cipher_key(compound_private_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1signerKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_private_key_t /*9*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_private_key_signer_key(compound_private_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1signature (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_private_key_t /*9*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_compound_private_key_signature(compound_private_key_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_compound_private_key_t **)&c_ctx = vscf_compound_private_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_compound_private_key_delete(*(vscf_compound_private_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_private_key_t /*9*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_compound_private_key_alg_id(compound_private_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_private_key_t /*9*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_private_key_alg_info(compound_private_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_private_key_t /*9*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_compound_private_key_len(compound_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_private_key_t /*9*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_compound_private_key_bitlen(compound_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_private_key_t /*9*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_compound_private_key_is_valid(compound_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundPrivateKey_1extractPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_private_key_t /*9*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_private_key_extract_public_key(compound_private_key_ctx /*a1*/);
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_compound_key_alg_release_random((vscf_compound_key_alg_t /*9*/ *) c_ctx);
    vscf_compound_key_alg_use_random((vscf_compound_key_alg_t /*9*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1setHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jhash) {
    jclass hash_cls = (*jenv)->GetObjectClass(jenv, jhash);
    if (NULL == hash_cls) {
        VSCF_ASSERT("Class Hash not found.");
    }
    jfieldID hash_fidCtx = (*jenv)->GetFieldID(jenv, hash_cls, "cCtx", "J");
    if (NULL == hash_fidCtx) {
        VSCF_ASSERT("Class 'Hash' has no field 'cCtx'.");
    }
    jlong hash_c_ctx = (*jenv)->GetLongField(jenv, jhash, hash_fidCtx);
    vscf_impl_t */*6*/ hash = *(vscf_impl_t */*6*/*) &hash_c_ctx;

    vscf_compound_key_alg_release_hash((vscf_compound_key_alg_t /*9*/ *) c_ctx);
    vscf_compound_key_alg_use_hash((vscf_compound_key_alg_t /*9*/ *) c_ctx, hash);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_compound_key_alg_setup_defaults(compound_key_alg_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1makeKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jcipherKey, jobject jsignerKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass cipher_key_cls = (*jenv)->GetObjectClass(jenv, jcipherKey);
    if (NULL == cipher_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID cipher_key_fidCtx = (*jenv)->GetFieldID(jenv, cipher_key_cls, "cCtx", "J");
    if (NULL == cipher_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong cipher_key_c_ctx = (*jenv)->GetLongField(jenv, jcipherKey, cipher_key_fidCtx);
    vscf_impl_t */*6*/ cipher_key = *(vscf_impl_t */*6*/*)&cipher_key_c_ctx;

    jclass signer_key_cls = (*jenv)->GetObjectClass(jenv, jsignerKey);
    if (NULL == signer_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID signer_key_fidCtx = (*jenv)->GetFieldID(jenv, signer_key_cls, "cCtx", "J");
    if (NULL == signer_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong signer_key_c_ctx = (*jenv)->GetLongField(jenv, jsignerKey, signer_key_fidCtx);
    vscf_impl_t */*6*/ signer_key = *(vscf_impl_t */*6*/*)&signer_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_make_key(compound_key_alg_ctx /*a1*/, cipher_key /*a6*/, signer_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_compound_key_alg_t **)&c_ctx = vscf_compound_key_alg_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_compound_key_alg_delete(*(vscf_compound_key_alg_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_compound_key_alg_alg_id(compound_key_alg_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_produce_alg_info(compound_key_alg_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_compound_key_alg_restore_alg_info(compound_key_alg_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_generate_ephemeral_key(compound_key_alg_ctx /*a1*/, key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ raw_key = *(vscf_raw_public_key_t * /*7*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_import_public_key(compound_key_alg_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    const vscf_raw_public_key_t */*5*/ proxyResult = vscf_compound_key_alg_export_public_key(compound_key_alg_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_private_key_t */*5*/ raw_key = *(vscf_raw_private_key_t */*5*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_import_private_key(compound_key_alg_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    const vscf_raw_private_key_t */*5*/ proxyResult = vscf_compound_key_alg_export_private_key(compound_key_alg_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1canEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_compound_key_alg_can_encrypt(compound_key_alg_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jint ret = (jint) vscf_compound_key_alg_encrypted_len(compound_key_alg_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jbyteArray jdata) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_compound_key_alg_encrypted_len((vscf_compound_key_alg_t /*9*/ *) c_ctx /*3*/, public_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_compound_key_alg_encrypt(compound_key_alg_ctx /*a1*/, public_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1canDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_compound_key_alg_can_decrypt(compound_key_alg_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_compound_key_alg_decrypted_len(compound_key_alg_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jbyteArray jdata) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_compound_key_alg_decrypted_len((vscf_compound_key_alg_t /*9*/ *) c_ctx /*3*/, private_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_compound_key_alg_decrypt(compound_key_alg_ctx /*a1*/, private_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1canSign (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_compound_key_alg_can_sign(compound_key_alg_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_compound_key_alg_signature_len(compound_key_alg_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1signHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jobject jhashId, jbyteArray jdigest) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_compound_key_alg_signature_len((vscf_compound_key_alg_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_compound_key_alg_sign_hash(compound_key_alg_ctx /*a1*/, private_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), (jbyte*) vsc_buffer_bytes(signature));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1canVerify (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_compound_key_alg_can_verify(compound_key_alg_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_compoundKeyAlg_1verifyHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jobject jhashId, jbyteArray jdigest, jbyteArray jsignature) {
    // Cast class context
    vscf_compound_key_alg_t /*9*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
    vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

    jboolean ret = (jboolean) vscf_compound_key_alg_verify_hash(compound_key_alg_ctx /*a1*/, public_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlgInfo_1l1KeyAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_key_alg_info_t /*9*/* chained_key_alg_info_ctx = *(vscf_chained_key_alg_info_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_key_alg_info_l1_key_alg_info(chained_key_alg_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlgInfo_1l2KeyAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_key_alg_info_t /*9*/* chained_key_alg_info_ctx = *(vscf_chained_key_alg_info_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_key_alg_info_l2_key_alg_info(chained_key_alg_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlgInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_chained_key_alg_info_t **)&c_ctx = vscf_chained_key_alg_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_chained_key_alg_info_delete(*(vscf_chained_key_alg_info_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_key_alg_info_t /*9*/* chained_key_alg_info_ctx = *(vscf_chained_key_alg_info_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_chained_key_alg_info_alg_id(chained_key_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPublicKey_1l1Key (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_public_key_t /*9*/* chained_public_key_ctx = *(vscf_chained_public_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_public_key_l1_key(chained_public_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPublicKey_1l2Key (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_public_key_t /*9*/* chained_public_key_ctx = *(vscf_chained_public_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_public_key_l2_key(chained_public_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPublicKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_chained_public_key_t **)&c_ctx = vscf_chained_public_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPublicKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_chained_public_key_delete(*(vscf_chained_public_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPublicKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_public_key_t /*9*/* chained_public_key_ctx = *(vscf_chained_public_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_chained_public_key_alg_id(chained_public_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPublicKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_public_key_t /*9*/* chained_public_key_ctx = *(vscf_chained_public_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_public_key_alg_info(chained_public_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPublicKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_public_key_t /*9*/* chained_public_key_ctx = *(vscf_chained_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_chained_public_key_len(chained_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPublicKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_public_key_t /*9*/* chained_public_key_ctx = *(vscf_chained_public_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_chained_public_key_bitlen(chained_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPublicKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_public_key_t /*9*/* chained_public_key_ctx = *(vscf_chained_public_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_chained_public_key_is_valid(chained_public_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1l1Key (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_private_key_t /*9*/* chained_private_key_ctx = *(vscf_chained_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_private_key_l1_key(chained_private_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1l2Key (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_private_key_t /*9*/* chained_private_key_ctx = *(vscf_chained_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_private_key_l2_key(chained_private_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_chained_private_key_t **)&c_ctx = vscf_chained_private_key_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_chained_private_key_delete(*(vscf_chained_private_key_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_private_key_t /*9*/* chained_private_key_ctx = *(vscf_chained_private_key_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_chained_private_key_alg_id(chained_private_key_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1algInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_private_key_t /*9*/* chained_private_key_ctx = *(vscf_chained_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_private_key_alg_info(chained_private_key_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_private_key_t /*9*/* chained_private_key_ctx = *(vscf_chained_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_chained_private_key_len(chained_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1bitlen (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_private_key_t /*9*/* chained_private_key_ctx = *(vscf_chained_private_key_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_chained_private_key_bitlen(chained_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1isValid (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_private_key_t /*9*/* chained_private_key_ctx = *(vscf_chained_private_key_t /*9*/**) &c_ctx;

    jboolean ret = (jboolean) vscf_chained_private_key_is_valid(chained_private_key_ctx /*a1*/);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedPrivateKey_1extractPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_private_key_t /*9*/* chained_private_key_ctx = *(vscf_chained_private_key_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_private_key_extract_public_key(chained_private_key_ctx /*a1*/);
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_chained_key_alg_release_random((vscf_chained_key_alg_t /*9*/ *) c_ctx);
    vscf_chained_key_alg_use_random((vscf_chained_key_alg_t /*9*/ *) c_ctx, random);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;

    vscf_status_t status = vscf_chained_key_alg_setup_defaults(chained_key_alg_ctx /*a1*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1makeKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jl1Key, jobject jl2Key) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass l1_key_cls = (*jenv)->GetObjectClass(jenv, jl1Key);
    if (NULL == l1_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID l1_key_fidCtx = (*jenv)->GetFieldID(jenv, l1_key_cls, "cCtx", "J");
    if (NULL == l1_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong l1_key_c_ctx = (*jenv)->GetLongField(jenv, jl1Key, l1_key_fidCtx);
    vscf_impl_t */*6*/ l1_key = *(vscf_impl_t */*6*/*)&l1_key_c_ctx;

    jclass l2_key_cls = (*jenv)->GetObjectClass(jenv, jl2Key);
    if (NULL == l2_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID l2_key_fidCtx = (*jenv)->GetFieldID(jenv, l2_key_cls, "cCtx", "J");
    if (NULL == l2_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong l2_key_c_ctx = (*jenv)->GetLongField(jenv, jl2Key, l2_key_fidCtx);
    vscf_impl_t */*6*/ l2_key = *(vscf_impl_t */*6*/*)&l2_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_key_alg_make_key(chained_key_alg_ctx /*a1*/, l1_key /*a6*/, l2_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_chained_key_alg_t **)&c_ctx = vscf_chained_key_alg_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_chained_key_alg_delete(*(vscf_chained_key_alg_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_chained_key_alg_alg_id(chained_key_alg_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_key_alg_produce_alg_info(chained_key_alg_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_chained_key_alg_restore_alg_info(chained_key_alg_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1generateEphemeralKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jkey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass key_cls = (*jenv)->GetObjectClass(jenv, jkey);
    if (NULL == key_cls) {
        VSCF_ASSERT("Class Key not found.");
    }
    jfieldID key_fidCtx = (*jenv)->GetFieldID(jenv, key_cls, "cCtx", "J");
    if (NULL == key_fidCtx) {
        VSCF_ASSERT("Class 'Key' has no field 'cCtx'.");
    }
    jlong key_c_ctx = (*jenv)->GetLongField(jenv, jkey, key_fidCtx);
    vscf_impl_t */*6*/ key = *(vscf_impl_t */*6*/*)&key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_key_alg_generate_ephemeral_key(chained_key_alg_ctx /*a1*/, key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1importPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPublicKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_public_key_t * /*7*/ raw_key = *(vscf_raw_public_key_t * /*7*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_key_alg_import_public_key(chained_key_alg_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1exportPublicKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    const vscf_raw_public_key_t */*5*/ proxyResult = vscf_chained_key_alg_export_public_key(chained_key_alg_ctx /*a1*/, public_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPublicKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1importPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrawKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass raw_key_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == raw_key_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jfieldID raw_key_fidCtx = (*jenv)->GetFieldID(jenv, raw_key_cls, "cCtx", "J");
    if (NULL == raw_key_fidCtx) {
        VSCF_ASSERT("Class 'RawPrivateKey' has no field 'cCtx'.");
    }
    jlong raw_key_c_ctx = (*jenv)->GetLongField(jenv, jrawKey, raw_key_fidCtx);
    vscf_raw_private_key_t */*5*/ raw_key = *(vscf_raw_private_key_t */*5*/*) &raw_key_c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_chained_key_alg_import_private_key(chained_key_alg_ctx /*a1*/, raw_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1exportPrivateKey (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    const vscf_raw_private_key_t */*5*/ proxyResult = vscf_chained_key_alg_export_private_key(chained_key_alg_ctx /*a1*/, private_key /*a6*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPrivateKey");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class RawPrivateKey not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPrivateKey;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class RawPrivateKey has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1canEncrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_chained_key_alg_can_encrypt(chained_key_alg_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1encryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jint jdataLen) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jint ret = (jint) vscf_chained_key_alg_encrypted_len(chained_key_alg_ctx /*a1*/, public_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1encrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jbyteArray jdata) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_chained_key_alg_encrypted_len((vscf_chained_key_alg_t /*9*/ *) c_ctx /*3*/, public_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_chained_key_alg_encrypt(chained_key_alg_ctx /*a1*/, public_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1canDecrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_chained_key_alg_can_decrypt(chained_key_alg_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1decryptedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jint jdataLen) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_chained_key_alg_decrypted_len(chained_key_alg_ctx /*a1*/, private_key /*a6*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1decrypt (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jbyteArray jdata) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_chained_key_alg_decrypted_len((vscf_chained_key_alg_t /*9*/ *) c_ctx /*3*/, private_key/*a*/, data.len/*a*/));

    vscf_status_t status = vscf_chained_key_alg_decrypt(chained_key_alg_ctx /*a1*/, private_key /*a6*/, data /*a3*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1canSign (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jboolean ret = (jboolean) vscf_chained_key_alg_can_sign(chained_key_alg_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1signatureLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    jint ret = (jint) vscf_chained_key_alg_signature_len(chained_key_alg_ctx /*a1*/, private_key /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1signHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jprivateKey, jobject jhashId, jbyteArray jdigest) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass private_key_cls = (*jenv)->GetObjectClass(jenv, jprivateKey);
    if (NULL == private_key_cls) {
        VSCF_ASSERT("Class PrivateKey not found.");
    }
    jfieldID private_key_fidCtx = (*jenv)->GetFieldID(jenv, private_key_cls, "cCtx", "J");
    if (NULL == private_key_fidCtx) {
        VSCF_ASSERT("Class 'PrivateKey' has no field 'cCtx'.");
    }
    jlong private_key_c_ctx = (*jenv)->GetLongField(jenv, jprivateKey, private_key_fidCtx);
    vscf_impl_t */*6*/ private_key = *(vscf_impl_t */*6*/*)&private_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_chained_key_alg_signature_len((vscf_chained_key_alg_t /*9*/ *) c_ctx /*3*/, private_key/*a*/));

    vscf_status_t status = vscf_chained_key_alg_sign_hash(chained_key_alg_ctx /*a1*/, private_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), (jbyte*) vsc_buffer_bytes(signature));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    vsc_buffer_delete(signature);

    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1canVerify (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    jboolean ret = (jboolean) vscf_chained_key_alg_can_verify(chained_key_alg_ctx /*a1*/, public_key /*a6*/);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_chainedKeyAlg_1verifyHash (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jpublicKey, jobject jhashId, jbyteArray jdigest, jbyteArray jsignature) {
    // Cast class context
    vscf_chained_key_alg_t /*9*/* chained_key_alg_ctx = *(vscf_chained_key_alg_t /*9*/**) &c_ctx;

    // Wrap enums
    jclass hash_id_cls = (*jenv)->GetObjectClass(jenv, jhashId);
    jmethodID hash_id_methodID = (*jenv)->GetMethodID(jenv, hash_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hash_id_methodID);
    // Wrap Java interfaces
    jclass public_key_cls = (*jenv)->GetObjectClass(jenv, jpublicKey);
    if (NULL == public_key_cls) {
        VSCF_ASSERT("Class PublicKey not found.");
    }
    jfieldID public_key_fidCtx = (*jenv)->GetFieldID(jenv, public_key_cls, "cCtx", "J");
    if (NULL == public_key_fidCtx) {
        VSCF_ASSERT("Class 'PublicKey' has no field 'cCtx'.");
    }
    jlong public_key_c_ctx = (*jenv)->GetLongField(jenv, jpublicKey, public_key_fidCtx);
    vscf_impl_t */*6*/ public_key = *(vscf_impl_t */*6*/*)&public_key_c_ctx;

    // Wrap input data
    byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
    vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

    byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
    vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

    jboolean ret = (jboolean) vscf_chained_key_alg_verify_hash(chained_key_alg_ctx /*a1*/, public_key /*a6*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

    (*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_simpleAlgInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_simple_alg_info_t **)&c_ctx = vscf_simple_alg_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_simpleAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_simple_alg_info_delete(*(vscf_simple_alg_info_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_simpleAlgInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgId_2 (JNIEnv *jenv, jobject jobj, jobject jalgId) {
    // Wrap enums
    jclass alg_id_cls = (*jenv)->GetObjectClass(jenv, jalgId);
    jmethodID alg_id_methodID = (*jenv)->GetMethodID(jenv, alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, alg_id_methodID);

    jlong proxyResult = (jlong) vscf_simple_alg_info_new_with_alg_id(alg_id /*a7*/);
    return proxyResult;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_simpleAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_simple_alg_info_t /*9*/* simple_alg_info_ctx = *(vscf_simple_alg_info_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_simple_alg_info_alg_id(simple_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1hashAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_hash_based_alg_info_t /*9*/* hash_based_alg_info_ctx = *(vscf_hash_based_alg_info_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_hash_based_alg_info_t **)&c_ctx = vscf_hash_based_alg_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_hash_based_alg_info_delete(*(vscf_hash_based_alg_info_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_hashBasedAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_hash_based_alg_info_t /*9*/* hash_based_alg_info_ctx = *(vscf_hash_based_alg_info_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_hash_based_alg_info_alg_id(hash_based_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1nonce (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_cipher_alg_info_t /*9*/* cipher_alg_info_ctx = *(vscf_cipher_alg_info_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_cipher_alg_info_nonce(cipher_alg_info_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_cipher_alg_info_t **)&c_ctx = vscf_cipher_alg_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_cipher_alg_info_delete(*(vscf_cipher_alg_info_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgId_2_3B (JNIEnv *jenv, jobject jobj, jobject jalgId, jbyteArray jnonce) {
    // Wrap enums
    jclass alg_id_cls = (*jenv)->GetObjectClass(jenv, jalgId);
    jmethodID alg_id_methodID = (*jenv)->GetMethodID(jenv, alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, alg_id_methodID);

    // Wrap input data
    byte* nonce_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jnonce, NULL);
    vsc_data_t nonce = vsc_data(nonce_arr, (*jenv)->GetArrayLength(jenv, jnonce));

    jlong proxyResult = (jlong) vscf_cipher_alg_info_new_with_members(alg_id /*a7*/, nonce /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jnonce, (jbyte*) nonce_arr, 0);

    return proxyResult;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_cipherAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_cipher_alg_info_t /*9*/* cipher_alg_info_ctx = *(vscf_cipher_alg_info_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_cipher_alg_info_alg_id(cipher_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1hashAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_salted_kdf_alg_info_t /*9*/* salted_kdf_alg_info_ctx = *(vscf_salted_kdf_alg_info_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_salted_kdf_alg_info_hash_alg_info(salted_kdf_alg_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1salt (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_salted_kdf_alg_info_t /*9*/* salted_kdf_alg_info_ctx = *(vscf_salted_kdf_alg_info_t /*9*/**) &c_ctx;

    const vsc_data_t /*3*/ proxyResult = vscf_salted_kdf_alg_info_salt(salted_kdf_alg_info_ctx /*a1*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1iterationCount (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_salted_kdf_alg_info_t /*9*/* salted_kdf_alg_info_ctx = *(vscf_salted_kdf_alg_info_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_salted_kdf_alg_info_iteration_count(salted_kdf_alg_info_ctx /*a1*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_salted_kdf_alg_info_t **)&c_ctx = vscf_salted_kdf_alg_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_salted_kdf_alg_info_delete(*(vscf_salted_kdf_alg_info_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_saltedKdfAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_salted_kdf_alg_info_t /*9*/* salted_kdf_alg_info_ctx = *(vscf_salted_kdf_alg_info_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_salted_kdf_alg_info_alg_id(salted_kdf_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1kdfAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_pbe_alg_info_t /*9*/* pbe_alg_info_ctx = *(vscf_pbe_alg_info_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_pbe_alg_info_kdf_alg_info(pbe_alg_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1cipherAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_pbe_alg_info_t /*9*/* pbe_alg_info_ctx = *(vscf_pbe_alg_info_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_pbe_alg_info_cipher_alg_info(pbe_alg_info_ctx /*a1*/);
    vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_pbe_alg_info_t **)&c_ctx = vscf_pbe_alg_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_pbe_alg_info_delete(*(vscf_pbe_alg_info_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_pbeAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_pbe_alg_info_t /*9*/* pbe_alg_info_ctx = *(vscf_pbe_alg_info_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_pbe_alg_info_alg_id(pbe_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1keyId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_alg_info_t /*9*/* ecc_alg_info_ctx = *(vscf_ecc_alg_info_t /*9*/**) &c_ctx;

    const vscf_oid_id_t proxyResult = vscf_ecc_alg_info_key_id(ecc_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/OidId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum OidId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/OidId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum OidId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1domainId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_alg_info_t /*9*/* ecc_alg_info_ctx = *(vscf_ecc_alg_info_t /*9*/**) &c_ctx;

    const vscf_oid_id_t proxyResult = vscf_ecc_alg_info_domain_id(ecc_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/OidId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum OidId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/OidId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum OidId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_ecc_alg_info_t **)&c_ctx = vscf_ecc_alg_info_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_ecc_alg_info_delete(*(vscf_ecc_alg_info_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1new__Lcom_virgilsecurity_crypto_foundation_AlgId_2Lcom_virgilsecurity_crypto_foundation_OidId_2Lcom_virgilsecurity_crypto_foundation_OidId_2 (JNIEnv *jenv, jobject jobj, jobject jalgId, jobject jkeyId, jobject jdomainId) {
    // Wrap enums
    jclass alg_id_cls = (*jenv)->GetObjectClass(jenv, jalgId);
    jmethodID alg_id_methodID = (*jenv)->GetMethodID(jenv, alg_id_cls, "getCode", "()I");
    vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, alg_id_methodID);

    jclass key_id_cls = (*jenv)->GetObjectClass(jenv, jkeyId);
    jmethodID key_id_methodID = (*jenv)->GetMethodID(jenv, key_id_cls, "getCode", "()I");
    vscf_oid_id_t /*8*/ key_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jkeyId, key_id_methodID);

    jclass domain_id_cls = (*jenv)->GetObjectClass(jenv, jdomainId);
    jmethodID domain_id_methodID = (*jenv)->GetMethodID(jenv, domain_id_cls, "getCode", "()I");
    vscf_oid_id_t /*8*/ domain_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jdomainId, domain_id_methodID);

    jlong proxyResult = (jlong) vscf_ecc_alg_info_new_with_members(alg_id /*a7*/, key_id /*a7*/, domain_id /*a7*/);
    return proxyResult;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_eccAlgInfo_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_ecc_alg_info_t /*9*/* ecc_alg_info_ctx = *(vscf_ecc_alg_info_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_ecc_alg_info_alg_id(ecc_alg_info_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1setAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Writer) {
    jclass asn1_writer_cls = (*jenv)->GetObjectClass(jenv, jasn1Writer);
    if (NULL == asn1_writer_cls) {
        VSCF_ASSERT("Class Asn1Writer not found.");
    }
    jfieldID asn1_writer_fidCtx = (*jenv)->GetFieldID(jenv, asn1_writer_cls, "cCtx", "J");
    if (NULL == asn1_writer_fidCtx) {
        VSCF_ASSERT("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    jlong asn1_writer_c_ctx = (*jenv)->GetLongField(jenv, jasn1Writer, asn1_writer_fidCtx);
    vscf_impl_t */*6*/ asn1_writer = *(vscf_impl_t */*6*/*) &asn1_writer_c_ctx;

    vscf_alg_info_der_serializer_release_asn1_writer((vscf_alg_info_der_serializer_t /*9*/ *) c_ctx);
    vscf_alg_info_der_serializer_use_asn1_writer((vscf_alg_info_der_serializer_t /*9*/ *) c_ctx, asn1_writer);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_alg_info_der_serializer_t /*9*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*9*/**) &c_ctx;

    vscf_alg_info_der_serializer_setup_defaults(alg_info_der_serializer_ctx /*a1*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serializeInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_alg_info_der_serializer_t /*9*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    jint ret = (jint) vscf_alg_info_der_serializer_serialize_inplace(alg_info_der_serializer_ctx /*a1*/, alg_info /*a6*/);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_alg_info_der_serializer_t **)&c_ctx = vscf_alg_info_der_serializer_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_info_der_serializer_delete(*(vscf_alg_info_der_serializer_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serializedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_alg_info_der_serializer_t /*9*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    jint ret = (jint) vscf_alg_info_der_serializer_serialized_len(alg_info_der_serializer_ctx /*a1*/, alg_info /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerSerializer_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_alg_info_der_serializer_t /*9*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_alg_info_der_serializer_serialized_len((vscf_alg_info_der_serializer_t /*9*/ *) c_ctx /*3*/, alg_info/*a*/));

    vscf_alg_info_der_serializer_serialize(alg_info_der_serializer_ctx /*a1*/, alg_info /*a6*/, out /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1setAsn1Reader (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Reader) {
    jclass asn1_reader_cls = (*jenv)->GetObjectClass(jenv, jasn1Reader);
    if (NULL == asn1_reader_cls) {
        VSCF_ASSERT("Class Asn1Reader not found.");
    }
    jfieldID asn1_reader_fidCtx = (*jenv)->GetFieldID(jenv, asn1_reader_cls, "cCtx", "J");
    if (NULL == asn1_reader_fidCtx) {
        VSCF_ASSERT("Class 'Asn1Reader' has no field 'cCtx'.");
    }
    jlong asn1_reader_c_ctx = (*jenv)->GetLongField(jenv, jasn1Reader, asn1_reader_fidCtx);
    vscf_impl_t */*6*/ asn1_reader = *(vscf_impl_t */*6*/*) &asn1_reader_c_ctx;

    vscf_alg_info_der_deserializer_release_asn1_reader((vscf_alg_info_der_deserializer_t /*9*/ *) c_ctx);
    vscf_alg_info_der_deserializer_use_asn1_reader((vscf_alg_info_der_deserializer_t /*9*/ *) c_ctx, asn1_reader);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_alg_info_der_deserializer_t /*9*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*9*/**) &c_ctx;

    vscf_alg_info_der_deserializer_setup_defaults(alg_info_der_deserializer_ctx /*a1*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1deserializeInplace (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_alg_info_der_deserializer_t /*9*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_inplace(alg_info_der_deserializer_ctx /*a1*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_alg_info_der_deserializer_t **)&c_ctx = vscf_alg_info_der_deserializer_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_alg_info_der_deserializer_delete(*(vscf_alg_info_der_deserializer_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_algInfoDerDeserializer_1deserialize (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_alg_info_der_deserializer_t /*9*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize(alg_info_der_deserializer_ctx /*a1*/, data /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setAsn1Reader (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Reader) {
    jclass asn1_reader_cls = (*jenv)->GetObjectClass(jenv, jasn1Reader);
    if (NULL == asn1_reader_cls) {
        VSCF_ASSERT("Class Asn1Reader not found.");
    }
    jfieldID asn1_reader_fidCtx = (*jenv)->GetFieldID(jenv, asn1_reader_cls, "cCtx", "J");
    if (NULL == asn1_reader_fidCtx) {
        VSCF_ASSERT("Class 'Asn1Reader' has no field 'cCtx'.");
    }
    jlong asn1_reader_c_ctx = (*jenv)->GetLongField(jenv, jasn1Reader, asn1_reader_fidCtx);
    vscf_impl_t */*6*/ asn1_reader = *(vscf_impl_t */*6*/*) &asn1_reader_c_ctx;

    vscf_message_info_der_serializer_release_asn1_reader((vscf_message_info_der_serializer_t /*9*/ *) c_ctx);
    vscf_message_info_der_serializer_use_asn1_reader((vscf_message_info_der_serializer_t /*9*/ *) c_ctx, asn1_reader);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setAsn1Writer (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jasn1Writer) {
    jclass asn1_writer_cls = (*jenv)->GetObjectClass(jenv, jasn1Writer);
    if (NULL == asn1_writer_cls) {
        VSCF_ASSERT("Class Asn1Writer not found.");
    }
    jfieldID asn1_writer_fidCtx = (*jenv)->GetFieldID(jenv, asn1_writer_cls, "cCtx", "J");
    if (NULL == asn1_writer_fidCtx) {
        VSCF_ASSERT("Class 'Asn1Writer' has no field 'cCtx'.");
    }
    jlong asn1_writer_c_ctx = (*jenv)->GetLongField(jenv, jasn1Writer, asn1_writer_fidCtx);
    vscf_impl_t */*6*/ asn1_writer = *(vscf_impl_t */*6*/*) &asn1_writer_c_ctx;

    vscf_message_info_der_serializer_release_asn1_writer((vscf_message_info_der_serializer_t /*9*/ *) c_ctx);
    vscf_message_info_der_serializer_use_asn1_writer((vscf_message_info_der_serializer_t /*9*/ *) c_ctx, asn1_writer);
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1setupDefaults (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_message_info_der_serializer_t /*9*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*9*/**) &c_ctx;

    vscf_message_info_der_serializer_setup_defaults(message_info_der_serializer_ctx /*a1*/);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_message_info_der_serializer_t **)&c_ctx = vscf_message_info_der_serializer_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_message_info_der_serializer_delete(*(vscf_message_info_der_serializer_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serializedLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessageInfo) {
    // Cast class context
    vscf_message_info_der_serializer_t /*9*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass message_info_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/MessageInfo");
    if (NULL == message_info_cls) {
        VSCF_ASSERT("Class MessageInfo not found.");
    }
    jfieldID message_info_fidCtx = (*jenv)->GetFieldID(jenv, message_info_cls, "cCtx", "J");
    if (NULL == message_info_fidCtx) {
        VSCF_ASSERT("Class 'MessageInfo' has no field 'cCtx'.");
    }
    jlong message_info_c_ctx = (*jenv)->GetLongField(jenv, jmessageInfo, message_info_fidCtx);
    vscf_message_info_t */*5*/ message_info = *(vscf_message_info_t */*5*/*) &message_info_c_ctx;

    jint ret = (jint) vscf_message_info_der_serializer_serialized_len(message_info_der_serializer_ctx /*a1*/, message_info /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serialize (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessageInfo) {
    // Cast class context
    vscf_message_info_der_serializer_t /*9*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass message_info_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/MessageInfo");
    if (NULL == message_info_cls) {
        VSCF_ASSERT("Class MessageInfo not found.");
    }
    jfieldID message_info_fidCtx = (*jenv)->GetFieldID(jenv, message_info_cls, "cCtx", "J");
    if (NULL == message_info_fidCtx) {
        VSCF_ASSERT("Class 'MessageInfo' has no field 'cCtx'.");
    }
    jlong message_info_c_ctx = (*jenv)->GetLongField(jenv, jmessageInfo, message_info_fidCtx);
    vscf_message_info_t */*5*/ message_info = *(vscf_message_info_t */*5*/*) &message_info_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_len((vscf_message_info_der_serializer_t /*9*/ *) c_ctx /*3*/, message_info/*a*/));

    vscf_message_info_der_serializer_serialize(message_info_der_serializer_ctx /*a1*/, message_info /*a6*/, out /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1readPrefix (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_message_info_der_serializer_t /*9*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    jint ret = (jint) vscf_message_info_der_serializer_read_prefix(message_info_der_serializer_ctx /*a1*/, data /*a3*/);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1deserialize (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_message_info_der_serializer_t /*9*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    const vscf_message_info_t */*5*/ proxyResult = vscf_message_info_der_serializer_deserialize(message_info_der_serializer_ctx /*a1*/, data /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/MessageInfo");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class MessageInfo not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/MessageInfo;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class MessageInfo has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serializedFooterLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessageInfoFooter) {
    // Cast class context
    vscf_message_info_der_serializer_t /*9*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass message_info_footer_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/MessageInfoFooter");
    if (NULL == message_info_footer_cls) {
        VSCF_ASSERT("Class MessageInfoFooter not found.");
    }
    jfieldID message_info_footer_fidCtx = (*jenv)->GetFieldID(jenv, message_info_footer_cls, "cCtx", "J");
    if (NULL == message_info_footer_fidCtx) {
        VSCF_ASSERT("Class 'MessageInfoFooter' has no field 'cCtx'.");
    }
    jlong message_info_footer_c_ctx = (*jenv)->GetLongField(jenv, jmessageInfoFooter, message_info_footer_fidCtx);
    vscf_message_info_footer_t */*5*/ message_info_footer = *(vscf_message_info_footer_t */*5*/*) &message_info_footer_c_ctx;

    jint ret = (jint) vscf_message_info_der_serializer_serialized_footer_len(message_info_der_serializer_ctx /*a1*/, message_info_footer /*a6*/);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1serializeFooter (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jmessageInfoFooter) {
    // Cast class context
    vscf_message_info_der_serializer_t /*9*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass message_info_footer_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/MessageInfoFooter");
    if (NULL == message_info_footer_cls) {
        VSCF_ASSERT("Class MessageInfoFooter not found.");
    }
    jfieldID message_info_footer_fidCtx = (*jenv)->GetFieldID(jenv, message_info_footer_cls, "cCtx", "J");
    if (NULL == message_info_footer_fidCtx) {
        VSCF_ASSERT("Class 'MessageInfoFooter' has no field 'cCtx'.");
    }
    jlong message_info_footer_c_ctx = (*jenv)->GetLongField(jenv, jmessageInfoFooter, message_info_footer_fidCtx);
    vscf_message_info_footer_t */*5*/ message_info_footer = *(vscf_message_info_footer_t */*5*/*) &message_info_footer_c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_footer_len((vscf_message_info_der_serializer_t /*9*/ *) c_ctx /*3*/, message_info_footer/*a*/));

    vscf_message_info_der_serializer_serialize_footer(message_info_der_serializer_ctx /*a1*/, message_info_footer /*a6*/, out /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_messageInfoDerSerializer_1deserializeFooter (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Wrap errors
    struct vscf_error_t /*4*/ error;
    vscf_error_reset(&error);
    // Cast class context
    vscf_message_info_der_serializer_t /*9*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    const vscf_message_info_footer_t */*5*/ proxyResult = vscf_message_info_der_serializer_deserialize_footer(message_info_der_serializer_ctx /*a1*/, data /*a3*/, &error /*a4*/);

    if (error.status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, error.status);
        return NULL;
    }
    jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/MessageInfoFooter");
    if (NULL == result_cls) {
        VSCF_ASSERT("Class MessageInfoFooter not found.");
    }
    jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/MessageInfoFooter;");
    if (NULL == result_methodID) {
        VSCF_ASSERT("Class MessageInfoFooter has no 'getInstance' method.");
    }

    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1setRandom (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jrandom) {
    jclass random_cls = (*jenv)->GetObjectClass(jenv, jrandom);
    if (NULL == random_cls) {
        VSCF_ASSERT("Class Random not found.");
    }
    jfieldID random_fidCtx = (*jenv)->GetFieldID(jenv, random_cls, "cCtx", "J");
    if (NULL == random_fidCtx) {
        VSCF_ASSERT("Class 'Random' has no field 'cCtx'.");
    }
    jlong random_c_ctx = (*jenv)->GetLongField(jenv, jrandom, random_fidCtx);
    vscf_impl_t */*6*/ random = *(vscf_impl_t */*6*/*) &random_c_ctx;

    vscf_random_padding_release_random((vscf_random_padding_t /*9*/ *) c_ctx);
    vscf_random_padding_use_random((vscf_random_padding_t /*9*/ *) c_ctx, random);
}

JNIEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1new__ (JNIEnv *jenv, jobject jobj) {
    jlong c_ctx = 0;
    *(vscf_random_padding_t **)&c_ctx = vscf_random_padding_new();
    return c_ctx;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1close (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    vscf_random_padding_delete(*(vscf_random_padding_t /*9*/ **) &c_ctx /*5*/);
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1algId (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    const vscf_alg_id_t proxyResult = vscf_random_padding_alg_id(random_padding_ctx /*a1*/);
    jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/AlgId");
    if (NULL == cls) {
        VSCF_ASSERT("Enum AlgId not found.");
    }

    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/foundation/AlgId;");
    if (NULL == methodID) {
        VSCF_ASSERT("Enum AlgId has no method 'fromCode'.");
    }
    jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
    return ret;
}

JNIEXPORT jobject JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1produceAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    const vscf_impl_t */*6*/ proxyResult = vscf_random_padding_produce_alg_info(random_padding_ctx /*a1*/);
    jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1restoreAlgInfo (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jalgInfo) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;
    // Wrap Java interfaces
    jclass alg_info_cls = (*jenv)->GetObjectClass(jenv, jalgInfo);
    if (NULL == alg_info_cls) {
        VSCF_ASSERT("Class AlgInfo not found.");
    }
    jfieldID alg_info_fidCtx = (*jenv)->GetFieldID(jenv, alg_info_cls, "cCtx", "J");
    if (NULL == alg_info_fidCtx) {
        VSCF_ASSERT("Class 'AlgInfo' has no field 'cCtx'.");
    }
    jlong alg_info_c_ctx = (*jenv)->GetLongField(jenv, jalgInfo, alg_info_fidCtx);
    vscf_impl_t */*6*/ alg_info = *(vscf_impl_t */*6*/*)&alg_info_c_ctx;

    vscf_status_t status = vscf_random_padding_restore_alg_info(random_padding_ctx /*a1*/, alg_info /*a6*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return;
    }
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1configure (JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject jparams) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;
    // Wrap Java classes
    jclass params_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/PaddingParams");
    if (NULL == params_cls) {
        VSCF_ASSERT("Class PaddingParams not found.");
    }
    jfieldID params_fidCtx = (*jenv)->GetFieldID(jenv, params_cls, "cCtx", "J");
    if (NULL == params_fidCtx) {
        VSCF_ASSERT("Class 'PaddingParams' has no field 'cCtx'.");
    }
    jlong params_c_ctx = (*jenv)->GetLongField(jenv, jparams, params_fidCtx);
    vscf_padding_params_t */*5*/ params = *(vscf_padding_params_t */*5*/*) &params_c_ctx;

    vscf_random_padding_configure(random_padding_ctx /*a1*/, params /*a6*/);
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1paddedDataLen (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jdataLen) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_random_padding_padded_data_len(random_padding_ctx /*a1*/, jdataLen /*a9*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1len (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_random_padding_len(random_padding_ctx /*a1*/);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1lenMax (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    jint ret = (jint) vscf_random_padding_len_max(random_padding_ctx /*a1*/);
    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1startDataProcessing (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    vscf_random_padding_start_data_processing(random_padding_ctx /*a1*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1processData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    const vsc_data_t /*3*/ proxyResult = vscf_random_padding_process_data(random_padding_ctx /*a1*/, data /*a3*/);
    jbyteArray ret = NULL;
    if (proxyResult.len > 0) {
        ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
        (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
    }
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1finishDataProcessing (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_random_padding_len((vscf_random_padding_t /*9*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_random_padding_finish_data_processing(random_padding_ctx /*a1*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT void JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1startPaddedDataProcessing (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    vscf_random_padding_start_padded_data_processing(random_padding_ctx /*a1*/);
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1processPaddedData (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jdata) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    // Wrap input data
    byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
    vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(jdata);

    vscf_random_padding_process_padded_data(random_padding_ctx /*a1*/, data /*a3*/, out /*a3*/);
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    (*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

    vsc_buffer_delete(out);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_foundation_FoundationJNI_randomPadding_1finishPaddedDataProcessing (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
    // Cast class context
    vscf_random_padding_t /*9*/* random_padding_ctx = *(vscf_random_padding_t /*9*/**) &c_ctx;

    // Wrap input buffers
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_random_padding_len_max((vscf_random_padding_t /*9*/ *) c_ctx /*3*/));

    vscf_status_t status = vscf_random_padding_finish_padded_data_processing(random_padding_ctx /*a1*/, out /*a3*/);
    if (status != vscf_status_SUCCESS) {
        throwFoundationException(jenv, jobj, status);
        return NULL;
    }
    jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
    // Free resources
    vsc_buffer_delete(out);

    return ret;
}

