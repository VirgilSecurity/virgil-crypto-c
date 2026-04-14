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

jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/FoundationException");
if (NULL == cls) {
    VSCF_ASSERT("Class PheException not found.");
    return 0;
}

jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");
if (NULL == methodID) {
    VSCF_ASSERT("Class com.virgilsecurity.crypto.foundation.FoundationException has no constructor.");
    return 0;
}
jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);
if (NULL == obj) {
    VSCF_ASSERT("Can't instantiate com.virgilsecurity.crypto.foundation.FoundationException.");
    return 0;
}
return (*jenv)->Throw(jenv, obj);

// Wrap enums
jclass algId_cls = (*jenv)->GetObjectClass(jenv, jalgId);
jmethodID algId_methodID = (*jenv)->GetMethodID(jenv, algId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, algId_methodID);

const vsc_data_t /*3*/ proxyResult = vscf_oid_from_alg_id(alg_id /*a7*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

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

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

const vsc_data_t /*3*/ proxyResult = vscf_oid_from_id(oid_id /*a7*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

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

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

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

// Wrap input data
byte* lhs_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jlhs, NULL);
vsc_data_t lhs = vsc_data(lhs_arr, (*jenv)->GetArrayLength(jenv, jlhs));

// Wrap input data
byte* rhs_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrhs, NULL);
vsc_data_t rhs = vsc_data(rhs_arr, (*jenv)->GetArrayLength(jenv, jrhs));

jboolean ret = (jboolean) vscf_oid_equal(lhs /*a3*/, rhs /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jlhs, (jbyte*) lhs_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jrhs, (jbyte*) rhs_arr, 0);

return ret;

jint ret = (jint) vscf_base64_encoded_len(jdataLen /*a9*/);
return ret;

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

jint ret = (jint) vscf_base64_decoded_len(jstrLen /*a9*/);
return ret;

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

// Wrap Java strings
const char *title = (*jenv)->GetStringUTFChars(jenv, jtitle, NULL);

jint ret = (jint) vscf_pem_wrapped_len(title /*a8*/, jdataLen /*a9*/);
return ret;

// Wrap Java strings
const char *title = (*jenv)->GetStringUTFChars(jenv, jtitle, NULL);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *pem = vsc_buffer_new_with_capacity(vscf_pem_wrapped_len(title.len/*a*/, data.len/*a*/));

vscf_pem_wrap(title /*a8*/, data /*a3*/, pem /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(pem));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(pem), (jbyte*) vsc_buffer_bytes(pem));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(pem);

return ret;

jint ret = (jint) vscf_pem_unwrapped_len(jpemLen /*a9*/);
return ret;

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

jlong c_ctx = 0;
*(vscf_message_info_t **)&c_ctx = vscf_message_info_new();
return c_ctx;

vscf_message_info_delete(*(vscf_message_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_message_info_data_encryption_alg_info(message_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

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

// Cast class context
vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_message_info_has_custom_params(message_info_ctx /*a1*/);
return ret;

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
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

// Cast class context
vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_message_info_has_cipher_kdf_alg_info(message_info_ctx /*a1*/);
return ret;

// Cast class context
vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_message_info_cipher_kdf_alg_info(message_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_message_info_has_cipher_padding_alg_info(message_info_ctx /*a1*/);
return ret;

// Cast class context
vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_message_info_cipher_padding_alg_info(message_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_message_info_has_footer_info(message_info_ctx /*a1*/);
return ret;

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

// Cast class context
vscf_message_info_t /*2*/* message_info_ctx = *(vscf_message_info_t /*2*/**) &c_ctx;

vscf_message_info_clear(message_info_ctx /*a1*/);

jlong c_ctx = 0;
*(vscf_key_recipient_info_t **)&c_ctx = vscf_key_recipient_info_new();
return c_ctx;

vscf_key_recipient_info_delete(*(vscf_key_recipient_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_key_recipient_info_t /*2*/* key_recipient_info_ctx = *(vscf_key_recipient_info_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_key_recipient_info_recipient_id(key_recipient_info_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_key_recipient_info_t /*2*/* key_recipient_info_ctx = *(vscf_key_recipient_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_key_recipient_info_key_encryption_algorithm(key_recipient_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_key_recipient_info_t /*2*/* key_recipient_info_ctx = *(vscf_key_recipient_info_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_key_recipient_info_encrypted_key(key_recipient_info_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

jlong c_ctx = 0;
*(vscf_key_recipient_info_list_t **)&c_ctx = vscf_key_recipient_info_list_new();
return c_ctx;

vscf_key_recipient_info_list_delete(*(vscf_key_recipient_info_list_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_recipient_info_list_has_item(key_recipient_info_list_ctx /*a1*/);
return ret;

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

// Cast class context
vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_recipient_info_list_has_next(key_recipient_info_list_ctx /*a1*/);
return ret;

// Cast class context
vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

const vscf_self_t */*5*/ proxyResult = vscf_key_recipient_info_list_next(key_recipient_info_list_ctx /*a1*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Self");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Self not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/Self;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Self has no 'getInstance' method.");
}
vscf_self_shallow_copy((vscf_self_t */*5*/) proxyResult);
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

// Cast class context
vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_recipient_info_list_has_prev(key_recipient_info_list_ctx /*a1*/);
return ret;

// Cast class context
vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

const vscf_self_t */*5*/ proxyResult = vscf_key_recipient_info_list_prev(key_recipient_info_list_ctx /*a1*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Self");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Self not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/Self;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Self has no 'getInstance' method.");
}
vscf_self_shallow_copy((vscf_self_t */*5*/) proxyResult);
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

// Cast class context
vscf_key_recipient_info_list_t /*2*/* key_recipient_info_list_ctx = *(vscf_key_recipient_info_list_t /*2*/**) &c_ctx;

vscf_key_recipient_info_list_clear(key_recipient_info_list_ctx /*a1*/);

jlong c_ctx = 0;
*(vscf_password_recipient_info_t **)&c_ctx = vscf_password_recipient_info_new();
return c_ctx;

vscf_password_recipient_info_delete(*(vscf_password_recipient_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_password_recipient_info_t /*2*/* password_recipient_info_ctx = *(vscf_password_recipient_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_password_recipient_info_key_encryption_algorithm(password_recipient_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_password_recipient_info_t /*2*/* password_recipient_info_ctx = *(vscf_password_recipient_info_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_password_recipient_info_encrypted_key(password_recipient_info_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

jlong c_ctx = 0;
*(vscf_password_recipient_info_list_t **)&c_ctx = vscf_password_recipient_info_list_new();
return c_ctx;

vscf_password_recipient_info_list_delete(*(vscf_password_recipient_info_list_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_password_recipient_info_list_has_item(password_recipient_info_list_ctx /*a1*/);
return ret;

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

// Cast class context
vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_password_recipient_info_list_has_next(password_recipient_info_list_ctx /*a1*/);
return ret;

// Cast class context
vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

const vscf_self_t */*5*/ proxyResult = vscf_password_recipient_info_list_next(password_recipient_info_list_ctx /*a1*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Self");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Self not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/Self;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Self has no 'getInstance' method.");
}
vscf_self_shallow_copy((vscf_self_t */*5*/) proxyResult);
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

// Cast class context
vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_password_recipient_info_list_has_prev(password_recipient_info_list_ctx /*a1*/);
return ret;

// Cast class context
vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

const vscf_self_t */*5*/ proxyResult = vscf_password_recipient_info_list_prev(password_recipient_info_list_ctx /*a1*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Self");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Self not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/Self;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Self has no 'getInstance' method.");
}
vscf_self_shallow_copy((vscf_self_t */*5*/) proxyResult);
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

// Cast class context
vscf_password_recipient_info_list_t /*2*/* password_recipient_info_list_ctx = *(vscf_password_recipient_info_list_t /*2*/**) &c_ctx;

vscf_password_recipient_info_list_clear(password_recipient_info_list_ctx /*a1*/);

const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_hash_from_info(jalgInfo /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapHash(jenv, jobj, proxyResult);
return ret;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_mac_from_info(jalgInfo /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapMac(jenv, jobj, proxyResult);
return ret;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_kdf_from_info(jalgInfo /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapKdf(jenv, jobj, proxyResult);
return ret;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_salted_kdf_from_info(jalgInfo /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapSaltedKdf(jenv, jobj, proxyResult);
return ret;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_cipher_from_info(jalgInfo /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapCipher(jenv, jobj, proxyResult);
return ret;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_factory_create_padding_from_info(jalgInfo /*TODO*/, jrandom /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPadding(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass algId_cls = (*jenv)->GetObjectClass(jenv, jalgId);
jmethodID algId_methodID = (*jenv)->GetMethodID(jenv, algId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, algId_methodID);

const vscf_impl_t */*6*/ proxyResult = vscf_key_alg_factory_create_from_alg_id(alg_id /*a7*/, jrandom /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapKeyAlg(jenv, jobj, proxyResult);
return ret;

const vscf_impl_t */*6*/ proxyResult = vscf_key_alg_factory_create_from_key(jkey /*TODO*/, jrandom /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapKeyAlg(jenv, jobj, proxyResult);
return ret;

const vscf_impl_t */*6*/ proxyResult = vscf_key_alg_factory_create_from_raw_public_key(jpublicKey /*a9*/, jrandom /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapKeyAlg(jenv, jobj, proxyResult);
return ret;

const vscf_impl_t */*6*/ proxyResult = vscf_key_alg_factory_create_from_raw_private_key(jprivateKey /*a9*/, jrandom /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapKeyAlg(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_ecies_t **)&c_ctx = vscf_ecies_new();
return c_ctx;

vscf_ecies_delete(*(vscf_ecies_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

vscf_ecies_set_key_alg(ecies_ctx /*a1*/, jkeyAlg /*TODO*/);

// Cast class context
vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

vscf_ecies_release_key_alg(ecies_ctx /*a1*/);

// Cast class context
vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecies_setup_defaults(ecies_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

vscf_ecies_setup_defaults_no_random(ecies_ctx /*a1*/);

// Cast class context
vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecies_encrypted_len(ecies_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecies_encrypted_len(ecies_ctx, public_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecies_encrypt(ecies_ctx /*a1*/, jpublicKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecies_decrypted_len(ecies_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecies_decrypted_len(ecies_ctx, private_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_ecies_t /*2*/* ecies_ctx = *(vscf_ecies_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecies_decrypt(ecies_ctx /*a1*/, jprivateKey /*TODO*/, data /*a3*/, out /*a3*/);
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

jlong c_ctx = 0;
*(vscf_recipient_cipher_t **)&c_ctx = vscf_recipient_cipher_new();
return c_ctx;

vscf_recipient_cipher_delete(*(vscf_recipient_cipher_t /*2*/ **) &c_ctx /*5*/);

// Wrap input data
byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_recipient_cipher_has_key_recipient(recipient_cipher_ctx /*a1*/, recipient_id /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);

return ret;

// Wrap input data
byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_recipient_cipher_add_key_recipient(recipient_cipher_ctx /*a1*/, recipient_id /*a3*/, jpublicKey /*TODO*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);


// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_recipient_cipher_clear_recipients(recipient_cipher_ctx /*a1*/);

// Wrap input data
byte* signer_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignerId, NULL);
vsc_data_t signer_id = vsc_data(signer_id_arr, (*jenv)->GetArrayLength(jenv, jsignerId));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_recipient_cipher_add_signer(recipient_cipher_ctx /*a1*/, signer_id /*a3*/, jprivateKey /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsignerId, (jbyte*) signer_id_arr, 0);


// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_recipient_cipher_clear_signers(recipient_cipher_ctx /*a1*/);

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
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_recipient_cipher_start_encryption(recipient_cipher_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_recipient_cipher_start_signed_encryption(recipient_cipher_ctx /*a1*/, jdataSize /*a9*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_recipient_cipher_message_info_len(recipient_cipher_ctx /*a1*/);
return ret;

vsc_buffer_t *message_info = vsc_buffer_new_with_capacity(vscf_recipient_cipher_message_info_len(recipient_cipher_ctx));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_recipient_cipher_pack_message_info(recipient_cipher_ctx /*a1*/, message_info /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(message_info));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(message_info), (jbyte*) vsc_buffer_bytes(message_info));
vsc_buffer_delete(message_info);

return ret;

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_recipient_cipher_encryption_out_len(recipient_cipher_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_encryption_out_len(recipient_cipher_ctx, data.len/*a*/));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

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

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_encryption_out_len(recipient_cipher_ctx));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_recipient_cipher_finish_encryption(recipient_cipher_ctx /*a1*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Wrap input data
byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

// Wrap input data
byte* message_info_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmessageInfo, NULL);
vsc_data_t message_info = vsc_data(message_info_arr, (*jenv)->GetArrayLength(jenv, jmessageInfo));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_recipient_cipher_start_decryption_with_key(recipient_cipher_ctx /*a1*/, recipient_id /*a3*/, jprivateKey /*TODO*/, message_info /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jmessageInfo, (jbyte*) message_info_arr, 0);


// Wrap input data
byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

// Wrap input data
byte* message_info_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmessageInfo, NULL);
vsc_data_t message_info = vsc_data(message_info_arr, (*jenv)->GetArrayLength(jenv, jmessageInfo));

// Wrap input data
byte* message_info_footer_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmessageInfoFooter, NULL);
vsc_data_t message_info_footer = vsc_data(message_info_footer_arr, (*jenv)->GetArrayLength(jenv, jmessageInfoFooter));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_recipient_cipher_start_verified_decryption_with_key(recipient_cipher_ctx /*a1*/, recipient_id /*a3*/, jprivateKey /*TODO*/, message_info /*a3*/, message_info_footer /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jmessageInfo, (jbyte*) message_info_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jmessageInfoFooter, (jbyte*) message_info_footer_arr, 0);


// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_recipient_cipher_decryption_out_len(recipient_cipher_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len(recipient_cipher_ctx, data.len/*a*/));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

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

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len(recipient_cipher_ctx));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_recipient_cipher_finish_decryption(recipient_cipher_ctx /*a1*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_recipient_cipher_is_data_signed(recipient_cipher_ctx /*a1*/);
return ret;

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

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_recipient_cipher_verify_signer_info(recipient_cipher_ctx /*a1*/, jsignerInfo /*a9*/, jpublicKey /*TODO*/);
return ret;

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_recipient_cipher_message_info_footer_len(recipient_cipher_ctx /*a1*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_recipient_cipher_message_info_footer_len(recipient_cipher_ctx));

// Cast class context
vscf_recipient_cipher_t /*2*/* recipient_cipher_ctx = *(vscf_recipient_cipher_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_recipient_cipher_pack_message_info_footer(recipient_cipher_ctx /*a1*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

jlong c_ctx = 0;
*(vscf_message_info_custom_params_t **)&c_ctx = vscf_message_info_custom_params_new();
return c_ctx;

vscf_message_info_custom_params_delete(*(vscf_message_info_custom_params_t /*2*/ **) &c_ctx /*5*/);

// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Cast class context
vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

vscf_message_info_custom_params_add_int(message_info_custom_params_ctx /*a1*/, key /*a3*/, jvalue /*a9*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);


// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Wrap input data
byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

// Cast class context
vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

vscf_message_info_custom_params_add_string(message_info_custom_params_ctx /*a1*/, key /*a3*/, value /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);


// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Wrap input data
byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

// Cast class context
vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

vscf_message_info_custom_params_add_data(message_info_custom_params_ctx /*a1*/, key /*a3*/, value /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);


// Cast class context
vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

vscf_message_info_custom_params_clear(message_info_custom_params_ctx /*a1*/);

// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Cast class context
vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_custom_params_find_int(message_info_custom_params_ctx /*a1*/, key /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

return ret;

// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Cast class context
vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_message_info_custom_params_find_string(message_info_custom_params_ctx /*a1*/, key /*a3*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

return ret;

// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Cast class context
vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_message_info_custom_params_find_data(message_info_custom_params_ctx /*a1*/, key /*a3*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

return ret;

// Cast class context
vscf_message_info_custom_params_t /*2*/* message_info_custom_params_ctx = *(vscf_message_info_custom_params_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_message_info_custom_params_has_params(message_info_custom_params_ctx /*a1*/);
return ret;

jlong c_ctx = 0;
*(vscf_key_provider_t **)&c_ctx = vscf_key_provider_new();
return c_ctx;

vscf_key_provider_delete(*(vscf_key_provider_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_key_provider_setup_defaults(key_provider_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

vscf_key_provider_set_rsa_params(key_provider_ctx /*a1*/, jbitlen /*a9*/);

// Wrap enums
jclass algId_cls = (*jenv)->GetObjectClass(jenv, jalgId);
jmethodID algId_methodID = (*jenv)->GetMethodID(jenv, algId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, algId_methodID);

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_private_key(key_provider_ctx /*a1*/, alg_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_post_quantum_private_key(key_provider_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass cipherAlgId_cls = (*jenv)->GetObjectClass(jenv, jcipherAlgId);
jmethodID cipherAlgId_methodID = (*jenv)->GetMethodID(jenv, cipherAlgId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ cipher_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jcipherAlgId, cipherAlgId_methodID);

// Wrap enums
jclass signerAlgId_cls = (*jenv)->GetObjectClass(jenv, jsignerAlgId);
jmethodID signerAlgId_methodID = (*jenv)->GetMethodID(jenv, signerAlgId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ signer_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jsignerAlgId, signerAlgId_methodID);

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_compound_private_key(key_provider_ctx /*a1*/, cipher_alg_id /*a7*/, signer_alg_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass firstKeyAlgId_cls = (*jenv)->GetObjectClass(jenv, jfirstKeyAlgId);
jmethodID firstKeyAlgId_methodID = (*jenv)->GetMethodID(jenv, firstKeyAlgId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ first_key_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jfirstKeyAlgId, firstKeyAlgId_methodID);

// Wrap enums
jclass secondKeyAlgId_cls = (*jenv)->GetObjectClass(jenv, jsecondKeyAlgId);
jmethodID secondKeyAlgId_methodID = (*jenv)->GetMethodID(jenv, secondKeyAlgId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ second_key_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jsecondKeyAlgId, secondKeyAlgId_methodID);

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_hybrid_private_key(key_provider_ctx /*a1*/, first_key_alg_id /*a7*/, second_key_alg_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass cipherFirstKeyAlgId_cls = (*jenv)->GetObjectClass(jenv, jcipherFirstKeyAlgId);
jmethodID cipherFirstKeyAlgId_methodID = (*jenv)->GetMethodID(jenv, cipherFirstKeyAlgId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ cipher_first_key_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jcipherFirstKeyAlgId, cipherFirstKeyAlgId_methodID);

// Wrap enums
jclass cipherSecondKeyAlgId_cls = (*jenv)->GetObjectClass(jenv, jcipherSecondKeyAlgId);
jmethodID cipherSecondKeyAlgId_methodID = (*jenv)->GetMethodID(jenv, cipherSecondKeyAlgId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ cipher_second_key_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jcipherSecondKeyAlgId, cipherSecondKeyAlgId_methodID);

// Wrap enums
jclass signerFirstKeyAlgId_cls = (*jenv)->GetObjectClass(jenv, jsignerFirstKeyAlgId);
jmethodID signerFirstKeyAlgId_methodID = (*jenv)->GetMethodID(jenv, signerFirstKeyAlgId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ signer_first_key_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jsignerFirstKeyAlgId, signerFirstKeyAlgId_methodID);

// Wrap enums
jclass signerSecondKeyAlgId_cls = (*jenv)->GetObjectClass(jenv, jsignerSecondKeyAlgId);
jmethodID signerSecondKeyAlgId_methodID = (*jenv)->GetMethodID(jenv, signerSecondKeyAlgId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ signer_second_key_alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jsignerSecondKeyAlgId, signerSecondKeyAlgId_methodID);

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_generate_compound_hybrid_private_key(key_provider_ctx /*a1*/, cipher_first_key_alg_id /*a7*/, cipher_second_key_alg_id /*a7*/, signer_first_key_alg_id /*a7*/, signer_second_key_alg_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Wrap input data
byte* key_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkeyData, NULL);
vsc_data_t key_data = vsc_data(key_data_arr, (*jenv)->GetArrayLength(jenv, jkeyData));

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_import_private_key(key_provider_ctx /*a1*/, key_data /*a3*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkeyData, (jbyte*) key_data_arr, 0);

return ret;

// Wrap input data
byte* key_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkeyData, NULL);
vsc_data_t key_data = vsc_data(key_data_arr, (*jenv)->GetArrayLength(jenv, jkeyData));

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_key_provider_import_public_key(key_provider_ctx /*a1*/, key_data /*a3*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkeyData, (jbyte*) key_data_arr, 0);

return ret;

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_key_provider_exported_public_key_len(key_provider_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_key_provider_exported_public_key_len(key_provider_ctx, public_key.len/*a*/));

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_key_provider_export_public_key(key_provider_ctx /*a1*/, jpublicKey /*TODO*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_key_provider_exported_private_key_len(key_provider_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_key_provider_exported_private_key_len(key_provider_ctx, private_key.len/*a*/));

// Cast class context
vscf_key_provider_t /*2*/* key_provider_ctx = *(vscf_key_provider_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_key_provider_export_private_key(key_provider_ctx /*a1*/, jprivateKey /*TODO*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

jlong c_ctx = 0;
*(vscf_signer_t **)&c_ctx = vscf_signer_new();
return c_ctx;

vscf_signer_delete(*(vscf_signer_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_signer_t /*2*/* signer_ctx = *(vscf_signer_t /*2*/**) &c_ctx;

vscf_signer_reset(signer_ctx /*a1*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_signer_t /*2*/* signer_ctx = *(vscf_signer_t /*2*/**) &c_ctx;

vscf_signer_append_data(signer_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);


// Cast class context
vscf_signer_t /*2*/* signer_ctx = *(vscf_signer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_signer_signature_len(signer_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_signer_signature_len(signer_ctx, private_key.len/*a*/));

// Cast class context
vscf_signer_t /*2*/* signer_ctx = *(vscf_signer_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_signer_sign(signer_ctx /*a1*/, jprivateKey /*TODO*/, signature /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), (jbyte*) vsc_buffer_bytes(signature));
vsc_buffer_delete(signature);

return ret;

jlong c_ctx = 0;
*(vscf_verifier_t **)&c_ctx = vscf_verifier_new();
return c_ctx;

vscf_verifier_delete(*(vscf_verifier_t /*2*/ **) &c_ctx /*5*/);

// Wrap input data
byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

// Cast class context
vscf_verifier_t /*2*/* verifier_ctx = *(vscf_verifier_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_verifier_reset(verifier_ctx /*a1*/, signature /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);


// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_verifier_t /*2*/* verifier_ctx = *(vscf_verifier_t /*2*/**) &c_ctx;

vscf_verifier_append_data(verifier_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);


// Cast class context
vscf_verifier_t /*2*/* verifier_ctx = *(vscf_verifier_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_verifier_verify(verifier_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

jlong c_ctx = 0;
*(vscf_brainkey_client_t **)&c_ctx = vscf_brainkey_client_new();
return c_ctx;

vscf_brainkey_client_delete(*(vscf_brainkey_client_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_brainkey_client_t /*2*/* brainkey_client_ctx = *(vscf_brainkey_client_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_brainkey_client_setup_defaults(brainkey_client_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(mpi len);

vsc_buffer_t *blinded_point = vsc_buffer_new_with_capacity(point len);

// Cast class context
vscf_brainkey_client_t /*2*/* brainkey_client_ctx = *(vscf_brainkey_client_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_brainkey_client_blind(brainkey_client_ctx /*a1*/, password /*a3*/, deblind_factor /*a3*/, blinded_point /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/BrainkeyClientBlindResult");
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

vsc_buffer_delete(deblind_factor);

vsc_buffer_delete(blinded_point);

return ret;

// Wrap input data
byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

// Wrap input data
byte* hardened_point_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jhardenedPoint, NULL);
vsc_data_t hardened_point = vsc_data(hardened_point_arr, (*jenv)->GetArrayLength(jenv, jhardenedPoint));

// Wrap input data
byte* deblind_factor_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdeblindFactor, NULL);
vsc_data_t deblind_factor = vsc_data(deblind_factor_arr, (*jenv)->GetArrayLength(jenv, jdeblindFactor));

// Wrap input data
byte* key_name_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkeyName, NULL);
vsc_data_t key_name = vsc_data(key_name_arr, (*jenv)->GetArrayLength(jenv, jkeyName));

vsc_buffer_t *seed = vsc_buffer_new_with_capacity(point len);

// Cast class context
vscf_brainkey_client_t /*2*/* brainkey_client_ctx = *(vscf_brainkey_client_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_brainkey_client_deblind(brainkey_client_ctx /*a1*/, password /*a3*/, hardened_point /*a3*/, deblind_factor /*a3*/, key_name /*a3*/, seed /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(seed));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(seed), (jbyte*) vsc_buffer_bytes(seed));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jhardenedPoint, (jbyte*) hardened_point_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdeblindFactor, (jbyte*) deblind_factor_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkeyName, (jbyte*) key_name_arr, 0);

vsc_buffer_delete(seed);

return ret;

jlong c_ctx = 0;
*(vscf_brainkey_server_t **)&c_ctx = vscf_brainkey_server_new();
return c_ctx;

vscf_brainkey_server_delete(*(vscf_brainkey_server_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_brainkey_server_t /*2*/* brainkey_server_ctx = *(vscf_brainkey_server_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_brainkey_server_setup_defaults(brainkey_server_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

vsc_buffer_t *identity_secret = vsc_buffer_new_with_capacity(mpi len);

// Cast class context
vscf_brainkey_server_t /*2*/* brainkey_server_ctx = *(vscf_brainkey_server_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_brainkey_server_generate_identity_secret(brainkey_server_ctx /*a1*/, identity_secret /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(identity_secret));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(identity_secret), (jbyte*) vsc_buffer_bytes(identity_secret));
vsc_buffer_delete(identity_secret);

return ret;

// Wrap input data
byte* identity_secret_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jidentitySecret, NULL);
vsc_data_t identity_secret = vsc_data(identity_secret_arr, (*jenv)->GetArrayLength(jenv, jidentitySecret));

// Wrap input data
byte* blinded_point_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jblindedPoint, NULL);
vsc_data_t blinded_point = vsc_data(blinded_point_arr, (*jenv)->GetArrayLength(jenv, jblindedPoint));

vsc_buffer_t *hardened_point = vsc_buffer_new_with_capacity(point len);

// Cast class context
vscf_brainkey_server_t /*2*/* brainkey_server_ctx = *(vscf_brainkey_server_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_brainkey_server_harden(brainkey_server_ctx /*a1*/, identity_secret /*a3*/, blinded_point /*a3*/, hardened_point /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(hardened_point));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(hardened_point), (jbyte*) vsc_buffer_bytes(hardened_point));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jidentitySecret, (jbyte*) identity_secret_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jblindedPoint, (jbyte*) blinded_point_arr, 0);

vsc_buffer_delete(hardened_point);

return ret;

jlong c_ctx = 0;
*(vscf_group_session_message_t **)&c_ctx = vscf_group_session_message_new();
return c_ctx;

vscf_group_session_message_delete(*(vscf_group_session_message_t /*2*/ **) &c_ctx /*5*/);

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

// Cast class context
vscf_group_session_message_t /*2*/* group_session_message_ctx = *(vscf_group_session_message_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_group_session_message_get_session_id(group_session_message_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_group_session_message_t /*2*/* group_session_message_ctx = *(vscf_group_session_message_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_group_session_message_get_epoch(group_session_message_ctx /*a1*/);
return ret;

// Cast class context
vscf_group_session_message_t /*2*/* group_session_message_ctx = *(vscf_group_session_message_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_group_session_message_serialize_len(group_session_message_ctx /*a1*/);
return ret;

vsc_buffer_t *output = vsc_buffer_new_with_capacity(vscf_group_session_message_serialize_len(group_session_message_ctx));

// Cast class context
vscf_group_session_message_t /*2*/* group_session_message_ctx = *(vscf_group_session_message_t /*2*/**) &c_ctx;

vscf_group_session_message_serialize(group_session_message_ctx /*a1*/, output /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(output));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(output), (jbyte*) vsc_buffer_bytes(output));
vsc_buffer_delete(output);

return ret;

// Wrap input data
byte* input_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinput, NULL);
vsc_data_t input = vsc_data(input_arr, (*jenv)->GetArrayLength(jenv, jinput));

const vscf_self_t */*5*/ proxyResult = vscf_group_session_message_deserialize(input /*a3*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Self");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Self not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/Self;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Self has no 'getInstance' method.");
}
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jinput, (jbyte*) input_arr, 0);

return ret;

jlong c_ctx = 0;
*(vscf_group_session_ticket_t **)&c_ctx = vscf_group_session_ticket_new();
return c_ctx;

vscf_group_session_ticket_delete(*(vscf_group_session_ticket_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_group_session_ticket_t /*2*/* group_session_ticket_ctx = *(vscf_group_session_ticket_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_group_session_ticket_setup_defaults(group_session_ticket_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* session_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsessionId, NULL);
vsc_data_t session_id = vsc_data(session_id_arr, (*jenv)->GetArrayLength(jenv, jsessionId));

// Cast class context
vscf_group_session_ticket_t /*2*/* group_session_ticket_ctx = *(vscf_group_session_ticket_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_group_session_ticket_setup_ticket_as_new(group_session_ticket_ctx /*a1*/, session_id /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsessionId, (jbyte*) session_id_arr, 0);


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

jlong c_ctx = 0;
*(vscf_group_session_t **)&c_ctx = vscf_group_session_new();
return c_ctx;

vscf_group_session_delete(*(vscf_group_session_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_group_session_get_current_epoch(group_session_ctx /*a1*/);
return ret;

// Cast class context
vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_group_session_setup_defaults(group_session_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_group_session_get_session_id(group_session_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_group_session_add_epoch(group_session_ctx /*a1*/, jmessage /*a9*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* plain_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jplainText, NULL);
vsc_data_t plain_text = vsc_data(plain_text_arr, (*jenv)->GetArrayLength(jenv, jplainText));

// Cast class context
vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

const vscf_group_session_message_t */*5*/ proxyResult = vscf_group_session_encrypt(group_session_ctx /*a1*/, plain_text /*a3*/, jprivateKey /*TODO*/);
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

// Cast class context
vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_group_session_decrypt_len(group_session_ctx /*a1*/, jmessage /*a9*/);
return ret;

vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vscf_group_session_decrypt_len(group_session_ctx, message.len/*a*/));

// Cast class context
vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_group_session_decrypt(group_session_ctx /*a1*/, jmessage /*a9*/, jpublicKey /*TODO*/, plain_text /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), (jbyte*) vsc_buffer_bytes(plain_text));
vsc_buffer_delete(plain_text);

return ret;

// Cast class context
vscf_group_session_t /*2*/* group_session_ctx = *(vscf_group_session_t /*2*/**) &c_ctx;

const vscf_group_session_ticket_t */*5*/ proxyResult = vscf_group_session_create_group_ticket(group_session_ctx /*a1*/);
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

jlong c_ctx = 0;
*(vscf_message_info_editor_t **)&c_ctx = vscf_message_info_editor_new();
return c_ctx;

vscf_message_info_editor_delete(*(vscf_message_info_editor_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_message_info_editor_setup_defaults(message_info_editor_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* message_info_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jmessageInfoData, NULL);
vsc_data_t message_info_data = vsc_data(message_info_data_arr, (*jenv)->GetArrayLength(jenv, jmessageInfoData));

// Cast class context
vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_message_info_editor_unpack(message_info_editor_ctx /*a1*/, message_info_data /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jmessageInfoData, (jbyte*) message_info_data_arr, 0);


// Wrap input data
byte* owner_recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jownerRecipientId, NULL);
vsc_data_t owner_recipient_id = vsc_data(owner_recipient_id_arr, (*jenv)->GetArrayLength(jenv, jownerRecipientId));

// Cast class context
vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_message_info_editor_unlock(message_info_editor_ctx /*a1*/, owner_recipient_id /*a3*/, jownerPrivateKey /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jownerRecipientId, (jbyte*) owner_recipient_id_arr, 0);


// Wrap input data
byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

// Cast class context
vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_message_info_editor_add_key_recipient(message_info_editor_ctx /*a1*/, recipient_id /*a3*/, jpublicKey /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);


// Wrap input data
byte* recipient_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jrecipientId, NULL);
vsc_data_t recipient_id = vsc_data(recipient_id_arr, (*jenv)->GetArrayLength(jenv, jrecipientId));

// Cast class context
vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_message_info_editor_remove_key_recipient(message_info_editor_ctx /*a1*/, recipient_id /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jrecipientId, (jbyte*) recipient_id_arr, 0);

return ret;

// Cast class context
vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

vscf_message_info_editor_remove_all(message_info_editor_ctx /*a1*/);

// Cast class context
vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_editor_packed_len(message_info_editor_ctx /*a1*/);
return ret;

vsc_buffer_t *message_info = vsc_buffer_new_with_capacity(vscf_message_info_editor_packed_len(message_info_editor_ctx));

// Cast class context
vscf_message_info_editor_t /*2*/* message_info_editor_ctx = *(vscf_message_info_editor_t /*2*/**) &c_ctx;

vscf_message_info_editor_pack(message_info_editor_ctx /*a1*/, message_info /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(message_info));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(message_info), (jbyte*) vsc_buffer_bytes(message_info));
vsc_buffer_delete(message_info);

return ret;

jlong c_ctx = 0;
*(vscf_signer_info_t **)&c_ctx = vscf_signer_info_new();
return c_ctx;

vscf_signer_info_delete(*(vscf_signer_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_signer_info_t /*2*/* signer_info_ctx = *(vscf_signer_info_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_signer_info_signer_id(signer_info_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_signer_info_t /*2*/* signer_info_ctx = *(vscf_signer_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_signer_info_signer_alg_info(signer_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_signer_info_t /*2*/* signer_info_ctx = *(vscf_signer_info_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_signer_info_signature(signer_info_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

jlong c_ctx = 0;
*(vscf_signer_info_list_t **)&c_ctx = vscf_signer_info_list_new();
return c_ctx;

vscf_signer_info_list_delete(*(vscf_signer_info_list_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_signer_info_list_has_item(signer_info_list_ctx /*a1*/);
return ret;

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

// Cast class context
vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_signer_info_list_has_next(signer_info_list_ctx /*a1*/);
return ret;

// Cast class context
vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

const vscf_self_t */*5*/ proxyResult = vscf_signer_info_list_next(signer_info_list_ctx /*a1*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Self");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Self not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/Self;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Self has no 'getInstance' method.");
}
vscf_self_shallow_copy((vscf_self_t */*5*/) proxyResult);
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

// Cast class context
vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_signer_info_list_has_prev(signer_info_list_ctx /*a1*/);
return ret;

// Cast class context
vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

const vscf_self_t */*5*/ proxyResult = vscf_signer_info_list_prev(signer_info_list_ctx /*a1*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Self");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Self not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/Self;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Self has no 'getInstance' method.");
}
vscf_self_shallow_copy((vscf_self_t */*5*/) proxyResult);
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

// Cast class context
vscf_signer_info_list_t /*2*/* signer_info_list_ctx = *(vscf_signer_info_list_t /*2*/**) &c_ctx;

vscf_signer_info_list_clear(signer_info_list_ctx /*a1*/);

jlong c_ctx = 0;
*(vscf_message_info_footer_t **)&c_ctx = vscf_message_info_footer_new();
return c_ctx;

vscf_message_info_footer_delete(*(vscf_message_info_footer_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_message_info_footer_t /*2*/* message_info_footer_ctx = *(vscf_message_info_footer_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_message_info_footer_has_signer_infos(message_info_footer_ctx /*a1*/);
return ret;

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

// Cast class context
vscf_message_info_footer_t /*2*/* message_info_footer_ctx = *(vscf_message_info_footer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_message_info_footer_signer_hash_alg_info(message_info_footer_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_message_info_footer_t /*2*/* message_info_footer_ctx = *(vscf_message_info_footer_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_message_info_footer_signer_digest(message_info_footer_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

jlong c_ctx = 0;
*(vscf_signed_data_info_t **)&c_ctx = vscf_signed_data_info_new();
return c_ctx;

vscf_signed_data_info_delete(*(vscf_signed_data_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_signed_data_info_t /*2*/* signed_data_info_ctx = *(vscf_signed_data_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_signed_data_info_hash_alg_info(signed_data_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_footer_info_t **)&c_ctx = vscf_footer_info_new();
return c_ctx;

vscf_footer_info_delete(*(vscf_footer_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_footer_info_t /*2*/* footer_info_ctx = *(vscf_footer_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_footer_info_has_signed_data_info(footer_info_ctx /*a1*/);
return ret;

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

// Cast class context
vscf_footer_info_t /*2*/* footer_info_ctx = *(vscf_footer_info_t /*2*/**) &c_ctx;

vscf_footer_info_set_data_size(footer_info_ctx /*a1*/, jdataSize /*a9*/);

// Cast class context
vscf_footer_info_t /*2*/* footer_info_ctx = *(vscf_footer_info_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_footer_info_data_size(footer_info_ctx /*a1*/);
return ret;

jlong c_ctx = 0;
*(vscf_key_info_t **)&c_ctx = vscf_key_info_new();
return c_ctx;

vscf_key_info_delete(*(vscf_key_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_info_is_compound(key_info_ctx /*a1*/);
return ret;

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_info_is_hybrid(key_info_ctx /*a1*/);
return ret;

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_info_is_compound_hybrid(key_info_ctx /*a1*/);
return ret;

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_info_is_compound_hybrid_cipher(key_info_ctx /*a1*/);
return ret;

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_info_is_compound_hybrid_signer(key_info_ctx /*a1*/);
return ret;

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_info_is_hybrid_post_quantum(key_info_ctx /*a1*/);
return ret;

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_info_is_hybrid_post_quantum_cipher(key_info_ctx /*a1*/);
return ret;

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_key_info_is_hybrid_post_quantum_signer(key_info_ctx /*a1*/);
return ret;

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

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

const vscf_alg_id_t proxyResult = vscf_key_info_hybrid_first_key_alg_id(key_info_ctx /*a1*/);
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

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

const vscf_alg_id_t proxyResult = vscf_key_info_hybrid_second_key_alg_id(key_info_ctx /*a1*/);
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

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

const vscf_alg_id_t proxyResult = vscf_key_info_compound_hybrid_cipher_first_key_alg_id(key_info_ctx /*a1*/);
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

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

const vscf_alg_id_t proxyResult = vscf_key_info_compound_hybrid_cipher_second_key_alg_id(key_info_ctx /*a1*/);
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

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

const vscf_alg_id_t proxyResult = vscf_key_info_compound_hybrid_signer_first_key_alg_id(key_info_ctx /*a1*/);
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

// Cast class context
vscf_key_info_t /*2*/* key_info_ctx = *(vscf_key_info_t /*2*/**) &c_ctx;

const vscf_alg_id_t proxyResult = vscf_key_info_compound_hybrid_signer_second_key_alg_id(key_info_ctx /*a1*/);
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

jlong c_ctx = 0;
*(vscf_padding_params_t **)&c_ctx = vscf_padding_params_new();
return c_ctx;

vscf_padding_params_delete(*(vscf_padding_params_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_padding_params_t /*2*/* padding_params_ctx = *(vscf_padding_params_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_padding_params_frame(padding_params_ctx /*a1*/);
return ret;

// Cast class context
vscf_padding_params_t /*2*/* padding_params_ctx = *(vscf_padding_params_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_padding_params_frame_max(padding_params_ctx /*a1*/);
return ret;

jlong c_ctx = 0;
*(vscf_sha224_t **)&c_ctx = vscf_sha224_new();
return c_ctx;

vscf_sha224_delete(*(vscf_sha224_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_sha224_t /*2*/* sha224_ctx = *(vscf_sha224_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_sha224_t /*2*/* sha224_ctx = *(vscf_sha224_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_sha224_produce_alg_info(sha224_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_sha224_t /*2*/* sha224_ctx = *(vscf_sha224_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_sha224_restore_alg_info(sha224_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *digest = vsc_buffer_new_with_capacity(digest len);

vscf_sha224_hash(data /*a3*/, digest /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(digest);

return ret;

// Cast class context
vscf_sha224_t /*2*/* sha224_ctx = *(vscf_sha224_t /*2*/**) &c_ctx;

vscf_sha224_start(sha224_ctx /*a1*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_sha224_t /*2*/* sha224_ctx = *(vscf_sha224_t /*2*/**) &c_ctx;

vscf_sha224_update(sha224_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);


vsc_buffer_t *digest = vsc_buffer_new_with_capacity(digest len);

// Cast class context
vscf_sha224_t /*2*/* sha224_ctx = *(vscf_sha224_t /*2*/**) &c_ctx;

vscf_sha224_finish(sha224_ctx /*a1*/, digest /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
vsc_buffer_delete(digest);

return ret;

jlong c_ctx = 0;
*(vscf_sha256_t **)&c_ctx = vscf_sha256_new();
return c_ctx;

vscf_sha256_delete(*(vscf_sha256_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_sha256_t /*2*/* sha256_ctx = *(vscf_sha256_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_sha256_t /*2*/* sha256_ctx = *(vscf_sha256_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_sha256_produce_alg_info(sha256_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_sha256_t /*2*/* sha256_ctx = *(vscf_sha256_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_sha256_restore_alg_info(sha256_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *digest = vsc_buffer_new_with_capacity(digest len);

vscf_sha256_hash(data /*a3*/, digest /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(digest);

return ret;

// Cast class context
vscf_sha256_t /*2*/* sha256_ctx = *(vscf_sha256_t /*2*/**) &c_ctx;

vscf_sha256_start(sha256_ctx /*a1*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_sha256_t /*2*/* sha256_ctx = *(vscf_sha256_t /*2*/**) &c_ctx;

vscf_sha256_update(sha256_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);


vsc_buffer_t *digest = vsc_buffer_new_with_capacity(digest len);

// Cast class context
vscf_sha256_t /*2*/* sha256_ctx = *(vscf_sha256_t /*2*/**) &c_ctx;

vscf_sha256_finish(sha256_ctx /*a1*/, digest /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
vsc_buffer_delete(digest);

return ret;

jlong c_ctx = 0;
*(vscf_sha384_t **)&c_ctx = vscf_sha384_new();
return c_ctx;

vscf_sha384_delete(*(vscf_sha384_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_sha384_t /*2*/* sha384_ctx = *(vscf_sha384_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_sha384_t /*2*/* sha384_ctx = *(vscf_sha384_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_sha384_produce_alg_info(sha384_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_sha384_t /*2*/* sha384_ctx = *(vscf_sha384_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_sha384_restore_alg_info(sha384_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *digest = vsc_buffer_new_with_capacity(digest len);

vscf_sha384_hash(data /*a3*/, digest /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(digest);

return ret;

// Cast class context
vscf_sha384_t /*2*/* sha384_ctx = *(vscf_sha384_t /*2*/**) &c_ctx;

vscf_sha384_start(sha384_ctx /*a1*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_sha384_t /*2*/* sha384_ctx = *(vscf_sha384_t /*2*/**) &c_ctx;

vscf_sha384_update(sha384_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);


vsc_buffer_t *digest = vsc_buffer_new_with_capacity(digest len);

// Cast class context
vscf_sha384_t /*2*/* sha384_ctx = *(vscf_sha384_t /*2*/**) &c_ctx;

vscf_sha384_finish(sha384_ctx /*a1*/, digest /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
vsc_buffer_delete(digest);

return ret;

jlong c_ctx = 0;
*(vscf_sha512_t **)&c_ctx = vscf_sha512_new();
return c_ctx;

vscf_sha512_delete(*(vscf_sha512_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_sha512_t /*2*/* sha512_ctx = *(vscf_sha512_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_sha512_t /*2*/* sha512_ctx = *(vscf_sha512_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_sha512_produce_alg_info(sha512_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_sha512_t /*2*/* sha512_ctx = *(vscf_sha512_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_sha512_restore_alg_info(sha512_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *digest = vsc_buffer_new_with_capacity(digest len);

vscf_sha512_hash(data /*a3*/, digest /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(digest);

return ret;

// Cast class context
vscf_sha512_t /*2*/* sha512_ctx = *(vscf_sha512_t /*2*/**) &c_ctx;

vscf_sha512_start(sha512_ctx /*a1*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_sha512_t /*2*/* sha512_ctx = *(vscf_sha512_t /*2*/**) &c_ctx;

vscf_sha512_update(sha512_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);


vsc_buffer_t *digest = vsc_buffer_new_with_capacity(digest len);

// Cast class context
vscf_sha512_t /*2*/* sha512_ctx = *(vscf_sha512_t /*2*/**) &c_ctx;

vscf_sha512_finish(sha512_ctx /*a1*/, digest /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(digest));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(digest), (jbyte*) vsc_buffer_bytes(digest));
vsc_buffer_delete(digest);

return ret;

jlong c_ctx = 0;
*(vscf_aes256_gcm_t **)&c_ctx = vscf_aes256_gcm_new();
return c_ctx;

vscf_aes256_gcm_delete(*(vscf_aes256_gcm_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_aes256_gcm_produce_alg_info(aes256_gcm_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_aes256_gcm_restore_alg_info(aes256_gcm_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_encrypted_len(aes256_gcm_ctx, data.len/*a*/));

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_gcm_encrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_gcm_precise_encrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_decrypted_len(aes256_gcm_ctx, data.len/*a*/));

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_gcm_decrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* nonce_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jnonce, NULL);
vsc_data_t nonce = vsc_data(nonce_arr, (*jenv)->GetArrayLength(jenv, jnonce));

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_aes256_gcm_set_nonce(aes256_gcm_ctx /*a1*/, nonce /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jnonce, (jbyte*) nonce_arr, 0);


// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_aes256_gcm_set_key(aes256_gcm_ctx /*a1*/, key /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);


// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_aes256_gcm_start_encryption(aes256_gcm_ctx /*a1*/);

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_aes256_gcm_start_decryption(aes256_gcm_ctx /*a1*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len(aes256_gcm_ctx, data.len/*a*/));

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_aes256_gcm_update(aes256_gcm_ctx /*a1*/, data /*a3*/, out /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_gcm_out_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_gcm_encrypted_out_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_gcm_decrypted_out_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len(aes256_gcm_ctx));

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_aes256_gcm_finish(aes256_gcm_ctx /*a1*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Wrap input data
byte* auth_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jauthData, NULL);
vsc_data_t auth_data = vsc_data(auth_data_arr, (*jenv)->GetArrayLength(jenv, jauthData));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_auth_encrypted_len(aes256_gcm_ctx, data.len/*a*/));

vsc_buffer_t *tag = vsc_buffer_new_with_capacity(auth tag len);

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_aes256_gcm_auth_encrypt(aes256_gcm_ctx /*a1*/, data /*a3*/, auth_data /*a3*/, out /*a3*/, tag /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Aes256GcmAuthEncryptResult");
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jauthData, (jbyte*) auth_data_arr, 0);

vsc_buffer_delete(out);

vsc_buffer_delete(tag);

return ret;

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_gcm_auth_encrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Wrap input data
byte* auth_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jauthData, NULL);
vsc_data_t auth_data = vsc_data(auth_data_arr, (*jenv)->GetArrayLength(jenv, jauthData));

// Wrap input data
byte* tag_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtag, NULL);
vsc_data_t tag = vsc_data(tag_arr, (*jenv)->GetArrayLength(jenv, jtag));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_auth_decrypted_len(aes256_gcm_ctx, data.len/*a*/));

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_aes256_gcm_auth_decrypt(aes256_gcm_ctx /*a1*/, data /*a3*/, auth_data /*a3*/, tag /*a3*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jauthData, (jbyte*) auth_data_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jtag, (jbyte*) tag_arr, 0);

vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_gcm_auth_decrypted_len(aes256_gcm_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* auth_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jauthData, NULL);
vsc_data_t auth_data = vsc_data(auth_data_arr, (*jenv)->GetArrayLength(jenv, jauthData));

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_aes256_gcm_set_auth_data(aes256_gcm_ctx /*a1*/, auth_data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jauthData, (jbyte*) auth_data_arr, 0);


vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len(aes256_gcm_ctx));

vsc_buffer_t *tag = vsc_buffer_new_with_capacity(auth tag len);

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_aes256_gcm_finish_auth_encryption(aes256_gcm_ctx /*a1*/, out /*a3*/, tag /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Aes256GcmFinishAuthEncryptionResult");
vsc_buffer_delete(out);

vsc_buffer_delete(tag);

return ret;

// Wrap input data
byte* tag_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jtag, NULL);
vsc_data_t tag = vsc_data(tag_arr, (*jenv)->GetArrayLength(jenv, jtag));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_gcm_out_len(aes256_gcm_ctx));

// Cast class context
vscf_aes256_gcm_t /*2*/* aes256_gcm_ctx = *(vscf_aes256_gcm_t /*2*/**) &c_ctx;

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

jlong c_ctx = 0;
*(vscf_aes256_cbc_t **)&c_ctx = vscf_aes256_cbc_new();
return c_ctx;

vscf_aes256_cbc_delete(*(vscf_aes256_cbc_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_aes256_cbc_produce_alg_info(aes256_cbc_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_aes256_cbc_restore_alg_info(aes256_cbc_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_encrypted_len(aes256_cbc_ctx, data.len/*a*/));

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_cbc_encrypted_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_cbc_precise_encrypted_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_decrypted_len(aes256_cbc_ctx, data.len/*a*/));

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_cbc_decrypted_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* nonce_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jnonce, NULL);
vsc_data_t nonce = vsc_data(nonce_arr, (*jenv)->GetArrayLength(jenv, jnonce));

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

vscf_aes256_cbc_set_nonce(aes256_cbc_ctx /*a1*/, nonce /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jnonce, (jbyte*) nonce_arr, 0);


// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

vscf_aes256_cbc_set_key(aes256_cbc_ctx /*a1*/, key /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);


// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

vscf_aes256_cbc_start_encryption(aes256_cbc_ctx /*a1*/);

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

vscf_aes256_cbc_start_decryption(aes256_cbc_ctx /*a1*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_out_len(aes256_cbc_ctx, data.len/*a*/));

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

vscf_aes256_cbc_update(aes256_cbc_ctx /*a1*/, data /*a3*/, out /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_cbc_out_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_cbc_encrypted_out_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_aes256_cbc_decrypted_out_len(aes256_cbc_ctx /*a1*/, jdataLen /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_aes256_cbc_out_len(aes256_cbc_ctx));

// Cast class context
vscf_aes256_cbc_t /*2*/* aes256_cbc_ctx = *(vscf_aes256_cbc_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_aes256_cbc_finish(aes256_cbc_ctx /*a1*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

jlong c_ctx = 0;
*(vscf_asn1rd_t **)&c_ctx = vscf_asn1rd_new();
return c_ctx;

vscf_asn1rd_delete(*(vscf_asn1rd_t /*2*/ **) &c_ctx /*5*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

vscf_asn1rd_reset(asn1rd_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);


// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_left_len(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_asn1rd_has_error(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_asn1rd_status(asn1rd_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_get_tag(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_get_len(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_get_data_len(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_tag(asn1rd_ctx /*a1*/, jtag /*a9*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_context_tag(asn1rd_ctx /*a1*/, jtag /*a9*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_int(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_int8(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_int16(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_int32(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_int64(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_uint(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_uint8(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_uint16(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_uint32(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_uint64(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_asn1rd_read_bool(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

vscf_asn1rd_read_null(asn1rd_ctx /*a1*/);

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

vscf_asn1rd_read_null_optional(asn1rd_ctx /*a1*/);

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_octet_str(asn1rd_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_bitstring_as_octet_str(asn1rd_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_utf8_str(asn1rd_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_oid(asn1rd_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_data(asn1rd_ctx /*a1*/, jlen /*a9*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_sequence(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1rd_read_set(asn1rd_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_asn1rd_mbedtls_has_error(asn1rd_ctx /*a1*/, jcode /*a9*/);
return ret;

// Cast class context
vscf_asn1rd_t /*2*/* asn1rd_ctx = *(vscf_asn1rd_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_asn1rd_read_tag_data(asn1rd_ctx /*a1*/, jtag /*a9*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

jlong c_ctx = 0;
*(vscf_asn1wr_t **)&c_ctx = vscf_asn1wr_new();
return c_ctx;

vscf_asn1wr_delete(*(vscf_asn1wr_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

vscf_asn1wr_reset(asn1wr_ctx /*a1*/, jout /*a9*/, joutLen /*a9*/);

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_finish(asn1wr_ctx /*a1*/, jdoNotAdjust /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

vscf_asn1wr_bytes(asn1wr_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_len(asn1wr_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_written_len(asn1wr_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_unwritten_len(asn1wr_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_asn1wr_has_error(asn1wr_ctx /*a1*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_asn1wr_status(asn1wr_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

vscf_asn1wr_reserve(asn1wr_ctx /*a1*/, jlen /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_tag(asn1wr_ctx /*a1*/, jtag /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_context_tag(asn1wr_ctx /*a1*/, jtag /*a9*/, jlen /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_len(asn1wr_ctx /*a1*/, jlen /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_int(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_int8(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_int16(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_int32(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_int64(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_uint(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_uint8(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_uint16(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_uint32(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_uint64(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_bool(asn1wr_ctx /*a1*/, jvalue /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_null(asn1wr_ctx /*a1*/);
return ret;

// Wrap input data
byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_octet_str(asn1wr_ctx /*a1*/, value /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);

return ret;

// Wrap input data
byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_octet_str_as_bitstring(asn1wr_ctx /*a1*/, value /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);

return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_data(asn1wr_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

return ret;

// Wrap input data
byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_utf8_str(asn1wr_ctx /*a1*/, value /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);

return ret;

// Wrap input data
byte* value_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jvalue, NULL);
vsc_data_t value = vsc_data(value_arr, (*jenv)->GetArrayLength(jenv, jvalue));

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_oid(asn1wr_ctx /*a1*/, value /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jvalue, (jbyte*) value_arr, 0);

return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_sequence(asn1wr_ctx /*a1*/, jlen /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_set(asn1wr_ctx /*a1*/, jlen /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_asn1wr_mbedtls_has_error(asn1wr_ctx /*a1*/, jcode /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_asn1wr_write_tag_data(asn1wr_ctx /*a1*/, data /*a3*/, jtag /*a9*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

return ret;

jint ret = (jint) vscf_asn1wr_get_current_element_len(jcurr /*a9*/, jend /*a9*/);
return ret;

vscf_asn1wr_swap_elements_of_set(jtoStart /*a9*/, jtoLen /*a9*/, jfromStart /*a9*/, jfromLen /*a9*/);

jboolean ret = (jboolean) vscf_asn1wr_second_element_of_set_is_less(jfirstStart /*a9*/, jfirstLen /*a9*/, jsecondStart /*a9*/, jsecondLen /*a9*/);
return ret;

// Cast class context
vscf_asn1wr_t /*2*/* asn1wr_ctx = *(vscf_asn1wr_t /*2*/**) &c_ctx;

vscf_asn1wr_sort_elements_of_set(asn1wr_ctx /*a1*/, jlen /*a9*/);

jlong c_ctx = 0;
*(vscf_rsa_public_key_t **)&c_ctx = vscf_rsa_public_key_new();
return c_ctx;

vscf_rsa_public_key_delete(*(vscf_rsa_public_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_rsa_public_key_t /*2*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_rsa_public_key_t /*2*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_rsa_public_key_alg_info(rsa_public_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_rsa_public_key_t /*2*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_rsa_public_key_len(rsa_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_rsa_public_key_t /*2*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_rsa_public_key_bitlen(rsa_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_rsa_public_key_t /*2*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_rsa_public_key_is_valid(rsa_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_rsa_public_key_t /*2*/* rsa_public_key_ctx = *(vscf_rsa_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_rsa_public_key_key_exponent(rsa_public_key_ctx /*a1*/);
return ret;

jlong c_ctx = 0;
*(vscf_rsa_private_key_t **)&c_ctx = vscf_rsa_private_key_new();
return c_ctx;

vscf_rsa_private_key_delete(*(vscf_rsa_private_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_rsa_private_key_t /*2*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_rsa_private_key_t /*2*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_rsa_private_key_alg_info(rsa_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_rsa_private_key_t /*2*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_rsa_private_key_len(rsa_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_rsa_private_key_t /*2*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_rsa_private_key_bitlen(rsa_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_rsa_private_key_t /*2*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_rsa_private_key_is_valid(rsa_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_rsa_private_key_t /*2*/* rsa_private_key_ctx = *(vscf_rsa_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_rsa_private_key_extract_public_key(rsa_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_rsa_t **)&c_ctx = vscf_rsa_new();
return c_ctx;

vscf_rsa_delete(*(vscf_rsa_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Random

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_rsa_generate_ephemeral_key(rsa_ctx /*a1*/, jkey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_rsa_import_public_key(rsa_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_rsa_export_public_key(rsa_ctx /*a1*/, jpublicKey /*TODO*/);
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

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_rsa_import_private_key(rsa_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_rsa_export_private_key(rsa_ctx /*a1*/, jprivateKey /*TODO*/);
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

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_rsa_can_encrypt(rsa_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_rsa_encrypted_len(rsa_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_rsa_encrypted_len(rsa_ctx, public_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_rsa_encrypt(rsa_ctx /*a1*/, jpublicKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_rsa_can_decrypt(rsa_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_rsa_decrypted_len(rsa_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_rsa_decrypted_len(rsa_ctx, private_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_rsa_decrypt(rsa_ctx /*a1*/, jprivateKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_rsa_can_sign(rsa_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_rsa_signature_len(rsa_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_rsa_signature_len(rsa_ctx, private_key.len/*a*/));

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_rsa_sign_hash(rsa_ctx /*a1*/, jprivateKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
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

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_rsa_can_verify(rsa_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

// Wrap input data
byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_rsa_verify_hash(rsa_ctx /*a1*/, jpublicKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

return ret;

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_rsa_setup_defaults(rsa_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_rsa_t /*2*/* rsa_ctx = *(vscf_rsa_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_rsa_generate_key(rsa_ctx /*a1*/, jbitlen /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_ecc_public_key_t **)&c_ctx = vscf_ecc_public_key_new();
return c_ctx;

vscf_ecc_public_key_delete(*(vscf_ecc_public_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_ecc_public_key_t /*2*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_ecc_public_key_t /*2*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ecc_public_key_alg_info(ecc_public_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_ecc_public_key_t /*2*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_public_key_len(ecc_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_ecc_public_key_t /*2*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_public_key_bitlen(ecc_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_ecc_public_key_t /*2*/* ecc_public_key_ctx = *(vscf_ecc_public_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ecc_public_key_is_valid(ecc_public_key_ctx /*a1*/);
return ret;

jlong c_ctx = 0;
*(vscf_ecc_private_key_t **)&c_ctx = vscf_ecc_private_key_new();
return c_ctx;

vscf_ecc_private_key_delete(*(vscf_ecc_private_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_ecc_private_key_t /*2*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_ecc_private_key_t /*2*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ecc_private_key_alg_info(ecc_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_ecc_private_key_t /*2*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_private_key_len(ecc_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_ecc_private_key_t /*2*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_private_key_bitlen(ecc_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_ecc_private_key_t /*2*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ecc_private_key_is_valid(ecc_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_ecc_private_key_t /*2*/* ecc_private_key_ctx = *(vscf_ecc_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ecc_private_key_extract_public_key(ecc_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_ecc_t **)&c_ctx = vscf_ecc_new();
return c_ctx;

vscf_ecc_delete(*(vscf_ecc_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Random

// Dependency setter: Ecies

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ecc_generate_ephemeral_key(ecc_ctx /*a1*/, jkey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ecc_import_public_key(ecc_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_ecc_export_public_key(ecc_ctx /*a1*/, jpublicKey /*TODO*/);
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

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ecc_import_private_key(ecc_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_ecc_export_private_key(ecc_ctx /*a1*/, jprivateKey /*TODO*/);
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

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ecc_can_encrypt(ecc_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_encrypted_len(ecc_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecc_encrypted_len(ecc_ctx, public_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecc_encrypt(ecc_ctx /*a1*/, jpublicKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ecc_can_decrypt(ecc_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_decrypted_len(ecc_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ecc_decrypted_len(ecc_ctx, private_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecc_decrypt(ecc_ctx /*a1*/, jprivateKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ecc_can_sign(ecc_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_signature_len(ecc_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_ecc_signature_len(ecc_ctx, private_key.len/*a*/));

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecc_sign_hash(ecc_ctx /*a1*/, jprivateKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
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

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ecc_can_verify(ecc_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

// Wrap input data
byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ecc_verify_hash(ecc_ctx /*a1*/, jpublicKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

return ret;

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_ecc_shared_key_len(ecc_ctx, private_key.len/*a*/));

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecc_compute_shared_key(ecc_ctx /*a1*/, jpublicKey /*TODO*/, jprivateKey /*TODO*/, shared_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
vsc_buffer_delete(shared_key);

return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_shared_key_len(ecc_ctx /*a1*/, jkey /*TODO*/);
return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_kem_shared_key_len(ecc_ctx /*a1*/, jkey /*TODO*/);
return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ecc_kem_encapsulated_key_len(ecc_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_ecc_kem_shared_key_len(ecc_ctx, public_key.len/*a*/));

vsc_buffer_t *encapsulated_key = vsc_buffer_new_with_capacity(vscf_ecc_kem_encapsulated_key_len(ecc_ctx, public_key.len/*a*/));

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecc_kem_encapsulate(ecc_ctx /*a1*/, jpublicKey /*TODO*/, shared_key /*a3*/, encapsulated_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/EccKemEncapsulateResult");
vsc_buffer_delete(shared_key);

vsc_buffer_delete(encapsulated_key);

return ret;

// Wrap input data
byte* encapsulated_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jencapsulatedKey, NULL);
vsc_data_t encapsulated_key = vsc_data(encapsulated_key_arr, (*jenv)->GetArrayLength(jenv, jencapsulatedKey));

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_ecc_kem_shared_key_len(ecc_ctx, private_key.len/*a*/));

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecc_kem_decapsulate(ecc_ctx /*a1*/, encapsulated_key /*a3*/, jprivateKey /*TODO*/, shared_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jencapsulatedKey, (jbyte*) encapsulated_key_arr, 0);

vsc_buffer_delete(shared_key);

return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ecc_setup_defaults(ecc_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

vsc_buffer_t *signature = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

vscf_ecc_write_signature(jr /*a9*/, js /*a9*/, signature /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(signature));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(signature), (jbyte*) vsc_buffer_bytes(signature));
vsc_buffer_delete(signature);

return ret;

// Wrap input data
byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

vscf_status_t status = vscf_ecc_read_signature(signature /*a3*/, jr /*a9*/, js /*a9*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);


// Wrap enums
jclass algId_cls = (*jenv)->GetObjectClass(jenv, jalgId);
jmethodID algId_methodID = (*jenv)->GetMethodID(jenv, algId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, algId_methodID);

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ecc_generate_key(ecc_ctx /*a1*/, alg_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_ecc_t /*2*/* ecc_ctx = *(vscf_ecc_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ecc_produce_alg_info_for_key(ecc_ctx /*a1*/, jkey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_entropy_accumulator_t **)&c_ctx = vscf_entropy_accumulator_new();
return c_ctx;

vscf_entropy_accumulator_delete(*(vscf_entropy_accumulator_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_entropy_accumulator_t /*2*/* entropy_accumulator_ctx = *(vscf_entropy_accumulator_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_entropy_accumulator_is_strong(entropy_accumulator_ctx /*a1*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_entropy_accumulator_t /*2*/* entropy_accumulator_ctx = *(vscf_entropy_accumulator_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_entropy_accumulator_gather(entropy_accumulator_ctx /*a1*/, jlen /*a9*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_entropy_accumulator_t /*2*/* entropy_accumulator_ctx = *(vscf_entropy_accumulator_t /*2*/**) &c_ctx;

vscf_entropy_accumulator_setup_defaults(entropy_accumulator_ctx /*a1*/);

// Cast class context
vscf_entropy_accumulator_t /*2*/* entropy_accumulator_ctx = *(vscf_entropy_accumulator_t /*2*/**) &c_ctx;

vscf_entropy_accumulator_add_source(entropy_accumulator_ctx /*a1*/, jsource /*TODO*/, jthreshold /*a9*/);

jlong c_ctx = 0;
*(vscf_ctr_drbg_t **)&c_ctx = vscf_ctr_drbg_new();
return c_ctx;

vscf_ctr_drbg_delete(*(vscf_ctr_drbg_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: EntropySource

vsc_buffer_t *data = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_ctr_drbg_t /*2*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ctr_drbg_random(ctr_drbg_ctx /*a1*/, jdataLen /*a9*/, data /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), (jbyte*) vsc_buffer_bytes(data));
vsc_buffer_delete(data);

return ret;

// Cast class context
vscf_ctr_drbg_t /*2*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ctr_drbg_reseed(ctr_drbg_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_ctr_drbg_t /*2*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ctr_drbg_setup_defaults(ctr_drbg_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_ctr_drbg_t /*2*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*2*/**) &c_ctx;

vscf_ctr_drbg_enable_prediction_resistance(ctr_drbg_ctx /*a1*/);

// Cast class context
vscf_ctr_drbg_t /*2*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*2*/**) &c_ctx;

vscf_ctr_drbg_set_reseed_interval(ctr_drbg_ctx /*a1*/, jinterval /*a9*/);

// Cast class context
vscf_ctr_drbg_t /*2*/* ctr_drbg_ctx = *(vscf_ctr_drbg_t /*2*/**) &c_ctx;

vscf_ctr_drbg_set_entropy_len(ctr_drbg_ctx /*a1*/, jlen /*a9*/);

jlong c_ctx = 0;
*(vscf_hmac_t **)&c_ctx = vscf_hmac_new();
return c_ctx;

vscf_hmac_delete(*(vscf_hmac_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Hash

// Cast class context
vscf_hmac_t /*2*/* hmac_ctx = *(vscf_hmac_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_hmac_t /*2*/* hmac_ctx = *(vscf_hmac_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hmac_produce_alg_info(hmac_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hmac_t /*2*/* hmac_ctx = *(vscf_hmac_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_hmac_restore_alg_info(hmac_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_hmac_t /*2*/* hmac_ctx = *(vscf_hmac_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_hmac_digest_len(hmac_ctx /*a1*/);
return ret;

// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *mac = vsc_buffer_new_with_capacity(vscf_hmac_digest_len(hmac_ctx));

// Cast class context
vscf_hmac_t /*2*/* hmac_ctx = *(vscf_hmac_t /*2*/**) &c_ctx;

vscf_hmac_mac(hmac_ctx /*a1*/, key /*a3*/, data /*a3*/, mac /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(mac));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(mac), (jbyte*) vsc_buffer_bytes(mac));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(mac);

return ret;

// Wrap input data
byte* key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkey, NULL);
vsc_data_t key = vsc_data(key_arr, (*jenv)->GetArrayLength(jenv, jkey));

// Cast class context
vscf_hmac_t /*2*/* hmac_ctx = *(vscf_hmac_t /*2*/**) &c_ctx;

vscf_hmac_start(hmac_ctx /*a1*/, key /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkey, (jbyte*) key_arr, 0);


// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_hmac_t /*2*/* hmac_ctx = *(vscf_hmac_t /*2*/**) &c_ctx;

vscf_hmac_update(hmac_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);


vsc_buffer_t *mac = vsc_buffer_new_with_capacity(vscf_hmac_digest_len(hmac_ctx));

// Cast class context
vscf_hmac_t /*2*/* hmac_ctx = *(vscf_hmac_t /*2*/**) &c_ctx;

vscf_hmac_finish(hmac_ctx /*a1*/, mac /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(mac));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(mac), (jbyte*) vsc_buffer_bytes(mac));
vsc_buffer_delete(mac);

return ret;

// Cast class context
vscf_hmac_t /*2*/* hmac_ctx = *(vscf_hmac_t /*2*/**) &c_ctx;

vscf_hmac_reset(hmac_ctx /*a1*/);

jlong c_ctx = 0;
*(vscf_hkdf_t **)&c_ctx = vscf_hkdf_new();
return c_ctx;

vscf_hkdf_delete(*(vscf_hkdf_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Hash

// Cast class context
vscf_hkdf_t /*2*/* hkdf_ctx = *(vscf_hkdf_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_hkdf_t /*2*/* hkdf_ctx = *(vscf_hkdf_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hkdf_produce_alg_info(hkdf_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hkdf_t /*2*/* hkdf_ctx = *(vscf_hkdf_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_hkdf_restore_alg_info(hkdf_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *key = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_hkdf_t /*2*/* hkdf_ctx = *(vscf_hkdf_t /*2*/**) &c_ctx;

vscf_hkdf_derive(hkdf_ctx /*a1*/, data /*a3*/, jkeyLen /*a9*/, key /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), (jbyte*) vsc_buffer_bytes(key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(key);

return ret;

// Wrap input data
byte* salt_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsalt, NULL);
vsc_data_t salt = vsc_data(salt_arr, (*jenv)->GetArrayLength(jenv, jsalt));

// Cast class context
vscf_hkdf_t /*2*/* hkdf_ctx = *(vscf_hkdf_t /*2*/**) &c_ctx;

vscf_hkdf_reset(hkdf_ctx /*a1*/, salt /*a3*/, jiterationCount /*a9*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsalt, (jbyte*) salt_arr, 0);


// Wrap input data
byte* info_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinfo, NULL);
vsc_data_t info = vsc_data(info_arr, (*jenv)->GetArrayLength(jenv, jinfo));

// Cast class context
vscf_hkdf_t /*2*/* hkdf_ctx = *(vscf_hkdf_t /*2*/**) &c_ctx;

vscf_hkdf_set_info(hkdf_ctx /*a1*/, info /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jinfo, (jbyte*) info_arr, 0);


jlong c_ctx = 0;
*(vscf_kdf1_t **)&c_ctx = vscf_kdf1_new();
return c_ctx;

vscf_kdf1_delete(*(vscf_kdf1_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Hash

// Cast class context
vscf_kdf1_t /*2*/* kdf1_ctx = *(vscf_kdf1_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_kdf1_t /*2*/* kdf1_ctx = *(vscf_kdf1_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_kdf1_produce_alg_info(kdf1_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_kdf1_t /*2*/* kdf1_ctx = *(vscf_kdf1_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_kdf1_restore_alg_info(kdf1_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *key = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_kdf1_t /*2*/* kdf1_ctx = *(vscf_kdf1_t /*2*/**) &c_ctx;

vscf_kdf1_derive(kdf1_ctx /*a1*/, data /*a3*/, jkeyLen /*a9*/, key /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), (jbyte*) vsc_buffer_bytes(key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(key);

return ret;

jlong c_ctx = 0;
*(vscf_kdf2_t **)&c_ctx = vscf_kdf2_new();
return c_ctx;

vscf_kdf2_delete(*(vscf_kdf2_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Hash

// Cast class context
vscf_kdf2_t /*2*/* kdf2_ctx = *(vscf_kdf2_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_kdf2_t /*2*/* kdf2_ctx = *(vscf_kdf2_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_kdf2_produce_alg_info(kdf2_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_kdf2_t /*2*/* kdf2_ctx = *(vscf_kdf2_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_kdf2_restore_alg_info(kdf2_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *key = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_kdf2_t /*2*/* kdf2_ctx = *(vscf_kdf2_t /*2*/**) &c_ctx;

vscf_kdf2_derive(kdf2_ctx /*a1*/, data /*a3*/, jkeyLen /*a9*/, key /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), (jbyte*) vsc_buffer_bytes(key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(key);

return ret;

jlong c_ctx = 0;
*(vscf_fake_random_t **)&c_ctx = vscf_fake_random_new();
return c_ctx;

vscf_fake_random_delete(*(vscf_fake_random_t /*2*/ **) &c_ctx /*5*/);

vsc_buffer_t *data = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_fake_random_t /*2*/* fake_random_ctx = *(vscf_fake_random_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_fake_random_random(fake_random_ctx /*a1*/, jdataLen /*a9*/, data /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), (jbyte*) vsc_buffer_bytes(data));
vsc_buffer_delete(data);

return ret;

// Cast class context
vscf_fake_random_t /*2*/* fake_random_ctx = *(vscf_fake_random_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_fake_random_reseed(fake_random_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_fake_random_t /*2*/* fake_random_ctx = *(vscf_fake_random_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_fake_random_is_strong(fake_random_ctx /*a1*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_fake_random_t /*2*/* fake_random_ctx = *(vscf_fake_random_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_fake_random_gather(fake_random_ctx /*a1*/, jlen /*a9*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_fake_random_t /*2*/* fake_random_ctx = *(vscf_fake_random_t /*2*/**) &c_ctx;

vscf_fake_random_setup_source_byte(fake_random_ctx /*a1*/, jbyteSource /*a9*/);

// Wrap input data
byte* data_source_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdataSource, NULL);
vsc_data_t data_source = vsc_data(data_source_arr, (*jenv)->GetArrayLength(jenv, jdataSource));

// Cast class context
vscf_fake_random_t /*2*/* fake_random_ctx = *(vscf_fake_random_t /*2*/**) &c_ctx;

vscf_fake_random_setup_source_data(fake_random_ctx /*a1*/, data_source /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdataSource, (jbyte*) data_source_arr, 0);


jlong c_ctx = 0;
*(vscf_pkcs5_pbkdf2_t **)&c_ctx = vscf_pkcs5_pbkdf2_new();
return c_ctx;

vscf_pkcs5_pbkdf2_delete(*(vscf_pkcs5_pbkdf2_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Hmac

// Cast class context
vscf_pkcs5_pbkdf2_t /*2*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_pkcs5_pbkdf2_t /*2*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_pkcs5_pbkdf2_produce_alg_info(pkcs5_pbkdf2_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_pkcs5_pbkdf2_t /*2*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_pkcs5_pbkdf2_restore_alg_info(pkcs5_pbkdf2_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *key = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_pkcs5_pbkdf2_t /*2*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*2*/**) &c_ctx;

vscf_pkcs5_pbkdf2_derive(pkcs5_pbkdf2_ctx /*a1*/, data /*a3*/, jkeyLen /*a9*/, key /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(key), (jbyte*) vsc_buffer_bytes(key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(key);

return ret;

// Wrap input data
byte* salt_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsalt, NULL);
vsc_data_t salt = vsc_data(salt_arr, (*jenv)->GetArrayLength(jenv, jsalt));

// Cast class context
vscf_pkcs5_pbkdf2_t /*2*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*2*/**) &c_ctx;

vscf_pkcs5_pbkdf2_reset(pkcs5_pbkdf2_ctx /*a1*/, salt /*a3*/, jiterationCount /*a9*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsalt, (jbyte*) salt_arr, 0);


// Wrap input data
byte* info_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinfo, NULL);
vsc_data_t info = vsc_data(info_arr, (*jenv)->GetArrayLength(jenv, jinfo));

// Cast class context
vscf_pkcs5_pbkdf2_t /*2*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*2*/**) &c_ctx;

vscf_pkcs5_pbkdf2_set_info(pkcs5_pbkdf2_ctx /*a1*/, info /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jinfo, (jbyte*) info_arr, 0);


// Cast class context
vscf_pkcs5_pbkdf2_t /*2*/* pkcs5_pbkdf2_ctx = *(vscf_pkcs5_pbkdf2_t /*2*/**) &c_ctx;

vscf_pkcs5_pbkdf2_setup_defaults(pkcs5_pbkdf2_ctx /*a1*/);

jlong c_ctx = 0;
*(vscf_pkcs5_pbes2_t **)&c_ctx = vscf_pkcs5_pbes2_new();
return c_ctx;

vscf_pkcs5_pbes2_delete(*(vscf_pkcs5_pbes2_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Kdf

// Dependency setter: Cipher

// Cast class context
vscf_pkcs5_pbes2_t /*2*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_pkcs5_pbes2_t /*2*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_pkcs5_pbes2_produce_alg_info(pkcs5_pbes2_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_pkcs5_pbes2_t /*2*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_pkcs5_pbes2_restore_alg_info(pkcs5_pbes2_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs5_pbes2_encrypted_len(pkcs5_pbes2_ctx, data.len/*a*/));

// Cast class context
vscf_pkcs5_pbes2_t /*2*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_pkcs5_pbes2_t /*2*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_pkcs5_pbes2_encrypted_len(pkcs5_pbes2_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_pkcs5_pbes2_t /*2*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_pkcs5_pbes2_precise_encrypted_len(pkcs5_pbes2_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs5_pbes2_decrypted_len(pkcs5_pbes2_ctx, data.len/*a*/));

// Cast class context
vscf_pkcs5_pbes2_t /*2*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_pkcs5_pbes2_t /*2*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_pkcs5_pbes2_decrypted_len(pkcs5_pbes2_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* pwd_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpwd, NULL);
vsc_data_t pwd = vsc_data(pwd_arr, (*jenv)->GetArrayLength(jenv, jpwd));

// Cast class context
vscf_pkcs5_pbes2_t /*2*/* pkcs5_pbes2_ctx = *(vscf_pkcs5_pbes2_t /*2*/**) &c_ctx;

vscf_pkcs5_pbes2_reset(pkcs5_pbes2_ctx /*a1*/, pwd /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jpwd, (jbyte*) pwd_arr, 0);


jlong c_ctx = 0;
*(vscf_seed_entropy_source_t **)&c_ctx = vscf_seed_entropy_source_new();
return c_ctx;

vscf_seed_entropy_source_delete(*(vscf_seed_entropy_source_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_seed_entropy_source_t /*2*/* seed_entropy_source_ctx = *(vscf_seed_entropy_source_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_seed_entropy_source_is_strong(seed_entropy_source_ctx /*a1*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_seed_entropy_source_t /*2*/* seed_entropy_source_ctx = *(vscf_seed_entropy_source_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_seed_entropy_source_gather(seed_entropy_source_ctx /*a1*/, jlen /*a9*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Wrap input data
byte* seed_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jseed, NULL);
vsc_data_t seed = vsc_data(seed_arr, (*jenv)->GetArrayLength(jenv, jseed));

// Cast class context
vscf_seed_entropy_source_t /*2*/* seed_entropy_source_ctx = *(vscf_seed_entropy_source_t /*2*/**) &c_ctx;

vscf_seed_entropy_source_reset_seed(seed_entropy_source_ctx /*a1*/, seed /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jseed, (jbyte*) seed_arr, 0);


// Cast class context
vscf_seed_entropy_source_t /*2*/* seed_entropy_source_ctx = *(vscf_seed_entropy_source_t /*2*/**) &c_ctx;

vscf_seed_entropy_source_move_forward(seed_entropy_source_ctx /*a1*/);

jlong c_ctx = 0;
*(vscf_key_material_rng_t **)&c_ctx = vscf_key_material_rng_new();
return c_ctx;

vscf_key_material_rng_delete(*(vscf_key_material_rng_t /*2*/ **) &c_ctx /*5*/);

vsc_buffer_t *data = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_key_material_rng_t /*2*/* key_material_rng_ctx = *(vscf_key_material_rng_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_key_material_rng_random(key_material_rng_ctx /*a1*/, jdataLen /*a9*/, data /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(data));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(data), (jbyte*) vsc_buffer_bytes(data));
vsc_buffer_delete(data);

return ret;

// Cast class context
vscf_key_material_rng_t /*2*/* key_material_rng_ctx = *(vscf_key_material_rng_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_key_material_rng_reseed(key_material_rng_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* key_material_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jkeyMaterial, NULL);
vsc_data_t key_material = vsc_data(key_material_arr, (*jenv)->GetArrayLength(jenv, jkeyMaterial));

// Cast class context
vscf_key_material_rng_t /*2*/* key_material_rng_ctx = *(vscf_key_material_rng_t /*2*/**) &c_ctx;

vscf_key_material_rng_reset_key_material(key_material_rng_ctx /*a1*/, key_material /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jkeyMaterial, (jbyte*) key_material_arr, 0);


jlong c_ctx = 0;
*(vscf_raw_public_key_t **)&c_ctx = vscf_raw_public_key_new();
return c_ctx;

vscf_raw_public_key_delete(*(vscf_raw_public_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_raw_public_key_t /*2*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_raw_public_key_t /*2*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_raw_public_key_alg_info(raw_public_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_raw_public_key_t /*2*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_raw_public_key_len(raw_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_raw_public_key_t /*2*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_raw_public_key_bitlen(raw_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_raw_public_key_t /*2*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_raw_public_key_is_valid(raw_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_raw_public_key_t /*2*/* raw_public_key_ctx = *(vscf_raw_public_key_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_raw_public_key_data(raw_public_key_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

jlong c_ctx = 0;
*(vscf_raw_private_key_t **)&c_ctx = vscf_raw_private_key_new();
return c_ctx;

vscf_raw_private_key_delete(*(vscf_raw_private_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_raw_private_key_alg_info(raw_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_raw_private_key_len(raw_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_raw_private_key_bitlen(raw_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_raw_private_key_is_valid(raw_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_raw_private_key_extract_public_key(raw_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_raw_private_key_data(raw_private_key_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_raw_private_key_has_public_key(raw_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

vscf_raw_private_key_set_public_key(raw_private_key_ctx /*a1*/, jrawPublicKey /*a9*/);

// Cast class context
vscf_raw_private_key_t /*2*/* raw_private_key_ctx = *(vscf_raw_private_key_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_raw_private_key_get_public_key(raw_private_key_ctx /*a1*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/RawPublicKey");
if (NULL == result_cls) {
    VSCF_ASSERT("Class RawPublicKey not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/foundation/RawPublicKey;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class RawPublicKey has no 'getInstance' method.");
}
vscf_raw_public_key_shallow_copy((vscf_raw_public_key_t */*5*/) proxyResult);
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_pkcs8_serializer_t **)&c_ctx = vscf_pkcs8_serializer_new();
return c_ctx;

vscf_pkcs8_serializer_delete(*(vscf_pkcs8_serializer_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Asn1Writer

// Cast class context
vscf_pkcs8_serializer_t /*2*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_pkcs8_serializer_serialized_public_key_len(pkcs8_serializer_ctx /*a1*/, jpublicKey /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs8_serializer_serialized_public_key_len(pkcs8_serializer_ctx, public_key.len/*a*/));

// Cast class context
vscf_pkcs8_serializer_t /*2*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_pkcs8_serializer_serialize_public_key(pkcs8_serializer_ctx /*a1*/, jpublicKey /*a9*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_pkcs8_serializer_t /*2*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_pkcs8_serializer_serialized_private_key_len(pkcs8_serializer_ctx /*a1*/, jprivateKey /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_pkcs8_serializer_serialized_private_key_len(pkcs8_serializer_ctx, private_key.len/*a*/));

// Cast class context
vscf_pkcs8_serializer_t /*2*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_pkcs8_serializer_serialize_private_key(pkcs8_serializer_ctx /*a1*/, jprivateKey /*a9*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_pkcs8_serializer_t /*2*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*2*/**) &c_ctx;

vscf_pkcs8_serializer_setup_defaults(pkcs8_serializer_ctx /*a1*/);

// Cast class context
vscf_pkcs8_serializer_t /*2*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_pkcs8_serializer_serialize_public_key_inplace(pkcs8_serializer_ctx /*a1*/, jpublicKey /*a9*/);
return ret;

// Cast class context
vscf_pkcs8_serializer_t /*2*/* pkcs8_serializer_ctx = *(vscf_pkcs8_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_pkcs8_serializer_serialize_private_key_inplace(pkcs8_serializer_ctx /*a1*/, jprivateKey /*a9*/);
return ret;

jlong c_ctx = 0;
*(vscf_sec1_serializer_t **)&c_ctx = vscf_sec1_serializer_new();
return c_ctx;

vscf_sec1_serializer_delete(*(vscf_sec1_serializer_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Asn1Writer

// Cast class context
vscf_sec1_serializer_t /*2*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_sec1_serializer_serialized_public_key_len(sec1_serializer_ctx /*a1*/, jpublicKey /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_sec1_serializer_serialized_public_key_len(sec1_serializer_ctx, public_key.len/*a*/));

// Cast class context
vscf_sec1_serializer_t /*2*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_sec1_serializer_serialize_public_key(sec1_serializer_ctx /*a1*/, jpublicKey /*a9*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_sec1_serializer_t /*2*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_sec1_serializer_serialized_private_key_len(sec1_serializer_ctx /*a1*/, jprivateKey /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_sec1_serializer_serialized_private_key_len(sec1_serializer_ctx, private_key.len/*a*/));

// Cast class context
vscf_sec1_serializer_t /*2*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_sec1_serializer_serialize_private_key(sec1_serializer_ctx /*a1*/, jprivateKey /*a9*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_sec1_serializer_t /*2*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*2*/**) &c_ctx;

vscf_sec1_serializer_setup_defaults(sec1_serializer_ctx /*a1*/);

// Cast class context
vscf_sec1_serializer_t /*2*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_sec1_serializer_serialize_public_key_inplace(sec1_serializer_ctx /*a1*/, jpublicKey /*a9*/);
return ret;

// Cast class context
vscf_sec1_serializer_t /*2*/* sec1_serializer_ctx = *(vscf_sec1_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_sec1_serializer_serialize_private_key_inplace(sec1_serializer_ctx /*a1*/, jprivateKey /*a9*/);
return ret;

jboolean ret = (jboolean) vscf_sec1_serializer_is_ec_key(jkey /*TODO*/);
return ret;

jlong c_ctx = 0;
*(vscf_key_asn1_serializer_t **)&c_ctx = vscf_key_asn1_serializer_new();
return c_ctx;

vscf_key_asn1_serializer_delete(*(vscf_key_asn1_serializer_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Asn1Writer

// Cast class context
vscf_key_asn1_serializer_t /*2*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_key_asn1_serializer_serialized_public_key_len(key_asn1_serializer_ctx /*a1*/, jpublicKey /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_key_asn1_serializer_serialized_public_key_len(key_asn1_serializer_ctx, public_key.len/*a*/));

// Cast class context
vscf_key_asn1_serializer_t /*2*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_key_asn1_serializer_serialize_public_key(key_asn1_serializer_ctx /*a1*/, jpublicKey /*a9*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_key_asn1_serializer_t /*2*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_key_asn1_serializer_serialized_private_key_len(key_asn1_serializer_ctx /*a1*/, jprivateKey /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_key_asn1_serializer_serialized_private_key_len(key_asn1_serializer_ctx, private_key.len/*a*/));

// Cast class context
vscf_key_asn1_serializer_t /*2*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_key_asn1_serializer_serialize_private_key(key_asn1_serializer_ctx /*a1*/, jprivateKey /*a9*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_key_asn1_serializer_t /*2*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*2*/**) &c_ctx;

vscf_key_asn1_serializer_setup_defaults(key_asn1_serializer_ctx /*a1*/);

// Cast class context
vscf_key_asn1_serializer_t /*2*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_key_asn1_serializer_serialize_public_key_inplace(key_asn1_serializer_ctx /*a1*/, jpublicKey /*a9*/);
return ret;

// Cast class context
vscf_key_asn1_serializer_t /*2*/* key_asn1_serializer_ctx = *(vscf_key_asn1_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_key_asn1_serializer_serialize_private_key_inplace(key_asn1_serializer_ctx /*a1*/, jprivateKey /*a9*/);
return ret;

jlong c_ctx = 0;
*(vscf_key_asn1_deserializer_t **)&c_ctx = vscf_key_asn1_deserializer_new();
return c_ctx;

vscf_key_asn1_deserializer_delete(*(vscf_key_asn1_deserializer_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Asn1Reader

// Wrap input data
byte* public_key_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpublicKeyData, NULL);
vsc_data_t public_key_data = vsc_data(public_key_data_arr, (*jenv)->GetArrayLength(jenv, jpublicKeyData));

// Cast class context
vscf_key_asn1_deserializer_t /*2*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_key_asn1_deserializer_deserialize_public_key(key_asn1_deserializer_ctx /*a1*/, public_key_data /*a3*/);
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

// Wrap input data
byte* private_key_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jprivateKeyData, NULL);
vsc_data_t private_key_data = vsc_data(private_key_data_arr, (*jenv)->GetArrayLength(jenv, jprivateKeyData));

// Cast class context
vscf_key_asn1_deserializer_t /*2*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_key_asn1_deserializer_deserialize_private_key(key_asn1_deserializer_ctx /*a1*/, private_key_data /*a3*/);
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

// Cast class context
vscf_key_asn1_deserializer_t /*2*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*2*/**) &c_ctx;

vscf_key_asn1_deserializer_setup_defaults(key_asn1_deserializer_ctx /*a1*/);

// Cast class context
vscf_key_asn1_deserializer_t /*2*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_key_asn1_deserializer_deserialize_public_key_inplace(key_asn1_deserializer_ctx /*a1*/);
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

// Cast class context
vscf_key_asn1_deserializer_t /*2*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_key_asn1_deserializer_deserialize_private_key_inplace(key_asn1_deserializer_ctx /*a1*/);
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

// Cast class context
vscf_key_asn1_deserializer_t /*2*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_key_asn1_deserializer_deserialize_pkcs8_private_key_inplace(key_asn1_deserializer_ctx /*a1*/, jseqLeftLen /*a9*/, jversion /*a9*/);
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

// Cast class context
vscf_key_asn1_deserializer_t /*2*/* key_asn1_deserializer_ctx = *(vscf_key_asn1_deserializer_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_key_asn1_deserializer_deserialize_sec1_private_key_inplace(key_asn1_deserializer_ctx /*a1*/, jseqLeftLen /*a9*/, jversion /*a9*/, jalgInfo /*TODO*/);
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

jlong c_ctx = 0;
*(vscf_ed25519_t **)&c_ctx = vscf_ed25519_new();
return c_ctx;

vscf_ed25519_delete(*(vscf_ed25519_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Random

// Dependency setter: Ecies

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ed25519_generate_ephemeral_key(ed25519_ctx /*a1*/, jkey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ed25519_import_public_key(ed25519_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_ed25519_export_public_key(ed25519_ctx /*a1*/, jpublicKey /*TODO*/);
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

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ed25519_import_private_key(ed25519_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_ed25519_export_private_key(ed25519_ctx /*a1*/, jprivateKey /*TODO*/);
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

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ed25519_can_encrypt(ed25519_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ed25519_encrypted_len(ed25519_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ed25519_encrypted_len(ed25519_ctx, public_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ed25519_encrypt(ed25519_ctx /*a1*/, jpublicKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ed25519_can_decrypt(ed25519_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ed25519_decrypted_len(ed25519_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_ed25519_decrypted_len(ed25519_ctx, private_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ed25519_decrypt(ed25519_ctx /*a1*/, jprivateKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ed25519_can_sign(ed25519_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ed25519_signature_len(ed25519_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_ed25519_signature_len(ed25519_ctx, private_key.len/*a*/));

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ed25519_sign_hash(ed25519_ctx /*a1*/, jprivateKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
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

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ed25519_can_verify(ed25519_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

// Wrap input data
byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_ed25519_verify_hash(ed25519_ctx /*a1*/, jpublicKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

return ret;

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_ed25519_shared_key_len(ed25519_ctx, private_key.len/*a*/));

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ed25519_compute_shared_key(ed25519_ctx /*a1*/, jpublicKey /*TODO*/, jprivateKey /*TODO*/, shared_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
vsc_buffer_delete(shared_key);

return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ed25519_shared_key_len(ed25519_ctx /*a1*/, jkey /*TODO*/);
return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ed25519_kem_shared_key_len(ed25519_ctx /*a1*/, jkey /*TODO*/);
return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_ed25519_kem_encapsulated_key_len(ed25519_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_ed25519_kem_shared_key_len(ed25519_ctx, public_key.len/*a*/));

vsc_buffer_t *encapsulated_key = vsc_buffer_new_with_capacity(vscf_ed25519_kem_encapsulated_key_len(ed25519_ctx, public_key.len/*a*/));

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ed25519_kem_encapsulate(ed25519_ctx /*a1*/, jpublicKey /*TODO*/, shared_key /*a3*/, encapsulated_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Ed25519KemEncapsulateResult");
vsc_buffer_delete(shared_key);

vsc_buffer_delete(encapsulated_key);

return ret;

// Wrap input data
byte* encapsulated_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jencapsulatedKey, NULL);
vsc_data_t encapsulated_key = vsc_data(encapsulated_key_arr, (*jenv)->GetArrayLength(jenv, jencapsulatedKey));

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_ed25519_kem_shared_key_len(ed25519_ctx, private_key.len/*a*/));

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ed25519_kem_decapsulate(ed25519_ctx /*a1*/, encapsulated_key /*a3*/, jprivateKey /*TODO*/, shared_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jencapsulatedKey, (jbyte*) encapsulated_key_arr, 0);

vsc_buffer_delete(shared_key);

return ret;

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_ed25519_setup_defaults(ed25519_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_ed25519_t /*2*/* ed25519_ctx = *(vscf_ed25519_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_ed25519_generate_key(ed25519_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_curve25519_t **)&c_ctx = vscf_curve25519_new();
return c_ctx;

vscf_curve25519_delete(*(vscf_curve25519_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Random

// Dependency setter: Ecies

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_curve25519_generate_ephemeral_key(curve25519_ctx /*a1*/, jkey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_curve25519_import_public_key(curve25519_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_curve25519_export_public_key(curve25519_ctx /*a1*/, jpublicKey /*TODO*/);
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

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_curve25519_import_private_key(curve25519_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_curve25519_export_private_key(curve25519_ctx /*a1*/, jprivateKey /*TODO*/);
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

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_curve25519_can_encrypt(curve25519_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_curve25519_encrypted_len(curve25519_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_curve25519_encrypted_len(curve25519_ctx, public_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_curve25519_encrypt(curve25519_ctx /*a1*/, jpublicKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_curve25519_can_decrypt(curve25519_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_curve25519_decrypted_len(curve25519_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_curve25519_decrypted_len(curve25519_ctx, private_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_curve25519_decrypt(curve25519_ctx /*a1*/, jprivateKey /*TODO*/, data /*a3*/, out /*a3*/);
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

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_curve25519_shared_key_len(curve25519_ctx, private_key.len/*a*/));

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_curve25519_compute_shared_key(curve25519_ctx /*a1*/, jpublicKey /*TODO*/, jprivateKey /*TODO*/, shared_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
vsc_buffer_delete(shared_key);

return ret;

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_curve25519_shared_key_len(curve25519_ctx /*a1*/, jkey /*TODO*/);
return ret;

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_curve25519_kem_shared_key_len(curve25519_ctx /*a1*/, jkey /*TODO*/);
return ret;

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_curve25519_kem_encapsulated_key_len(curve25519_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_curve25519_kem_shared_key_len(curve25519_ctx, public_key.len/*a*/));

vsc_buffer_t *encapsulated_key = vsc_buffer_new_with_capacity(vscf_curve25519_kem_encapsulated_key_len(curve25519_ctx, public_key.len/*a*/));

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_curve25519_kem_encapsulate(curve25519_ctx /*a1*/, jpublicKey /*TODO*/, shared_key /*a3*/, encapsulated_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Curve25519KemEncapsulateResult");
vsc_buffer_delete(shared_key);

vsc_buffer_delete(encapsulated_key);

return ret;

// Wrap input data
byte* encapsulated_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jencapsulatedKey, NULL);
vsc_data_t encapsulated_key = vsc_data(encapsulated_key_arr, (*jenv)->GetArrayLength(jenv, jencapsulatedKey));

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_curve25519_kem_shared_key_len(curve25519_ctx, private_key.len/*a*/));

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_curve25519_kem_decapsulate(curve25519_ctx /*a1*/, encapsulated_key /*a3*/, jprivateKey /*TODO*/, shared_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jencapsulatedKey, (jbyte*) encapsulated_key_arr, 0);

vsc_buffer_delete(shared_key);

return ret;

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_curve25519_setup_defaults(curve25519_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_curve25519_t /*2*/* curve25519_ctx = *(vscf_curve25519_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_curve25519_generate_key(curve25519_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_falcon_t **)&c_ctx = vscf_falcon_new();
return c_ctx;

vscf_falcon_delete(*(vscf_falcon_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Random

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_falcon_produce_alg_info(falcon_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_falcon_restore_alg_info(falcon_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_falcon_generate_ephemeral_key(falcon_ctx /*a1*/, jkey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_falcon_import_public_key(falcon_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_falcon_export_public_key(falcon_ctx /*a1*/, jpublicKey /*TODO*/);
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

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_falcon_import_private_key(falcon_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_falcon_export_private_key(falcon_ctx /*a1*/, jprivateKey /*TODO*/);
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

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_falcon_can_sign(falcon_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_falcon_signature_len(falcon_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_falcon_signature_len(falcon_ctx, private_key.len/*a*/));

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_falcon_sign_hash(falcon_ctx /*a1*/, jprivateKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
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

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_falcon_can_verify(falcon_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

// Wrap input data
byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_falcon_verify_hash(falcon_ctx /*a1*/, jpublicKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

return ret;

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_falcon_setup_defaults(falcon_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_falcon_t /*2*/* falcon_ctx = *(vscf_falcon_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_falcon_generate_key(falcon_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_round5_t **)&c_ctx = vscf_round5_new();
return c_ctx;

vscf_round5_delete(*(vscf_round5_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Random

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_round5_generate_ephemeral_key(round5_ctx /*a1*/, jkey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_round5_import_public_key(round5_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_round5_export_public_key(round5_ctx /*a1*/, jpublicKey /*TODO*/);
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

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_round5_import_private_key(round5_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_round5_export_private_key(round5_ctx /*a1*/, jprivateKey /*TODO*/);
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

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_round5_kem_shared_key_len(round5_ctx /*a1*/, jkey /*TODO*/);
return ret;

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_round5_kem_encapsulated_key_len(round5_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_round5_kem_shared_key_len(round5_ctx, public_key.len/*a*/));

vsc_buffer_t *encapsulated_key = vsc_buffer_new_with_capacity(vscf_round5_kem_encapsulated_key_len(round5_ctx, public_key.len/*a*/));

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_round5_kem_encapsulate(round5_ctx /*a1*/, jpublicKey /*TODO*/, shared_key /*a3*/, encapsulated_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/foundation/Round5KemEncapsulateResult");
vsc_buffer_delete(shared_key);

vsc_buffer_delete(encapsulated_key);

return ret;

// Wrap input data
byte* encapsulated_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jencapsulatedKey, NULL);
vsc_data_t encapsulated_key = vsc_data(encapsulated_key_arr, (*jenv)->GetArrayLength(jenv, jencapsulatedKey));

vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(vscf_round5_kem_shared_key_len(round5_ctx, private_key.len/*a*/));

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_round5_kem_decapsulate(round5_ctx /*a1*/, encapsulated_key /*a3*/, jprivateKey /*TODO*/, shared_key /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(shared_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(shared_key), (jbyte*) vsc_buffer_bytes(shared_key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jencapsulatedKey, (jbyte*) encapsulated_key_arr, 0);

vsc_buffer_delete(shared_key);

return ret;

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_round5_setup_defaults(round5_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Wrap enums
jclass algId_cls = (*jenv)->GetObjectClass(jenv, jalgId);
jmethodID algId_methodID = (*jenv)->GetMethodID(jenv, algId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, algId_methodID);

// Cast class context
vscf_round5_t /*2*/* round5_ctx = *(vscf_round5_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_round5_generate_key(round5_ctx /*a1*/, alg_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_compound_key_alg_info_t **)&c_ctx = vscf_compound_key_alg_info_new();
return c_ctx;

vscf_compound_key_alg_info_delete(*(vscf_compound_key_alg_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_compound_key_alg_info_t /*2*/* compound_key_alg_info_ctx = *(vscf_compound_key_alg_info_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_compound_key_alg_info_t /*2*/* compound_key_alg_info_ctx = *(vscf_compound_key_alg_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_info_cipher_alg_info(compound_key_alg_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_key_alg_info_t /*2*/* compound_key_alg_info_ctx = *(vscf_compound_key_alg_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_info_signer_alg_info(compound_key_alg_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_compound_public_key_t **)&c_ctx = vscf_compound_public_key_new();
return c_ctx;

vscf_compound_public_key_delete(*(vscf_compound_public_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_compound_public_key_t /*2*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_compound_public_key_t /*2*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_public_key_alg_info(compound_public_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_public_key_t /*2*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_compound_public_key_len(compound_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_compound_public_key_t /*2*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_compound_public_key_bitlen(compound_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_compound_public_key_t /*2*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_compound_public_key_is_valid(compound_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_compound_public_key_t /*2*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_public_key_cipher_key(compound_public_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_public_key_t /*2*/* compound_public_key_ctx = *(vscf_compound_public_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_public_key_signer_key(compound_public_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_compound_private_key_t **)&c_ctx = vscf_compound_private_key_new();
return c_ctx;

vscf_compound_private_key_delete(*(vscf_compound_private_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_compound_private_key_t /*2*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_compound_private_key_t /*2*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_private_key_alg_info(compound_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_private_key_t /*2*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_compound_private_key_len(compound_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_compound_private_key_t /*2*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_compound_private_key_bitlen(compound_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_compound_private_key_t /*2*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_compound_private_key_is_valid(compound_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_compound_private_key_t /*2*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_private_key_extract_public_key(compound_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_private_key_t /*2*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_private_key_cipher_key(compound_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_private_key_t /*2*/* compound_private_key_ctx = *(vscf_compound_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_private_key_signer_key(compound_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_compound_key_alg_t **)&c_ctx = vscf_compound_key_alg_new();
return c_ctx;

vscf_compound_key_alg_delete(*(vscf_compound_key_alg_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Random

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_produce_alg_info(compound_key_alg_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_compound_key_alg_restore_alg_info(compound_key_alg_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_generate_ephemeral_key(compound_key_alg_ctx /*a1*/, jkey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_import_public_key(compound_key_alg_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_compound_key_alg_export_public_key(compound_key_alg_ctx /*a1*/, jpublicKey /*TODO*/);
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

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_import_private_key(compound_key_alg_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_compound_key_alg_export_private_key(compound_key_alg_ctx /*a1*/, jprivateKey /*TODO*/);
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

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_compound_key_alg_can_encrypt(compound_key_alg_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_compound_key_alg_encrypted_len(compound_key_alg_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_compound_key_alg_encrypted_len(compound_key_alg_ctx, public_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_compound_key_alg_encrypt(compound_key_alg_ctx /*a1*/, jpublicKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_compound_key_alg_can_decrypt(compound_key_alg_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_compound_key_alg_decrypted_len(compound_key_alg_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_compound_key_alg_decrypted_len(compound_key_alg_ctx, private_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_compound_key_alg_decrypt(compound_key_alg_ctx /*a1*/, jprivateKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_compound_key_alg_can_sign(compound_key_alg_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_compound_key_alg_signature_len(compound_key_alg_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_compound_key_alg_signature_len(compound_key_alg_ctx, private_key.len/*a*/));

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_compound_key_alg_sign_hash(compound_key_alg_ctx /*a1*/, jprivateKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
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

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_compound_key_alg_can_verify(compound_key_alg_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

// Wrap input data
byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_compound_key_alg_verify_hash(compound_key_alg_ctx /*a1*/, jpublicKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

return ret;

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_compound_key_alg_setup_defaults(compound_key_alg_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_compound_key_alg_t /*2*/* compound_key_alg_ctx = *(vscf_compound_key_alg_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_compound_key_alg_make_key(compound_key_alg_ctx /*a1*/, jcipherKey /*TODO*/, jsignerKey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_hybrid_key_alg_info_t **)&c_ctx = vscf_hybrid_key_alg_info_new();
return c_ctx;

vscf_hybrid_key_alg_info_delete(*(vscf_hybrid_key_alg_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_hybrid_key_alg_info_t /*2*/* hybrid_key_alg_info_ctx = *(vscf_hybrid_key_alg_info_t /*2*/**) &c_ctx;

const vscf_alg_id_t proxyResult = vscf_hybrid_key_alg_info_alg_id(hybrid_key_alg_info_ctx /*a1*/);
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

// Cast class context
vscf_hybrid_key_alg_info_t /*2*/* hybrid_key_alg_info_ctx = *(vscf_hybrid_key_alg_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_key_alg_info_first_key_alg_info(hybrid_key_alg_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hybrid_key_alg_info_t /*2*/* hybrid_key_alg_info_ctx = *(vscf_hybrid_key_alg_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_key_alg_info_second_key_alg_info(hybrid_key_alg_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_hybrid_public_key_t **)&c_ctx = vscf_hybrid_public_key_new();
return c_ctx;

vscf_hybrid_public_key_delete(*(vscf_hybrid_public_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_hybrid_public_key_t /*2*/* hybrid_public_key_ctx = *(vscf_hybrid_public_key_t /*2*/**) &c_ctx;

const vscf_alg_id_t proxyResult = vscf_hybrid_public_key_alg_id(hybrid_public_key_ctx /*a1*/);
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

// Cast class context
vscf_hybrid_public_key_t /*2*/* hybrid_public_key_ctx = *(vscf_hybrid_public_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_public_key_alg_info(hybrid_public_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hybrid_public_key_t /*2*/* hybrid_public_key_ctx = *(vscf_hybrid_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_hybrid_public_key_len(hybrid_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_hybrid_public_key_t /*2*/* hybrid_public_key_ctx = *(vscf_hybrid_public_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_hybrid_public_key_bitlen(hybrid_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_hybrid_public_key_t /*2*/* hybrid_public_key_ctx = *(vscf_hybrid_public_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_hybrid_public_key_is_valid(hybrid_public_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_hybrid_public_key_t /*2*/* hybrid_public_key_ctx = *(vscf_hybrid_public_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_public_key_first_key(hybrid_public_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hybrid_public_key_t /*2*/* hybrid_public_key_ctx = *(vscf_hybrid_public_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_public_key_second_key(hybrid_public_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_hybrid_private_key_t **)&c_ctx = vscf_hybrid_private_key_new();
return c_ctx;

vscf_hybrid_private_key_delete(*(vscf_hybrid_private_key_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_hybrid_private_key_t /*2*/* hybrid_private_key_ctx = *(vscf_hybrid_private_key_t /*2*/**) &c_ctx;

const vscf_alg_id_t proxyResult = vscf_hybrid_private_key_alg_id(hybrid_private_key_ctx /*a1*/);
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

// Cast class context
vscf_hybrid_private_key_t /*2*/* hybrid_private_key_ctx = *(vscf_hybrid_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_private_key_alg_info(hybrid_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hybrid_private_key_t /*2*/* hybrid_private_key_ctx = *(vscf_hybrid_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_hybrid_private_key_len(hybrid_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_hybrid_private_key_t /*2*/* hybrid_private_key_ctx = *(vscf_hybrid_private_key_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_hybrid_private_key_bitlen(hybrid_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_hybrid_private_key_t /*2*/* hybrid_private_key_ctx = *(vscf_hybrid_private_key_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_hybrid_private_key_is_valid(hybrid_private_key_ctx /*a1*/);
return ret;

// Cast class context
vscf_hybrid_private_key_t /*2*/* hybrid_private_key_ctx = *(vscf_hybrid_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_private_key_extract_public_key(hybrid_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hybrid_private_key_t /*2*/* hybrid_private_key_ctx = *(vscf_hybrid_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_private_key_first_key(hybrid_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hybrid_private_key_t /*2*/* hybrid_private_key_ctx = *(vscf_hybrid_private_key_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_private_key_second_key(hybrid_private_key_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_hybrid_key_alg_t **)&c_ctx = vscf_hybrid_key_alg_new();
return c_ctx;

vscf_hybrid_key_alg_delete(*(vscf_hybrid_key_alg_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Random

// Dependency setter: Cipher

// Dependency setter: Hash

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_key_alg_generate_ephemeral_key(hybrid_key_alg_ctx /*a1*/, jkey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_key_alg_import_public_key(hybrid_key_alg_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPublicKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

const vscf_raw_public_key_t */*5*/ proxyResult = vscf_hybrid_key_alg_export_public_key(hybrid_key_alg_ctx /*a1*/, jpublicKey /*TODO*/);
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

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_key_alg_import_private_key(hybrid_key_alg_ctx /*a1*/, jrawKey /*a9*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

const vscf_raw_private_key_t */*5*/ proxyResult = vscf_hybrid_key_alg_export_private_key(hybrid_key_alg_ctx /*a1*/, jprivateKey /*TODO*/);
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

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_hybrid_key_alg_can_encrypt(hybrid_key_alg_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_hybrid_key_alg_encrypted_len(hybrid_key_alg_ctx /*a1*/, jpublicKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_hybrid_key_alg_encrypted_len(hybrid_key_alg_ctx, public_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_hybrid_key_alg_encrypt(hybrid_key_alg_ctx /*a1*/, jpublicKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_hybrid_key_alg_can_decrypt(hybrid_key_alg_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_hybrid_key_alg_decrypted_len(hybrid_key_alg_ctx /*a1*/, jprivateKey /*TODO*/, jdataLen /*a9*/);
return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_hybrid_key_alg_decrypted_len(hybrid_key_alg_ctx, private_key.len/*a*/, data.len/*a*/));

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_hybrid_key_alg_decrypt(hybrid_key_alg_ctx /*a1*/, jprivateKey /*TODO*/, data /*a3*/, out /*a3*/);
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

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_hybrid_key_alg_can_sign(hybrid_key_alg_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_hybrid_key_alg_signature_len(hybrid_key_alg_ctx /*a1*/, jprivateKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_hybrid_key_alg_signature_len(hybrid_key_alg_ctx, private_key.len/*a*/));

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_hybrid_key_alg_sign_hash(hybrid_key_alg_ctx /*a1*/, jprivateKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
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

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_hybrid_key_alg_can_verify(hybrid_key_alg_ctx /*a1*/, jpublicKey /*TODO*/);
return ret;

// Wrap enums
jclass hashId_cls = (*jenv)->GetObjectClass(jenv, jhashId);
jmethodID hashId_methodID = (*jenv)->GetMethodID(jenv, hashId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ hash_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jhashId, hashId_methodID);

// Wrap input data
byte* digest_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdigest, NULL);
vsc_data_t digest = vsc_data(digest_arr, (*jenv)->GetArrayLength(jenv, jdigest));

// Wrap input data
byte* signature_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsignature, NULL);
vsc_data_t signature = vsc_data(signature_arr, (*jenv)->GetArrayLength(jenv, jsignature));

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscf_hybrid_key_alg_verify_hash(hybrid_key_alg_ctx /*a1*/, jpublicKey /*TODO*/, hash_id /*a7*/, digest /*a3*/, signature /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdigest, (jbyte*) digest_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsignature, (jbyte*) signature_arr, 0);

return ret;

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_hybrid_key_alg_setup_defaults(hybrid_key_alg_ctx /*a1*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_hybrid_key_alg_t /*2*/* hybrid_key_alg_ctx = *(vscf_hybrid_key_alg_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hybrid_key_alg_make_key(hybrid_key_alg_ctx /*a1*/, jfirstKey /*TODO*/, jsecondKey /*TODO*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapPrivateKey(jenv, jobj, proxyResult);
return ret;

// Wrap input data
byte* shared_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsharedKey, NULL);
vsc_data_t shared_key = vsc_data(shared_key_arr, (*jenv)->GetArrayLength(jenv, jsharedKey));

vscf_hybrid_key_alg_config_cipher(jcipher /*TODO*/, jhash /*TODO*/, shared_key /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsharedKey, (jbyte*) shared_key_arr, 0);


jlong c_ctx = 0;
*(vscf_simple_alg_info_t **)&c_ctx = vscf_simple_alg_info_new();
return c_ctx;

vscf_simple_alg_info_delete(*(vscf_simple_alg_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_simple_alg_info_t /*2*/* simple_alg_info_ctx = *(vscf_simple_alg_info_t /*2*/**) &c_ctx;

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

jlong c_ctx = 0;
*(vscf_hash_based_alg_info_t **)&c_ctx = vscf_hash_based_alg_info_new();
return c_ctx;

vscf_hash_based_alg_info_delete(*(vscf_hash_based_alg_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_hash_based_alg_info_t /*2*/* hash_based_alg_info_ctx = *(vscf_hash_based_alg_info_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_hash_based_alg_info_t /*2*/* hash_based_alg_info_ctx = *(vscf_hash_based_alg_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_cipher_alg_info_t **)&c_ctx = vscf_cipher_alg_info_new();
return c_ctx;

vscf_cipher_alg_info_delete(*(vscf_cipher_alg_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_cipher_alg_info_t /*2*/* cipher_alg_info_ctx = *(vscf_cipher_alg_info_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_cipher_alg_info_t /*2*/* cipher_alg_info_ctx = *(vscf_cipher_alg_info_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_cipher_alg_info_nonce(cipher_alg_info_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

jlong c_ctx = 0;
*(vscf_salted_kdf_alg_info_t **)&c_ctx = vscf_salted_kdf_alg_info_new();
return c_ctx;

vscf_salted_kdf_alg_info_delete(*(vscf_salted_kdf_alg_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_salted_kdf_alg_info_t /*2*/* salted_kdf_alg_info_ctx = *(vscf_salted_kdf_alg_info_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_salted_kdf_alg_info_t /*2*/* salted_kdf_alg_info_ctx = *(vscf_salted_kdf_alg_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_salted_kdf_alg_info_hash_alg_info(salted_kdf_alg_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_salted_kdf_alg_info_t /*2*/* salted_kdf_alg_info_ctx = *(vscf_salted_kdf_alg_info_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_salted_kdf_alg_info_salt(salted_kdf_alg_info_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscf_salted_kdf_alg_info_t /*2*/* salted_kdf_alg_info_ctx = *(vscf_salted_kdf_alg_info_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_salted_kdf_alg_info_iteration_count(salted_kdf_alg_info_ctx /*a1*/);
return ret;

jlong c_ctx = 0;
*(vscf_pbe_alg_info_t **)&c_ctx = vscf_pbe_alg_info_new();
return c_ctx;

vscf_pbe_alg_info_delete(*(vscf_pbe_alg_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_pbe_alg_info_t /*2*/* pbe_alg_info_ctx = *(vscf_pbe_alg_info_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_pbe_alg_info_t /*2*/* pbe_alg_info_ctx = *(vscf_pbe_alg_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_pbe_alg_info_kdf_alg_info(pbe_alg_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_pbe_alg_info_t /*2*/* pbe_alg_info_ctx = *(vscf_pbe_alg_info_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_pbe_alg_info_cipher_alg_info(pbe_alg_info_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_ecc_alg_info_t **)&c_ctx = vscf_ecc_alg_info_new();
return c_ctx;

vscf_ecc_alg_info_delete(*(vscf_ecc_alg_info_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscf_ecc_alg_info_t /*2*/* ecc_alg_info_ctx = *(vscf_ecc_alg_info_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_ecc_alg_info_t /*2*/* ecc_alg_info_ctx = *(vscf_ecc_alg_info_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_ecc_alg_info_t /*2*/* ecc_alg_info_ctx = *(vscf_ecc_alg_info_t /*2*/**) &c_ctx;

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

jlong c_ctx = 0;
*(vscf_alg_info_der_serializer_t **)&c_ctx = vscf_alg_info_der_serializer_new();
return c_ctx;

vscf_alg_info_der_serializer_delete(*(vscf_alg_info_der_serializer_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Asn1Writer

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_alg_info_der_serializer_serialized_len(alg_info_der_serializer_ctx, alg_info.len/*a*/));

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

vscf_alg_info_der_serializer_serialize(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/, out /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

vscf_alg_info_der_serializer_setup_defaults(alg_info_der_serializer_ctx /*a1*/);

// Wrap enums
jclass algId_cls = (*jenv)->GetObjectClass(jenv, jalgId);
jmethodID algId_methodID = (*jenv)->GetMethodID(jenv, algId_cls, "getCode", "()I");
vscf_alg_id_t /*8*/ alg_id = (vscf_alg_id_t /*8*/) (*jenv)->CallIntMethod(jenv, jalgId, algId_methodID);

jboolean ret = (jboolean) vscf_alg_info_der_serializer_is_alg_require_null_params(alg_id /*a7*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_simple_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_simple_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_kdf_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_hkdf_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_hkdf_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_hmac_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_hmac_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_cipher_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_pbkdf2_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_pbkdf2_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_pbes2_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_pbes2_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_ecc_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_ecc_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_compound_key_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_compound_key_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialized_hybrid_key_alg_info_len(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_hybrid_key_alg_info(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

// Cast class context
vscf_alg_info_der_serializer_t /*2*/* alg_info_der_serializer_ctx = *(vscf_alg_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_alg_info_der_serializer_serialize_inplace(alg_info_der_serializer_ctx /*a1*/, jalgInfo /*TODO*/);
return ret;

jlong c_ctx = 0;
*(vscf_alg_info_der_deserializer_t **)&c_ctx = vscf_alg_info_der_deserializer_new();
return c_ctx;

vscf_alg_info_der_deserializer_delete(*(vscf_alg_info_der_deserializer_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Asn1Reader

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize(alg_info_der_deserializer_ctx /*a1*/, data /*a3*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

return ret;

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

vscf_alg_info_der_deserializer_setup_defaults(alg_info_der_deserializer_ctx /*a1*/);

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_simple_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_ecc_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_compound_key_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Wrap enums
jclass oidId_cls = (*jenv)->GetObjectClass(jenv, joidId);
jmethodID oidId_methodID = (*jenv)->GetMethodID(jenv, oidId_cls, "getCode", "()I");
vscf_oid_id_t /*8*/ oid_id = (vscf_oid_id_t /*8*/) (*jenv)->CallIntMethod(jenv, joidId, oidId_methodID);

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_hybrid_key_alg_info(alg_info_der_deserializer_ctx /*a1*/, oid_id /*a7*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_alg_info_der_deserializer_t /*2*/* alg_info_der_deserializer_ctx = *(vscf_alg_info_der_deserializer_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_alg_info_der_deserializer_deserialize_inplace(alg_info_der_deserializer_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

jlong c_ctx = 0;
*(vscf_message_info_der_serializer_t **)&c_ctx = vscf_message_info_der_serializer_new();
return c_ctx;

vscf_message_info_der_serializer_delete(*(vscf_message_info_der_serializer_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Asn1Reader

// Dependency setter: Asn1Writer

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_len(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_len(message_info_der_serializer_ctx, message_info.len/*a*/));

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_serialize(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/, out /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_read_prefix(message_info_der_serializer_ctx /*a1*/, data /*a3*/);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

const vscf_message_info_t */*5*/ proxyResult = vscf_message_info_der_serializer_deserialize(message_info_der_serializer_ctx /*a1*/, data /*a3*/);
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

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_footer_len(message_info_der_serializer_ctx /*a1*/, jmessageInfoFooter /*a9*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_message_info_der_serializer_serialized_footer_len(message_info_der_serializer_ctx, message_info_footer.len/*a*/));

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_serialize_footer(message_info_der_serializer_ctx /*a1*/, jmessageInfoFooter /*a9*/, out /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

const vscf_message_info_footer_t */*5*/ proxyResult = vscf_message_info_der_serializer_deserialize_footer(message_info_der_serializer_ctx /*a1*/, data /*a3*/);
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

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_setup_defaults(message_info_der_serializer_ctx /*a1*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_custom_params_len(message_info_der_serializer_ctx /*a1*/, jcustomParams /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_custom_params(message_info_der_serializer_ctx /*a1*/, jcustomParams /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_footer_info_len(message_info_der_serializer_ctx /*a1*/, jfooterInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_footer_info(message_info_der_serializer_ctx /*a1*/, jfooterInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_signed_data_info_internal(message_info_der_serializer_ctx /*a1*/, jsignedDataInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_key_recipient_info_len(message_info_der_serializer_ctx /*a1*/, jkeyRecipientInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_key_recipient_info(message_info_der_serializer_ctx /*a1*/, jkeyRecipientInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_password_recipient_info_len(message_info_der_serializer_ctx /*a1*/, jpasswordRecipientInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_password_recipient_info(message_info_der_serializer_ctx /*a1*/, jpasswordRecipientInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_recipient_infos_len(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_recipient_infos(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_encrypted_content_info_len(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_encrypted_content_info(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_enveloped_data_len(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_enveloped_data(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_cms_content_info_len(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_cms_content_info_(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_signer_infos_len(message_info_der_serializer_ctx /*a1*/, jmessageInfoFooter /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_signer_infos(message_info_der_serializer_ctx /*a1*/, jmessageInfoFooter /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialized_signer_info_len(message_info_der_serializer_ctx /*a1*/, jsignerInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_message_info_der_serializer_serialize_signer_info(message_info_der_serializer_ctx /*a1*/, jsignerInfo /*a9*/);
return ret;

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_custom_params(message_info_der_serializer_ctx /*a1*/, jcustomParams /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_cipher_kdf(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_cipher_padding(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_footer_info(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_signed_data_info(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_key_recipient_info(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_password_recipient_info(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_recipient_infos(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_encrypted_content_info(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_enveloped_data(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_cms_content_info(message_info_der_serializer_ctx /*a1*/, jmessageInfo /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_signer_infos(message_info_der_serializer_ctx /*a1*/, jmessageInfoFooter /*a9*/);

// Cast class context
vscf_message_info_der_serializer_t /*2*/* message_info_der_serializer_ctx = *(vscf_message_info_der_serializer_t /*2*/**) &c_ctx;

vscf_message_info_der_serializer_deserialize_signer_info(message_info_der_serializer_ctx /*a1*/, jmessageInfoFooter /*a9*/);

jlong c_ctx = 0;
*(vscf_random_padding_t **)&c_ctx = vscf_random_padding_new();
return c_ctx;

vscf_random_padding_delete(*(vscf_random_padding_t /*2*/ **) &c_ctx /*5*/);

// Dependency setter: Random

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

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

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

const vscf_impl_t */*6*/ proxyResult = vscf_random_padding_produce_alg_info(random_padding_ctx /*a1*/);
vscf_impl_shallow_copy((vscf_impl_t */*6*/) proxyResult);
jobject ret = wrapAlgInfo(jenv, jobj, proxyResult);
return ret;

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_random_padding_restore_alg_info(random_padding_ctx /*a1*/, jalgInfo /*TODO*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

vscf_random_padding_configure(random_padding_ctx /*a1*/, jparams /*a9*/);

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_random_padding_padded_data_len(random_padding_ctx /*a1*/, jdataLen /*a9*/);
return ret;

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_random_padding_len(random_padding_ctx /*a1*/);
return ret;

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_random_padding_len_max(random_padding_ctx /*a1*/);
return ret;

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

vscf_random_padding_start_data_processing(random_padding_ctx /*a1*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscf_random_padding_process_data(random_padding_ctx /*a1*/, data /*a3*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_random_padding_len(random_padding_ctx));

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_random_padding_finish_data_processing(random_padding_ctx /*a1*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

vscf_random_padding_start_padded_data_processing(random_padding_ctx /*a1*/);

// Wrap input data
byte* data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdata, NULL);
vsc_data_t data = vsc_data(data_arr, (*jenv)->GetArrayLength(jenv, jdata));

vsc_buffer_t *out = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

vscf_random_padding_process_padded_data(random_padding_ctx /*a1*/, data /*a3*/, out /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdata, (jbyte*) data_arr, 0);

vsc_buffer_delete(out);

return ret;

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

jint ret = (jint) vscf_random_padding_finish_padded_data_processing_out_len(random_padding_ctx /*a1*/);
return ret;

vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_random_padding_finish_padded_data_processing_out_len(random_padding_ctx));

// Cast class context
vscf_random_padding_t /*2*/* random_padding_ctx = *(vscf_random_padding_t /*2*/**) &c_ctx;

vscf_status_t status = vscf_random_padding_finish_padded_data_processing(random_padding_ctx /*a1*/, out /*a3*/);
if (status != vscf_status_SUCCESS) {
    throwFoundationException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(out));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(out), (jbyte*) vsc_buffer_bytes(out));
vsc_buffer_delete(out);

return ret;
