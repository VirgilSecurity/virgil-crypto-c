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

jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetException");
if (NULL == cls) {
    VSCF_ASSERT("Class PheException not found.");
    return 0;
}

jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");
if (NULL == methodID) {
    VSCF_ASSERT("Class com.virgilsecurity.crypto.ratchet.RatchetException has no constructor.");
    return 0;
}
jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);
if (NULL == obj) {
    VSCF_ASSERT("Can't instantiate com.virgilsecurity.crypto.ratchet.RatchetException.");
    return 0;
}
return (*jenv)->Throw(jenv, obj);

jlong c_ctx = 0;
*(vscr_ratchet_message_t **)&c_ctx = vscr_ratchet_message_new();
return c_ctx;

vscr_ratchet_message_delete(*(vscr_ratchet_message_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

const vscr_msg_type_t proxyResult = vscr_ratchet_message_get_type(ratchet_message_ctx /*a1*/);
jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/MsgType");
if (NULL == cls) {
    VSCF_ASSERT("Enum MsgType not found.");
}

jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "fromCode", "(I)Lcom/virgilsecurity/crypto/ratchet/MsgType;");
if (NULL == methodID) {
    VSCF_ASSERT("Enum MsgType has no method 'fromCode'.");
}
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);
return ret;

// Cast class context
vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

jint ret = (jint) vscr_ratchet_message_get_counter(ratchet_message_ctx /*a1*/);
return ret;

// Cast class context
vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_sender_identity_key_id(ratchet_message_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_receiver_identity_key_id(ratchet_message_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_receiver_long_term_key_id(ratchet_message_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

const vsc_data_t /*3*/ proxyResult = vscr_ratchet_message_get_receiver_one_time_key_id(ratchet_message_ctx /*a1*/);
jbyteArray ret = NULL;
if (proxyResult.len > 0) {
    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);
    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, (jbyte*) proxyResult.bytes);
}
return ret;

// Cast class context
vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

jint ret = (jint) vscr_ratchet_message_serialize_len(ratchet_message_ctx /*a1*/);
return ret;

vsc_buffer_t *output = vsc_buffer_new_with_capacity(vscr_ratchet_message_serialize_len(ratchet_message_ctx));

// Cast class context
vscr_ratchet_message_t /*2*/* ratchet_message_ctx = *(vscr_ratchet_message_t /*2*/**) &c_ctx;

vscr_ratchet_message_serialize(ratchet_message_ctx /*a1*/, output /*a3*/);
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(output));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(output), (jbyte*) vsc_buffer_bytes(output));
vsc_buffer_delete(output);

return ret;

// Wrap input data
byte* input_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinput, NULL);
vsc_data_t input = vsc_data(input_arr, (*jenv)->GetArrayLength(jenv, jinput));

const vscr_self_t */*5*/ proxyResult = vscr_ratchet_message_deserialize(input /*a3*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/Self");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Self not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/Self;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Self has no 'getInstance' method.");
}
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jinput, (jbyte*) input_arr, 0);

return ret;

jlong c_ctx = 0;
*(vscr_ratchet_session_t **)&c_ctx = vscr_ratchet_session_new();
return c_ctx;

vscr_ratchet_session_delete(*(vscr_ratchet_session_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

vscr_status_t status = vscr_ratchet_session_setup_defaults(ratchet_session_ctx /*a1*/);
if (status != vscr_status_SUCCESS) {
    throwRatchetException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* sender_identity_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsenderIdentityKeyId, NULL);
vsc_data_t sender_identity_key_id = vsc_data(sender_identity_key_id_arr, (*jenv)->GetArrayLength(jenv, jsenderIdentityKeyId));

// Wrap input data
byte* receiver_identity_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverIdentityKeyId, NULL);
vsc_data_t receiver_identity_key_id = vsc_data(receiver_identity_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverIdentityKeyId));

// Wrap input data
byte* receiver_long_term_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverLongTermKeyId, NULL);
vsc_data_t receiver_long_term_key_id = vsc_data(receiver_long_term_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverLongTermKeyId));

// Wrap input data
byte* receiver_one_time_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverOneTimeKeyId, NULL);
vsc_data_t receiver_one_time_key_id = vsc_data(receiver_one_time_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverOneTimeKeyId));

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

vscr_status_t status = vscr_ratchet_session_initiate(ratchet_session_ctx /*a1*/, jsenderIdentityPrivateKey /*TODO*/, sender_identity_key_id /*a3*/, jreceiverIdentityPublicKey /*TODO*/, receiver_identity_key_id /*a3*/, jreceiverLongTermPublicKey /*TODO*/, receiver_long_term_key_id /*a3*/, jreceiverOneTimePublicKey /*TODO*/, receiver_one_time_key_id /*a3*/, jenablePostQuantum /*a9*/);
if (status != vscr_status_SUCCESS) {
    throwRatchetException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsenderIdentityKeyId, (jbyte*) sender_identity_key_id_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jreceiverIdentityKeyId, (jbyte*) receiver_identity_key_id_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jreceiverLongTermKeyId, (jbyte*) receiver_long_term_key_id_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jreceiverOneTimeKeyId, (jbyte*) receiver_one_time_key_id_arr, 0);


// Wrap input data
byte* sender_identity_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jsenderIdentityKeyId, NULL);
vsc_data_t sender_identity_key_id = vsc_data(sender_identity_key_id_arr, (*jenv)->GetArrayLength(jenv, jsenderIdentityKeyId));

// Wrap input data
byte* receiver_identity_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverIdentityKeyId, NULL);
vsc_data_t receiver_identity_key_id = vsc_data(receiver_identity_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverIdentityKeyId));

// Wrap input data
byte* receiver_long_term_key_id_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jreceiverLongTermKeyId, NULL);
vsc_data_t receiver_long_term_key_id = vsc_data(receiver_long_term_key_id_arr, (*jenv)->GetArrayLength(jenv, jreceiverLongTermKeyId));

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

vscr_status_t status = vscr_ratchet_session_initiate_no_one_time_key(ratchet_session_ctx /*a1*/, jsenderIdentityPrivateKey /*TODO*/, sender_identity_key_id /*a3*/, jreceiverIdentityPublicKey /*TODO*/, receiver_identity_key_id /*a3*/, jreceiverLongTermPublicKey /*TODO*/, receiver_long_term_key_id /*a3*/, jenablePostQuantum /*a9*/);
if (status != vscr_status_SUCCESS) {
    throwRatchetException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jsenderIdentityKeyId, (jbyte*) sender_identity_key_id_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jreceiverIdentityKeyId, (jbyte*) receiver_identity_key_id_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jreceiverLongTermKeyId, (jbyte*) receiver_long_term_key_id_arr, 0);


// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

vscr_status_t status = vscr_ratchet_session_respond(ratchet_session_ctx /*a1*/, jsenderIdentityPublicKey /*TODO*/, jreceiverIdentityPrivateKey /*TODO*/, jreceiverLongTermPrivateKey /*TODO*/, jreceiverOneTimePrivateKey /*TODO*/, jmessage /*a9*/, jenablePostQuantum /*a9*/);
if (status != vscr_status_SUCCESS) {
    throwRatchetException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

vscr_status_t status = vscr_ratchet_session_respond_no_one_time_key(ratchet_session_ctx /*a1*/, jsenderIdentityPublicKey /*TODO*/, jreceiverIdentityPrivateKey /*TODO*/, jreceiverLongTermPrivateKey /*TODO*/, jmessage /*a9*/, jenablePostQuantum /*a9*/);
if (status != vscr_status_SUCCESS) {
    throwRatchetException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscr_ratchet_session_is_initiator(ratchet_session_ctx /*a1*/);
return ret;

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscr_ratchet_session_is_pqc_enabled(ratchet_session_ctx /*a1*/);
return ret;

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscr_ratchet_session_received_first_response(ratchet_session_ctx /*a1*/);
return ret;

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

jboolean ret = (jboolean) vscr_ratchet_session_receiver_has_one_time_public_key(ratchet_session_ctx /*a1*/);
return ret;

// Wrap input data
byte* plain_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jplainText, NULL);
vsc_data_t plain_text = vsc_data(plain_text_arr, (*jenv)->GetArrayLength(jenv, jplainText));

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

const vscr_ratchet_message_t */*5*/ proxyResult = vscr_ratchet_session_encrypt(ratchet_session_ctx /*a1*/, plain_text /*a3*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/RatchetMessage");
if (NULL == result_cls) {
    VSCF_ASSERT("Class RatchetMessage not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/RatchetMessage;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class RatchetMessage has no 'getInstance' method.");
}
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jplainText, (jbyte*) plain_text_arr, 0);

return ret;

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

jint ret = (jint) vscr_ratchet_session_decrypt_len(ratchet_session_ctx /*a1*/, jmessage /*a9*/);
return ret;

vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vscr_ratchet_session_decrypt_len(ratchet_session_ctx, message.len/*a*/));

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

vscr_status_t status = vscr_ratchet_session_decrypt(ratchet_session_ctx /*a1*/, jmessage /*a9*/, plain_text /*a3*/);
if (status != vscr_status_SUCCESS) {
    throwRatchetException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), (jbyte*) vsc_buffer_bytes(plain_text));
vsc_buffer_delete(plain_text);

return ret;

// Cast class context
vscr_ratchet_session_t /*2*/* ratchet_session_ctx = *(vscr_ratchet_session_t /*2*/**) &c_ctx;

const vscr_buffer_t */*5*/ proxyResult = vscr_ratchet_session_serialize(ratchet_session_ctx /*a1*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/Buffer");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Buffer not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/Buffer;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Buffer has no 'getInstance' method.");
}
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
return ret;

// Wrap input data
byte* input_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jinput, NULL);
vsc_data_t input = vsc_data(input_arr, (*jenv)->GetArrayLength(jenv, jinput));

const vscr_self_t */*5*/ proxyResult = vscr_ratchet_session_deserialize(input /*a3*/);
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/ratchet/Self");
if (NULL == result_cls) {
    VSCF_ASSERT("Class Self not found.");
}
jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, "getInstance", "(J)Lcom/virgilsecurity/crypto/ratchet/Self;");
if (NULL == result_methodID) {
    VSCF_ASSERT("Class Self has no 'getInstance' method.");
}
jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, result_methodID, (jlong) proxyResult);
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jinput, (jbyte*) input_arr, 0);

return ret;
