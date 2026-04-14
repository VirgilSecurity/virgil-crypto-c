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

jclass cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheException");
if (NULL == cls) {
    VSCF_ASSERT("Class PheException not found.");
    return 0;
}

jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");
if (NULL == methodID) {
    VSCF_ASSERT("Class com.virgilsecurity.crypto.phe.PheException has no constructor.");
    return 0;
}
jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);
if (NULL == obj) {
    VSCF_ASSERT("Can't instantiate com.virgilsecurity.crypto.phe.PheException.");
    return 0;
}
return (*jenv)->Throw(jenv, obj);

jlong c_ctx = 0;
*(vsce_phe_server_t **)&c_ctx = vsce_phe_server_new();
return c_ctx;

vsce_phe_server_delete(*(vsce_phe_server_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_server_setup_defaults(phe_server_ctx /*a1*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}

vsc_buffer_t *server_private_key = vsc_buffer_new_with_capacity(phe private key length);

vsc_buffer_t *server_public_key = vsc_buffer_new_with_capacity(phe public key length);

// Cast class context
vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_server_generate_server_key_pair(phe_server_ctx /*a1*/, server_private_key /*a3*/, server_public_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheServerGenerateServerKeyPairResult");
vsc_buffer_delete(server_private_key);

vsc_buffer_delete(server_public_key);

return ret;

// Cast class context
vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

jint ret = (jint) vsce_phe_server_enrollment_response_len(phe_server_ctx /*a1*/);
return ret;

// Wrap input data
byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

// Wrap input data
byte* server_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL);
vsc_data_t server_public_key = vsc_data(server_public_key_arr, (*jenv)->GetArrayLength(jenv, jserverPublicKey));

vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len(phe_server_ctx));

// Cast class context
vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_server_get_enrollment(phe_server_ctx /*a1*/, server_private_key /*a3*/, server_public_key /*a3*/, enrollment_response /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(enrollment_response));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(enrollment_response), (jbyte*) vsc_buffer_bytes(enrollment_response));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jserverPublicKey, (jbyte*) server_public_key_arr, 0);

vsc_buffer_delete(enrollment_response);

return ret;

// Cast class context
vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

jint ret = (jint) vsce_phe_server_verify_password_response_len(phe_server_ctx /*a1*/);
return ret;

// Wrap input data
byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

// Wrap input data
byte* server_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL);
vsc_data_t server_public_key = vsc_data(server_public_key_arr, (*jenv)->GetArrayLength(jenv, jserverPublicKey));

// Wrap input data
byte* verify_password_request_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jverifyPasswordRequest, NULL);
vsc_data_t verify_password_request = vsc_data(verify_password_request_arr, (*jenv)->GetArrayLength(jenv, jverifyPasswordRequest));

vsc_buffer_t *verify_password_response = vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len(phe_server_ctx));

// Cast class context
vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_server_verify_password(phe_server_ctx /*a1*/, server_private_key /*a3*/, server_public_key /*a3*/, verify_password_request /*a3*/, verify_password_response /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(verify_password_response));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(verify_password_response), (jbyte*) vsc_buffer_bytes(verify_password_response));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jserverPublicKey, (jbyte*) server_public_key_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jverifyPasswordRequest, (jbyte*) verify_password_request_arr, 0);

vsc_buffer_delete(verify_password_response);

return ret;

// Cast class context
vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

jint ret = (jint) vsce_phe_server_update_token_len(phe_server_ctx /*a1*/);
return ret;

// Wrap input data
byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

vsc_buffer_t *new_server_private_key = vsc_buffer_new_with_capacity(phe private key length);

vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(phe public key length);

vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(vsce_phe_server_update_token_len(phe_server_ctx));

// Cast class context
vsce_phe_server_t /*2*/* phe_server_ctx = *(vsce_phe_server_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_server_rotate_keys(phe_server_ctx /*a1*/, server_private_key /*a3*/, new_server_private_key /*a3*/, new_server_public_key /*a3*/, update_token /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheServerRotateKeysResult");
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

vsc_buffer_delete(new_server_private_key);

vsc_buffer_delete(new_server_public_key);

vsc_buffer_delete(update_token);

return ret;

jlong c_ctx = 0;
*(vsce_phe_client_t **)&c_ctx = vsce_phe_client_new();
return c_ctx;

vsce_phe_client_delete(*(vsce_phe_client_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_client_setup_defaults(phe_client_ctx /*a1*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* client_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jclientPrivateKey, NULL);
vsc_data_t client_private_key = vsc_data(client_private_key_arr, (*jenv)->GetArrayLength(jenv, jclientPrivateKey));

// Wrap input data
byte* server_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL);
vsc_data_t server_public_key = vsc_data(server_public_key_arr, (*jenv)->GetArrayLength(jenv, jserverPublicKey));

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_client_set_keys(phe_client_ctx /*a1*/, client_private_key /*a3*/, server_public_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jclientPrivateKey, (jbyte*) client_private_key_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jserverPublicKey, (jbyte*) server_public_key_arr, 0);


vsc_buffer_t *client_private_key = vsc_buffer_new_with_capacity(phe private key length);

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_client_generate_client_private_key(phe_client_ctx /*a1*/, client_private_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(client_private_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(client_private_key), (jbyte*) vsc_buffer_bytes(client_private_key));
vsc_buffer_delete(client_private_key);

return ret;

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

jint ret = (jint) vsce_phe_client_enrollment_record_len(phe_client_ctx /*a1*/);
return ret;

// Wrap input data
byte* enrollment_response_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jenrollmentResponse, NULL);
vsc_data_t enrollment_response = vsc_data(enrollment_response_arr, (*jenv)->GetArrayLength(jenv, jenrollmentResponse));

// Wrap input data
byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(phe_client_ctx));

vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(phe account key length);

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_client_enroll_account(phe_client_ctx /*a1*/, enrollment_response /*a3*/, password /*a3*/, enrollment_record /*a3*/, account_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheClientEnrollAccountResult");
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jenrollmentResponse, (jbyte*) enrollment_response_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

vsc_buffer_delete(enrollment_record);

vsc_buffer_delete(account_key);

return ret;

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

jint ret = (jint) vsce_phe_client_verify_password_request_len(phe_client_ctx /*a1*/);
return ret;

// Wrap input data
byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

// Wrap input data
byte* enrollment_record_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, NULL);
vsc_data_t enrollment_record = vsc_data(enrollment_record_arr, (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

vsc_buffer_t *verify_password_request = vsc_buffer_new_with_capacity(vsce_phe_client_verify_password_request_len(phe_client_ctx));

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_client_create_verify_password_request(phe_client_ctx /*a1*/, password /*a3*/, enrollment_record /*a3*/, verify_password_request /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(verify_password_request));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(verify_password_request), (jbyte*) vsc_buffer_bytes(verify_password_request));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jenrollmentRecord, (jbyte*) enrollment_record_arr, 0);

vsc_buffer_delete(verify_password_request);

return ret;

// Wrap input data
byte* password_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jpassword, NULL);
vsc_data_t password = vsc_data(password_arr, (*jenv)->GetArrayLength(jenv, jpassword));

// Wrap input data
byte* enrollment_record_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, NULL);
vsc_data_t enrollment_record = vsc_data(enrollment_record_arr, (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

// Wrap input data
byte* verify_password_response_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jverifyPasswordResponse, NULL);
vsc_data_t verify_password_response = vsc_data(verify_password_response_arr, (*jenv)->GetArrayLength(jenv, jverifyPasswordResponse));

vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(phe account key length);

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_client_check_response_and_decrypt(phe_client_ctx /*a1*/, password /*a3*/, enrollment_record /*a3*/, verify_password_response /*a3*/, account_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(account_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(account_key), (jbyte*) vsc_buffer_bytes(account_key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jpassword, (jbyte*) password_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jenrollmentRecord, (jbyte*) enrollment_record_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jverifyPasswordResponse, (jbyte*) verify_password_response_arr, 0);

vsc_buffer_delete(account_key);

return ret;

// Wrap input data
byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(phe private key length);

vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(phe public key length);

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_client_rotate_keys(phe_client_ctx /*a1*/, update_token /*a3*/, new_client_private_key /*a3*/, new_server_public_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/PheClientRotateKeysResult");
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jupdateToken, (jbyte*) update_token_arr, 0);

vsc_buffer_delete(new_client_private_key);

vsc_buffer_delete(new_server_public_key);

return ret;

// Wrap input data
byte* enrollment_record_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, NULL);
vsc_data_t enrollment_record = vsc_data(enrollment_record_arr, (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

// Wrap input data
byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

vsc_buffer_t *new_enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(phe_client_ctx));

// Cast class context
vsce_phe_client_t /*2*/* phe_client_ctx = *(vsce_phe_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_client_update_enrollment_record(phe_client_ctx /*a1*/, enrollment_record /*a3*/, update_token /*a3*/, new_enrollment_record /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_enrollment_record));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(new_enrollment_record), (jbyte*) vsc_buffer_bytes(new_enrollment_record));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jenrollmentRecord, (jbyte*) enrollment_record_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jupdateToken, (jbyte*) update_token_arr, 0);

vsc_buffer_delete(new_enrollment_record);

return ret;

jlong c_ctx = 0;
*(vsce_phe_cipher_t **)&c_ctx = vsce_phe_cipher_new();
return c_ctx;

vsce_phe_cipher_delete(*(vsce_phe_cipher_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_cipher_setup_defaults(phe_cipher_ctx /*a1*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}

// Cast class context
vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

jint ret = (jint) vsce_phe_cipher_encrypt_len(phe_cipher_ctx /*a1*/, jplainTextLen /*a9*/);
return ret;

// Cast class context
vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

jint ret = (jint) vsce_phe_cipher_decrypt_len(phe_cipher_ctx /*a1*/, jcipherTextLen /*a9*/);
return ret;

// Wrap input data
byte* plain_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jplainText, NULL);
vsc_data_t plain_text = vsc_data(plain_text_arr, (*jenv)->GetArrayLength(jenv, jplainText));

// Wrap input data
byte* account_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL);
vsc_data_t account_key = vsc_data(account_key_arr, (*jenv)->GetArrayLength(jenv, jaccountKey));

vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_encrypt_len(phe_cipher_ctx, plain_text.len/*a*/));

// Cast class context
vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_cipher_encrypt(phe_cipher_ctx /*a1*/, plain_text /*a3*/, account_key /*a3*/, cipher_text /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(cipher_text));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(cipher_text), (jbyte*) vsc_buffer_bytes(cipher_text));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jplainText, (jbyte*) plain_text_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jaccountKey, (jbyte*) account_key_arr, 0);

vsc_buffer_delete(cipher_text);

return ret;

// Wrap input data
byte* cipher_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jcipherText, NULL);
vsc_data_t cipher_text = vsc_data(cipher_text_arr, (*jenv)->GetArrayLength(jenv, jcipherText));

// Wrap input data
byte* account_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL);
vsc_data_t account_key = vsc_data(account_key_arr, (*jenv)->GetArrayLength(jenv, jaccountKey));

vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_decrypt_len(phe_cipher_ctx, cipher_text.len/*a*/));

// Cast class context
vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_cipher_decrypt(phe_cipher_ctx /*a1*/, cipher_text /*a3*/, account_key /*a3*/, plain_text /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), (jbyte*) vsc_buffer_bytes(plain_text));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jcipherText, (jbyte*) cipher_text_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jaccountKey, (jbyte*) account_key_arr, 0);

vsc_buffer_delete(plain_text);

return ret;

// Wrap input data
byte* plain_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jplainText, NULL);
vsc_data_t plain_text = vsc_data(plain_text_arr, (*jenv)->GetArrayLength(jenv, jplainText));

// Wrap input data
byte* additional_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jadditionalData, NULL);
vsc_data_t additional_data = vsc_data(additional_data_arr, (*jenv)->GetArrayLength(jenv, jadditionalData));

// Wrap input data
byte* account_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL);
vsc_data_t account_key = vsc_data(account_key_arr, (*jenv)->GetArrayLength(jenv, jaccountKey));

vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_encrypt_len(phe_cipher_ctx, plain_text.len/*a*/));

// Cast class context
vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_cipher_auth_encrypt(phe_cipher_ctx /*a1*/, plain_text /*a3*/, additional_data /*a3*/, account_key /*a3*/, cipher_text /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(cipher_text));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(cipher_text), (jbyte*) vsc_buffer_bytes(cipher_text));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jplainText, (jbyte*) plain_text_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jadditionalData, (jbyte*) additional_data_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jaccountKey, (jbyte*) account_key_arr, 0);

vsc_buffer_delete(cipher_text);

return ret;

// Wrap input data
byte* cipher_text_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jcipherText, NULL);
vsc_data_t cipher_text = vsc_data(cipher_text_arr, (*jenv)->GetArrayLength(jenv, jcipherText));

// Wrap input data
byte* additional_data_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jadditionalData, NULL);
vsc_data_t additional_data = vsc_data(additional_data_arr, (*jenv)->GetArrayLength(jenv, jadditionalData));

// Wrap input data
byte* account_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jaccountKey, NULL);
vsc_data_t account_key = vsc_data(account_key_arr, (*jenv)->GetArrayLength(jenv, jaccountKey));

vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_decrypt_len(phe_cipher_ctx, cipher_text.len/*a*/));

// Cast class context
vsce_phe_cipher_t /*2*/* phe_cipher_ctx = *(vsce_phe_cipher_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_phe_cipher_auth_decrypt(phe_cipher_ctx /*a1*/, cipher_text /*a3*/, additional_data /*a3*/, account_key /*a3*/, plain_text /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), (jbyte*) vsc_buffer_bytes(plain_text));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jcipherText, (jbyte*) cipher_text_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jadditionalData, (jbyte*) additional_data_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jaccountKey, (jbyte*) account_key_arr, 0);

vsc_buffer_delete(plain_text);

return ret;

jlong c_ctx = 0;
*(vsce_uokms_client_t **)&c_ctx = vsce_uokms_client_new();
return c_ctx;

vsce_uokms_client_delete(*(vsce_uokms_client_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_client_setup_defaults(uokms_client_ctx /*a1*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* client_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jclientPrivateKey, NULL);
vsc_data_t client_private_key = vsc_data(client_private_key_arr, (*jenv)->GetArrayLength(jenv, jclientPrivateKey));

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_client_set_keys_oneparty(uokms_client_ctx /*a1*/, client_private_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jclientPrivateKey, (jbyte*) client_private_key_arr, 0);


// Wrap input data
byte* client_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jclientPrivateKey, NULL);
vsc_data_t client_private_key = vsc_data(client_private_key_arr, (*jenv)->GetArrayLength(jenv, jclientPrivateKey));

// Wrap input data
byte* server_public_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, NULL);
vsc_data_t server_public_key = vsc_data(server_public_key_arr, (*jenv)->GetArrayLength(jenv, jserverPublicKey));

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_client_set_keys(uokms_client_ctx /*a1*/, client_private_key /*a3*/, server_public_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jclientPrivateKey, (jbyte*) client_private_key_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jserverPublicKey, (jbyte*) server_public_key_arr, 0);


vsc_buffer_t *client_private_key = vsc_buffer_new_with_capacity(phe private key length);

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_client_generate_client_private_key(uokms_client_ctx /*a1*/, client_private_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(client_private_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(client_private_key), (jbyte*) vsc_buffer_bytes(client_private_key));
vsc_buffer_delete(client_private_key);

return ret;

vsc_buffer_t *wrap = vsc_buffer_new_with_capacity(phe public key length);

vsc_buffer_t *encryption_key = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_client_generate_encrypt_wrap(uokms_client_ctx /*a1*/, wrap /*a3*/, jencryptionKeyLen /*a9*/, encryption_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsClientGenerateEncryptWrapResult");
vsc_buffer_delete(wrap);

vsc_buffer_delete(encryption_key);

return ret;

// Wrap input data
byte* wrap_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jwrap, NULL);
vsc_data_t wrap = vsc_data(wrap_arr, (*jenv)->GetArrayLength(jenv, jwrap));

vsc_buffer_t *encryption_key = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

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

// Wrap input data
byte* wrap_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jwrap, NULL);
vsc_data_t wrap = vsc_data(wrap_arr, (*jenv)->GetArrayLength(jenv, jwrap));

vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(phe private key length);

vsc_buffer_t *decrypt_request = vsc_buffer_new_with_capacity(phe public key length);

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_client_generate_decrypt_request(uokms_client_ctx /*a1*/, wrap /*a3*/, deblind_factor /*a3*/, decrypt_request /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsClientGenerateDecryptRequestResult");
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jwrap, (jbyte*) wrap_arr, 0);

vsc_buffer_delete(deblind_factor);

vsc_buffer_delete(decrypt_request);

return ret;

// Wrap input data
byte* wrap_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jwrap, NULL);
vsc_data_t wrap = vsc_data(wrap_arr, (*jenv)->GetArrayLength(jenv, jwrap));

// Wrap input data
byte* decrypt_request_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdecryptRequest, NULL);
vsc_data_t decrypt_request = vsc_data(decrypt_request_arr, (*jenv)->GetArrayLength(jenv, jdecryptRequest));

// Wrap input data
byte* decrypt_response_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdecryptResponse, NULL);
vsc_data_t decrypt_response = vsc_data(decrypt_response_arr, (*jenv)->GetArrayLength(jenv, jdecryptResponse));

// Wrap input data
byte* deblind_factor_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdeblindFactor, NULL);
vsc_data_t deblind_factor = vsc_data(deblind_factor_arr, (*jenv)->GetArrayLength(jenv, jdeblindFactor));

vsc_buffer_t *encryption_key = vsc_buffer_new_with_capacity(/* TODO: determine capacity */);

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_client_process_decrypt_response(uokms_client_ctx /*a1*/, wrap /*a3*/, decrypt_request /*a3*/, decrypt_response /*a3*/, deblind_factor /*a3*/, jencryptionKeyLen /*a9*/, encryption_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(encryption_key));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(encryption_key), (jbyte*) vsc_buffer_bytes(encryption_key));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jwrap, (jbyte*) wrap_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdecryptRequest, (jbyte*) decrypt_request_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdecryptResponse, (jbyte*) decrypt_response_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdeblindFactor, (jbyte*) deblind_factor_arr, 0);

vsc_buffer_delete(encryption_key);

return ret;

// Wrap input data
byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(phe private key length);

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

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

vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(phe private key length);

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_client_generate_update_token_oneparty(uokms_client_ctx /*a1*/, update_token /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(update_token));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(update_token), (jbyte*) vsc_buffer_bytes(update_token));
vsc_buffer_delete(update_token);

return ret;

// Wrap input data
byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(phe private key length);

vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(phe public key length);

// Cast class context
vsce_uokms_client_t /*2*/* uokms_client_ctx = *(vsce_uokms_client_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_client_rotate_keys(uokms_client_ctx /*a1*/, update_token /*a3*/, new_client_private_key /*a3*/, new_server_public_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsClientRotateKeysResult");
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jupdateToken, (jbyte*) update_token_arr, 0);

vsc_buffer_delete(new_client_private_key);

vsc_buffer_delete(new_server_public_key);

return ret;

jlong c_ctx = 0;
*(vsce_uokms_server_t **)&c_ctx = vsce_uokms_server_new();
return c_ctx;

vsce_uokms_server_delete(*(vsce_uokms_server_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_server_setup_defaults(uokms_server_ctx /*a1*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}

vsc_buffer_t *server_private_key = vsc_buffer_new_with_capacity(phe private key length);

vsc_buffer_t *server_public_key = vsc_buffer_new_with_capacity(phe public key length);

// Cast class context
vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_server_generate_server_key_pair(uokms_server_ctx /*a1*/, server_private_key /*a3*/, server_public_key /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsServerGenerateServerKeyPairResult");
vsc_buffer_delete(server_private_key);

vsc_buffer_delete(server_public_key);

return ret;

// Cast class context
vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

jint ret = (jint) vsce_uokms_server_decrypt_response_len(uokms_server_ctx /*a1*/);
return ret;

// Wrap input data
byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

// Wrap input data
byte* decrypt_request_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jdecryptRequest, NULL);
vsc_data_t decrypt_request = vsc_data(decrypt_request_arr, (*jenv)->GetArrayLength(jenv, jdecryptRequest));

vsc_buffer_t *decrypt_response = vsc_buffer_new_with_capacity(vsce_uokms_server_decrypt_response_len(uokms_server_ctx));

// Cast class context
vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_server_process_decrypt_request(uokms_server_ctx /*a1*/, server_private_key /*a3*/, decrypt_request /*a3*/, decrypt_response /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(decrypt_response));
(*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(decrypt_response), (jbyte*) vsc_buffer_bytes(decrypt_response));
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jdecryptRequest, (jbyte*) decrypt_request_arr, 0);

vsc_buffer_delete(decrypt_response);

return ret;

// Wrap input data
byte* server_private_key_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, NULL);
vsc_data_t server_private_key = vsc_data(server_private_key_arr, (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

vsc_buffer_t *new_server_private_key = vsc_buffer_new_with_capacity(phe private key length);

vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(phe public key length);

vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(phe private key length);

// Cast class context
vsce_uokms_server_t /*2*/* uokms_server_ctx = *(vsce_uokms_server_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_server_rotate_keys(uokms_server_ctx /*a1*/, server_private_key /*a3*/, new_server_private_key /*a3*/, new_server_public_key /*a3*/, update_token /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
jclass result_cls = (*jenv)->FindClass(jenv, "com/virgilsecurity/crypto/phe/UokmsServerRotateKeysResult");
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jserverPrivateKey, (jbyte*) server_private_key_arr, 0);

vsc_buffer_delete(new_server_private_key);

vsc_buffer_delete(new_server_public_key);

vsc_buffer_delete(update_token);

return ret;

jlong c_ctx = 0;
*(vsce_uokms_wrap_rotation_t **)&c_ctx = vsce_uokms_wrap_rotation_new();
return c_ctx;

vsce_uokms_wrap_rotation_delete(*(vsce_uokms_wrap_rotation_t /*2*/ **) &c_ctx /*5*/);

// Cast class context
vsce_uokms_wrap_rotation_t /*2*/* uokms_wrap_rotation_ctx = *(vsce_uokms_wrap_rotation_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_wrap_rotation_setup_defaults(uokms_wrap_rotation_ctx /*a1*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}

// Wrap input data
byte* update_token_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jupdateToken, NULL);
vsc_data_t update_token = vsc_data(update_token_arr, (*jenv)->GetArrayLength(jenv, jupdateToken));

// Cast class context
vsce_uokms_wrap_rotation_t /*2*/* uokms_wrap_rotation_ctx = *(vsce_uokms_wrap_rotation_t /*2*/**) &c_ctx;

vsce_status_t status = vsce_uokms_wrap_rotation_set_update_token(uokms_wrap_rotation_ctx /*a1*/, update_token /*a3*/);
if (status != vsce_status_SUCCESS) {
    throwPheException(jenv, jobj, status);
    return NULL;
}
// Free resources
(*jenv)->ReleaseByteArrayElements(jenv, jupdateToken, (jbyte*) update_token_arr, 0);


// Wrap input data
byte* wrap_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, jwrap, NULL);
vsc_data_t wrap = vsc_data(wrap_arr, (*jenv)->GetArrayLength(jenv, jwrap));

vsc_buffer_t *new_wrap = vsc_buffer_new_with_capacity(phe public key length);

// Cast class context
vsce_uokms_wrap_rotation_t /*2*/* uokms_wrap_rotation_ctx = *(vsce_uokms_wrap_rotation_t /*2*/**) &c_ctx;

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
