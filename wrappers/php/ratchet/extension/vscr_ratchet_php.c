//
// Copyright (C) 2015-2019 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

#include <php.h>
#include <zend_exceptions.h>
#include <zend_list.h>
#include "vscr_assert.h"
#include "vscr_ratchet_php.h"
#include "vscf_foundation_php.h"
#include "vscr_ratchet_common.h"
#include "vscr_ratchet_key_id.h"
#include "vscr_ratchet_message.h"
#include "vscr_ratchet_session.h"
#include "vscr_ratchet_group_participants_info.h"
#include "vscr_ratchet_group_message.h"
#include "vscr_ratchet_group_ticket.h"
#include "vscr_ratchet_group_participants_ids.h"
#include "vscr_ratchet_group_session.h"

#define VSCR_HANDLE_STATUS(status) do { if(status != vscr_status_SUCCESS) { vscr_handle_throw_exception(status); } } while (false)

void
vscr_handle_throw_exception(vscr_status_t status) {
    switch(status) {

    case vscr_status_ERROR_PROTOBUF_DECODE:
        zend_throw_exception(NULL, "VSCR: Error during protobuf deserialization.", -1);
        break;
    case vscr_status_ERROR_BAD_MESSAGE_TYPE:
        zend_throw_exception(NULL, "VSCR: Bad message type.", -2);
        break;
    case vscr_status_ERROR_AES:
        zend_throw_exception(NULL, "VSCR: AES error.", -3);
        break;
    case vscr_status_ERROR_RNG_FAILED:
        zend_throw_exception(NULL, "VSCR: RNG failed.", -4);
        break;
    case vscr_status_ERROR_CURVE25519:
        zend_throw_exception(NULL, "VSCR: Curve25519 error.", -5);
        break;
    case vscr_status_ERROR_ED25519:
        zend_throw_exception(NULL, "VSCR: Curve25519 error.", -6);
        break;
    case vscr_status_ERROR_KEY_DESERIALIZATION_FAILED:
        zend_throw_exception(NULL, "VSCR: Key deserialization failed.", -7);
        break;
    case vscr_status_ERROR_INVALID_KEY_TYPE:
        zend_throw_exception(NULL, "VSCR: Invalid key type.", -8);
        break;
    case vscr_status_ERROR_IDENTITY_KEY_DOESNT_MATCH:
        zend_throw_exception(NULL, "VSCR: Identity key doesn't match.", -9);
        break;
    case vscr_status_ERROR_MESSAGE_ALREADY_DECRYPTED:
        zend_throw_exception(NULL, "VSCR: Message already decrypted.", -10);
        break;
    case vscr_status_ERROR_TOO_MANY_LOST_MESSAGES:
        zend_throw_exception(NULL, "VSCR: Too many lost messages.", -11);
        break;
    case vscr_status_ERROR_SENDER_CHAIN_MISSING:
        zend_throw_exception(NULL, "VSCR: Sender chain missing.", -12);
        break;
    case vscr_status_ERROR_SKIPPED_MESSAGE_MISSING:
        zend_throw_exception(NULL, "VSCR: Skipped message missing.", -13);
        break;
    case vscr_status_ERROR_SESSION_IS_NOT_INITIALIZED:
        zend_throw_exception(NULL, "VSCR: Session is not initialized.", -14);
        break;
    case vscr_status_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN:
        zend_throw_exception(NULL, "VSCR: Exceeded max plain text len.", -15);
        break;
    case vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN:
        zend_throw_exception(NULL, "VSCR: Too many messages for sender chain.", -16);
        break;
    case vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN:
        zend_throw_exception(NULL, "VSCR: Too many messages for receiver chain.", -17);
        break;
    case vscr_status_ERROR_INVALID_PADDING:
        zend_throw_exception(NULL, "VSCR: Invalid padding.", -18);
        break;
    case vscr_status_ERROR_TOO_MANY_PARTICIPANTS:
        zend_throw_exception(NULL, "VSCR: Too many participants.", -19);
        break;
    case vscr_status_ERROR_TOO_FEW_PARTICIPANTS:
        zend_throw_exception(NULL, "VSCR: Too few participants.", -20);
        break;
    case vscr_status_ERROR_SENDER_NOT_FOUND:
        zend_throw_exception(NULL, "VSCR: Sender not found.", -21);
        break;
    case vscr_status_ERROR_CANNOT_DECRYPT_OWN_MESSAGES:
        zend_throw_exception(NULL, "VSCR: Cannot decrypt own messages.", -22);
        break;
    case vscr_status_ERROR_INVALID_SIGNATURE:
        zend_throw_exception(NULL, "VSCR: Invalid signature.", -23);
        break;
    case vscr_status_ERROR_CANNOT_REMOVE_MYSELF:
        zend_throw_exception(NULL, "VSCR: Cannot remove myself.", -24);
        break;
    case vscr_status_ERROR_EPOCH_MISMATCH:
        zend_throw_exception(NULL, "VSCR: Epoch mismatch.", -25);
        break;
    case vscr_status_ERROR_EPOCH_NOT_FOUND:
        zend_throw_exception(NULL, "VSCR: Epoch not found.", -26);
        break;
    case vscr_status_ERROR_SESSION_ID_MISMATCH:
        zend_throw_exception(NULL, "VSCR: Session id mismatch.", -27);
        break;
    case vscr_status_ERROR_SIMULTANEOUS_GROUP_USER_OPERATION:
        zend_throw_exception(NULL, "VSCR: Simultaneous group user operation.", -28);
        break;
    case vscr_status_ERROR_MYSELF_IS_INCLUDED_IN_INFO:
        zend_throw_exception(NULL, "VSCR: Myself is included in info.", -29);
        break;
    }
}

//
// Constants
//
const char VSCR_RATCHET_PHP_VERSION[] = "0.12.0";
const char VSCR_RATCHET_PHP_EXTNAME[] = "vscr_ratchet_php";

static const char VSCR_RATCHET_KEY_ID_T_PHP_RES_NAME[] = "vscr_ratchet_key_id_t";
static const char VSCR_RATCHET_MESSAGE_T_PHP_RES_NAME[] = "vscr_ratchet_message_t";
static const char VSCR_RATCHET_SESSION_T_PHP_RES_NAME[] = "vscr_ratchet_session_t";
static const char VSCR_RATCHET_GROUP_PARTICIPANTS_INFO_T_PHP_RES_NAME[] = "vscr_ratchet_group_participants_info_t";
static const char VSCR_RATCHET_GROUP_MESSAGE_T_PHP_RES_NAME[] = "vscr_ratchet_group_message_t";
static const char VSCR_RATCHET_GROUP_TICKET_T_PHP_RES_NAME[] = "vscr_ratchet_group_ticket_t";
static const char VSCR_RATCHET_GROUP_PARTICIPANTS_IDS_T_PHP_RES_NAME[] = "vscr_ratchet_group_participants_ids_t";
static const char VSCR_RATCHET_GROUP_SESSION_T_PHP_RES_NAME[] = "vscr_ratchet_group_session_t";

//
// Constants func wrapping
//
VSCR_PUBLIC const char* vscr_ratchet_key_id_t_php_res_name(void) {
    return VSCR_RATCHET_KEY_ID_T_PHP_RES_NAME;
}

VSCR_PUBLIC const char* vscr_ratchet_message_t_php_res_name(void) {
    return VSCR_RATCHET_MESSAGE_T_PHP_RES_NAME;
}

VSCR_PUBLIC const char* vscr_ratchet_session_t_php_res_name(void) {
    return VSCR_RATCHET_SESSION_T_PHP_RES_NAME;
}

VSCR_PUBLIC const char* vscr_ratchet_group_participants_info_t_php_res_name(void) {
    return VSCR_RATCHET_GROUP_PARTICIPANTS_INFO_T_PHP_RES_NAME;
}

VSCR_PUBLIC const char* vscr_ratchet_group_message_t_php_res_name(void) {
    return VSCR_RATCHET_GROUP_MESSAGE_T_PHP_RES_NAME;
}

VSCR_PUBLIC const char* vscr_ratchet_group_ticket_t_php_res_name(void) {
    return VSCR_RATCHET_GROUP_TICKET_T_PHP_RES_NAME;
}

VSCR_PUBLIC const char* vscr_ratchet_group_participants_ids_t_php_res_name(void) {
    return VSCR_RATCHET_GROUP_PARTICIPANTS_IDS_T_PHP_RES_NAME;
}

VSCR_PUBLIC const char* vscr_ratchet_group_session_t_php_res_name(void) {
    return VSCR_RATCHET_GROUP_SESSION_T_PHP_RES_NAME;
}

//
// Registered resources
//
int LE_VSCR_RATCHET_KEY_ID_T;
int LE_VSCR_RATCHET_MESSAGE_T;
int LE_VSCR_RATCHET_SESSION_T;
int LE_VSCR_RATCHET_GROUP_PARTICIPANTS_INFO_T;
int LE_VSCR_RATCHET_GROUP_MESSAGE_T;
int LE_VSCR_RATCHET_GROUP_TICKET_T;
int LE_VSCR_RATCHET_GROUP_PARTICIPANTS_IDS_T;
int LE_VSCR_RATCHET_GROUP_SESSION_T;

//
// Registered resources func wrapping
//
VSCR_PUBLIC int le_vscr_ratchet_key_id_t(void) {
    return LE_VSCR_RATCHET_KEY_ID_T;
}

VSCR_PUBLIC int le_vscr_ratchet_message_t(void) {
    return LE_VSCR_RATCHET_MESSAGE_T;
}

VSCR_PUBLIC int le_vscr_ratchet_session_t(void) {
    return LE_VSCR_RATCHET_SESSION_T;
}

VSCR_PUBLIC int le_vscr_ratchet_group_participants_info_t(void) {
    return LE_VSCR_RATCHET_GROUP_PARTICIPANTS_INFO_T;
}

VSCR_PUBLIC int le_vscr_ratchet_group_message_t(void) {
    return LE_VSCR_RATCHET_GROUP_MESSAGE_T;
}

VSCR_PUBLIC int le_vscr_ratchet_group_ticket_t(void) {
    return LE_VSCR_RATCHET_GROUP_TICKET_T;
}

VSCR_PUBLIC int le_vscr_ratchet_group_participants_ids_t(void) {
    return LE_VSCR_RATCHET_GROUP_PARTICIPANTS_IDS_T;
}

VSCR_PUBLIC int le_vscr_ratchet_group_session_t(void) {
    return LE_VSCR_RATCHET_GROUP_SESSION_T;
}

//
// Extension init functions declaration
//
PHP_MINIT_FUNCTION(vscr_ratchet_php);
PHP_MSHUTDOWN_FUNCTION(vscr_ratchet_php);

//
// Functions wrapping
//
//
// Wrap method: vscr_ratchet_key_id_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_key_id_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_key_id_new_php) {
    vscr_ratchet_key_id_t *ratchet_key_id = vscr_ratchet_key_id_new();
    zend_resource *ratchet_key_id_res = zend_register_resource(ratchet_key_id, le_vscr_ratchet_key_id_t());
    RETVAL_RES(ratchet_key_id_res);
}

//
// Wrap method: vscr_ratchet_key_id_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_key_id_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_key_id_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscr_ratchet_key_id_t *ratchet_key_id = zend_fetch_resource_ex(in_ctx, vscr_ratchet_key_id_t_php_res_name(), le_vscr_ratchet_key_id_t());
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscr_ratchet_key_id_compute_public_key_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_key_id_compute_public_key_id_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_public_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_key_id_compute_public_key_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_public_key = NULL;
    size_t in_public_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_public_key, in_public_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_key_id_t *ratchet_key_id = zend_fetch_resource_ex(in_ctx, vscr_ratchet_key_id_t_php_res_name(), le_vscr_ratchet_key_id_t());
    vsc_data_t public_key = vsc_data((const byte*)in_public_key, in_public_key_len);

    //
    // Allocate output buffer for output 'key_id'
    //
    zend_string *out_key_id = zend_string_alloc(vscr_ratchet_common_KEY_ID_LEN, 0);
    vsc_buffer_t *key_id = vsc_buffer_new();
    vsc_buffer_use(key_id, (byte *)ZSTR_VAL(out_key_id), ZSTR_LEN(out_key_id));

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_key_id_compute_public_key_id(ratchet_key_id, public_key, key_id);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_key_id) = vsc_buffer_len(key_id);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        RETVAL_STR(out_key_id);
        vsc_buffer_destroy(&key_id);
    }
    else {
        zend_string_free(out_key_id);
    }
}

//
// Wrap method: vscr_ratchet_message_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_message_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_message_new_php) {
    vscr_ratchet_message_t *ratchet_message = vscr_ratchet_message_new();
    zend_resource *ratchet_message_res = zend_register_resource(ratchet_message, le_vscr_ratchet_message_t());
    RETVAL_RES(ratchet_message_res);
}

//
// Wrap method: vscr_ratchet_message_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_message_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_message_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscr_ratchet_message_t *ratchet_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscr_ratchet_message_get_type
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_message_get_type_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_message_get_type_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_message_t *ratchet_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());

    //
    // Call main function
    //
    int msg_type =vscr_ratchet_message_get_type(ratchet_message);

    //
    // Write returned result
    //
    RETVAL_LONG(msg_type);
}

//
// Wrap method: vscr_ratchet_message_get_counter
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_message_get_counter_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_message_get_counter_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_message_t *ratchet_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());

    //
    // Call main function
    //
    int res =vscr_ratchet_message_get_counter(ratchet_message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscr_ratchet_message_get_long_term_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_message_get_long_term_public_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_message_get_long_term_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_message_t *ratchet_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscr_ratchet_message_get_long_term_public_key(ratchet_message);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscr_ratchet_message_get_one_time_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_message_get_one_time_public_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_message_get_one_time_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_message_t *ratchet_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscr_ratchet_message_get_one_time_public_key(ratchet_message);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscr_ratchet_message_serialize_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_message_serialize_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_message_serialize_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_message_t *ratchet_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());

    //
    // Call main function
    //
    size_t res =vscr_ratchet_message_serialize_len(ratchet_message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscr_ratchet_message_serialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_message_serialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_message_serialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_message_t *ratchet_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());

    //
    // Allocate output buffer for output 'output'
    //
    zend_string *out_output = zend_string_alloc(vscr_ratchet_message_serialize_len(ratchet_message), 0);
    vsc_buffer_t *output = vsc_buffer_new();
    vsc_buffer_use(output, (byte *)ZSTR_VAL(out_output), ZSTR_LEN(out_output));

    //
    // Call main function
    //
    vscr_ratchet_message_serialize(ratchet_message, output);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_output) = vsc_buffer_len(output);

    //
    // Write returned result
    //
    RETVAL_STR(out_output);
}

//
// Wrap method: vscr_ratchet_message_deserialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_message_deserialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_input, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_message_deserialize_php) {

    //
    // Declare input argument
    //
    char *in_input = NULL;
    size_t in_input_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_input, in_input_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t input = vsc_data((const byte*)in_input, in_input_len);
    vscr_error_t error;
    vscr_error_reset(&error);

    //
    // Call main function
    //
    vscr_ratchet_message_t *ratchet_message_rs =vscr_ratchet_message_deserialize(input, &error);

    //
    // Handle error
    //
    vscr_status_t status = vscr_error_status(&error);
    VSCR_HANDLE_STATUS(status);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        zend_resource *ratchet_message_res = zend_register_resource(ratchet_message_rs, le_vscr_ratchet_message_t());
        RETVAL_RES(ratchet_message_res);
    }
}

//
// Wrap method: vscr_ratchet_session_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_session_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_new_php) {
    vscr_ratchet_session_t *ratchet_session = vscr_ratchet_session_new();
    zend_resource *ratchet_session_res = zend_register_resource(ratchet_session, le_vscr_ratchet_session_t());
    RETVAL_RES(ratchet_session_res);
}

//
// Wrap method: vscr_ratchet_session_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_session_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscr_ratchet_session_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_session_setup_defaults(ratchet_session);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_session_initiate
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_initiate_php,
    0 /*return_reference*/,
    5 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_sender_identity_private_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_receiver_identity_public_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_receiver_long_term_public_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_receiver_one_time_public_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_initiate_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_sender_identity_private_key = NULL;
    size_t in_sender_identity_private_key_len = 0;
    char *in_receiver_identity_public_key = NULL;
    size_t in_receiver_identity_public_key_len = 0;
    char *in_receiver_long_term_public_key = NULL;
    size_t in_receiver_long_term_public_key_len = 0;
    char *in_receiver_one_time_public_key = NULL;
    size_t in_receiver_one_time_public_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 5, 5)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_sender_identity_private_key, in_sender_identity_private_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_receiver_identity_public_key, in_receiver_identity_public_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_receiver_long_term_public_key, in_receiver_long_term_public_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_receiver_one_time_public_key, in_receiver_one_time_public_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());
    vsc_data_t sender_identity_private_key = vsc_data((const byte*)in_sender_identity_private_key, in_sender_identity_private_key_len);
    vsc_data_t receiver_identity_public_key = vsc_data((const byte*)in_receiver_identity_public_key, in_receiver_identity_public_key_len);
    vsc_data_t receiver_long_term_public_key = vsc_data((const byte*)in_receiver_long_term_public_key, in_receiver_long_term_public_key_len);
    vsc_data_t receiver_one_time_public_key = vsc_data((const byte*)in_receiver_one_time_public_key, in_receiver_one_time_public_key_len);

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_session_initiate(ratchet_session, sender_identity_private_key, receiver_identity_public_key, receiver_long_term_public_key, receiver_one_time_public_key);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_session_respond
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_respond_php,
    0 /*return_reference*/,
    6 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_sender_identity_public_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_receiver_identity_private_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_receiver_long_term_private_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_receiver_one_time_private_key, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_respond_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_sender_identity_public_key = NULL;
    size_t in_sender_identity_public_key_len = 0;
    char *in_receiver_identity_private_key = NULL;
    size_t in_receiver_identity_private_key_len = 0;
    char *in_receiver_long_term_private_key = NULL;
    size_t in_receiver_long_term_private_key_len = 0;
    char *in_receiver_one_time_private_key = NULL;
    size_t in_receiver_one_time_private_key_len = 0;
    zval *in_message = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 6, 6)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_sender_identity_public_key, in_sender_identity_public_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_receiver_identity_private_key, in_receiver_identity_private_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_receiver_long_term_private_key, in_receiver_long_term_private_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_receiver_one_time_private_key, in_receiver_one_time_private_key_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());
    vsc_data_t sender_identity_public_key = vsc_data((const byte*)in_sender_identity_public_key, in_sender_identity_public_key_len);
    vsc_data_t receiver_identity_private_key = vsc_data((const byte*)in_receiver_identity_private_key, in_receiver_identity_private_key_len);
    vsc_data_t receiver_long_term_private_key = vsc_data((const byte*)in_receiver_long_term_private_key, in_receiver_long_term_private_key_len);
    vsc_data_t receiver_one_time_private_key = vsc_data((const byte*)in_receiver_one_time_private_key, in_receiver_one_time_private_key_len);
    vscr_ratchet_message_t *message = zend_fetch_resource_ex(in_message, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_session_respond(ratchet_session, sender_identity_public_key, receiver_identity_private_key, receiver_long_term_private_key, receiver_one_time_private_key, message);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_session_is_initiator
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_is_initiator_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_is_initiator_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());

    //
    // Call main function
    //
    zend_bool res =vscr_ratchet_session_is_initiator(ratchet_session);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscr_ratchet_session_received_first_response
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_received_first_response_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_received_first_response_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());

    //
    // Call main function
    //
    zend_bool res =vscr_ratchet_session_received_first_response(ratchet_session);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscr_ratchet_session_receiver_has_one_time_public_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_receiver_has_one_time_public_key_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_receiver_has_one_time_public_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());

    //
    // Call main function
    //
    zend_bool res =vscr_ratchet_session_receiver_has_one_time_public_key(ratchet_session);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscr_ratchet_session_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_encrypt_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_plain_text, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_plain_text = NULL;
    size_t in_plain_text_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_plain_text, in_plain_text_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());
    vsc_data_t plain_text = vsc_data((const byte*)in_plain_text, in_plain_text_len);
    vscr_error_t error;
    vscr_error_reset(&error);

    //
    // Call main function
    //
    vscr_ratchet_message_t *ratchet_message =vscr_ratchet_session_encrypt(ratchet_session, plain_text, &error);

    //
    // Handle error
    //
    vscr_status_t status = vscr_error_status(&error);
    VSCR_HANDLE_STATUS(status);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        zend_resource *ratchet_message_res = zend_register_resource(ratchet_message, le_vscr_ratchet_message_t());
        RETVAL_RES(ratchet_message_res);
    }
}

//
// Wrap method: vscr_ratchet_session_decrypt_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_decrypt_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_decrypt_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());
    vscr_ratchet_message_t *message = zend_fetch_resource_ex(in_message, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());

    //
    // Call main function
    //
    size_t res =vscr_ratchet_session_decrypt_len(ratchet_session, message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscr_ratchet_session_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_decrypt_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());
    vscr_ratchet_message_t *message = zend_fetch_resource_ex(in_message, vscr_ratchet_message_t_php_res_name(), le_vscr_ratchet_message_t());

    //
    // Allocate output buffer for output 'plain_text'
    //
    zend_string *out_plain_text = zend_string_alloc(vscr_ratchet_session_decrypt_len(ratchet_session, message), 0);
    vsc_buffer_t *plain_text = vsc_buffer_new();
    vsc_buffer_use(plain_text, (byte *)ZSTR_VAL(out_plain_text), ZSTR_LEN(out_plain_text));

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_session_decrypt(ratchet_session, message, plain_text);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_plain_text) = vsc_buffer_len(plain_text);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        RETVAL_STR(out_plain_text);
        vsc_buffer_destroy(&plain_text);
    }
    else {
        zend_string_free(out_plain_text);
    }
}

//
// Wrap method: vscr_ratchet_session_serialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_serialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_serialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());

    //
    // Call main function
    //
    vsc_buffer_t *out_buffer_temp =vscr_ratchet_session_serialize(ratchet_session);
    vsc_data_t out_data_temp = vsc_buffer_data(out_buffer_temp);
    zend_string *out_buffer = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);
    vsc_buffer_destroy(&out_buffer_temp);

    //
    // Write returned result
    //
    RETVAL_STR(out_buffer);
}

//
// Wrap method: vscr_ratchet_session_deserialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_deserialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_input, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_deserialize_php) {

    //
    // Declare input argument
    //
    char *in_input = NULL;
    size_t in_input_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_input, in_input_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t input = vsc_data((const byte*)in_input, in_input_len);
    vscr_error_t error;
    vscr_error_reset(&error);

    //
    // Call main function
    //
    vscr_ratchet_session_t *ratchet_session_rs =vscr_ratchet_session_deserialize(input, &error);

    //
    // Handle error
    //
    vscr_status_t status = vscr_error_status(&error);
    VSCR_HANDLE_STATUS(status);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        zend_resource *ratchet_session_res = zend_register_resource(ratchet_session_rs, le_vscr_ratchet_session_t());
        RETVAL_RES(ratchet_session_res);
    }
}

//
// Wrap method: vscr_ratchet_session_use_rng
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_session_use_rng_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_rng, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_session_use_rng_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_rng = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_rng, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_session_t *ratchet_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_session_t_php_res_name(), le_vscr_ratchet_session_t());
    vscf_impl_t *rng = zend_fetch_resource_ex(in_rng, vscf_impl_t_php_res_name(), le_vscf_impl_t());

    //
    // Call main function
    //
    vscr_ratchet_session_use_rng(ratchet_session, rng);
}

//
// Wrap method: vscr_ratchet_group_participants_info_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_participants_info_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_participants_info_new_php) {
    vscr_ratchet_group_participants_info_t *ratchet_group_participants_info = vscr_ratchet_group_participants_info_new();
    zend_resource *ratchet_group_participants_info_res = zend_register_resource(ratchet_group_participants_info, le_vscr_ratchet_group_participants_info_t());
    RETVAL_RES(ratchet_group_participants_info_res);
}

//
// Wrap method: vscr_ratchet_group_participants_info_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_participants_info_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_participants_info_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscr_ratchet_group_participants_info_t *ratchet_group_participants_info = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_participants_info_t_php_res_name(), le_vscr_ratchet_group_participants_info_t());
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscr_ratchet_group_participants_info_add_participant
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_participants_info_add_participant_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_id, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, in_pub_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_participants_info_add_participant_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_id = NULL;
    size_t in_id_len = 0;
    char *in_pub_key = NULL;
    size_t in_pub_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_id, in_id_len, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_pub_key, in_pub_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_participants_info_t *ratchet_group_participants_info = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_participants_info_t_php_res_name(), le_vscr_ratchet_group_participants_info_t());
    vsc_data_t id = vsc_data((const byte*)in_id, in_id_len);
    vsc_data_t pub_key = vsc_data((const byte*)in_pub_key, in_pub_key_len);

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_group_participants_info_add_participant(ratchet_group_participants_info, id, pub_key);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_group_message_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_message_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_message_new_php) {
    vscr_ratchet_group_message_t *ratchet_group_message = vscr_ratchet_group_message_new();
    zend_resource *ratchet_group_message_res = zend_register_resource(ratchet_group_message, le_vscr_ratchet_group_message_t());
    RETVAL_RES(ratchet_group_message_res);
}

//
// Wrap method: vscr_ratchet_group_message_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_message_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_message_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscr_ratchet_group_message_t *ratchet_group_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscr_ratchet_group_message_get_type
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_message_get_type_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_message_get_type_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_message_t *ratchet_group_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());

    //
    // Call main function
    //
    int group_msg_type =vscr_ratchet_group_message_get_type(ratchet_group_message);

    //
    // Write returned result
    //
    RETVAL_LONG(group_msg_type);
}

//
// Wrap method: vscr_ratchet_group_message_get_session_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_message_get_session_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_message_get_session_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_message_t *ratchet_group_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscr_ratchet_group_message_get_session_id(ratchet_group_message);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscr_ratchet_group_message_get_counter
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_message_get_counter_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_message_get_counter_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_message_t *ratchet_group_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());

    //
    // Call main function
    //
    int res =vscr_ratchet_group_message_get_counter(ratchet_group_message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscr_ratchet_group_message_get_epoch
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_message_get_epoch_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_message_get_epoch_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_message_t *ratchet_group_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());

    //
    // Call main function
    //
    int res =vscr_ratchet_group_message_get_epoch(ratchet_group_message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscr_ratchet_group_message_serialize_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_message_serialize_len_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_message_serialize_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_message_t *ratchet_group_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());

    //
    // Call main function
    //
    size_t res =vscr_ratchet_group_message_serialize_len(ratchet_group_message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscr_ratchet_group_message_serialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_message_serialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_message_serialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_message_t *ratchet_group_message = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());

    //
    // Allocate output buffer for output 'output'
    //
    zend_string *out_output = zend_string_alloc(vscr_ratchet_group_message_serialize_len(ratchet_group_message), 0);
    vsc_buffer_t *output = vsc_buffer_new();
    vsc_buffer_use(output, (byte *)ZSTR_VAL(out_output), ZSTR_LEN(out_output));

    //
    // Call main function
    //
    vscr_ratchet_group_message_serialize(ratchet_group_message, output);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_output) = vsc_buffer_len(output);

    //
    // Write returned result
    //
    RETVAL_STR(out_output);
}

//
// Wrap method: vscr_ratchet_group_message_deserialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_message_deserialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_input, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_message_deserialize_php) {

    //
    // Declare input argument
    //
    char *in_input = NULL;
    size_t in_input_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_input, in_input_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t input = vsc_data((const byte*)in_input, in_input_len);
    vscr_error_t error;
    vscr_error_reset(&error);

    //
    // Call main function
    //
    vscr_ratchet_group_message_t *ratchet_group_message_rs =vscr_ratchet_group_message_deserialize(input, &error);

    //
    // Handle error
    //
    vscr_status_t status = vscr_error_status(&error);
    VSCR_HANDLE_STATUS(status);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        zend_resource *ratchet_group_message_res = zend_register_resource(ratchet_group_message_rs, le_vscr_ratchet_group_message_t());
        RETVAL_RES(ratchet_group_message_res);
    }
}

//
// Wrap method: vscr_ratchet_group_ticket_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_ticket_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_ticket_new_php) {
    vscr_ratchet_group_ticket_t *ratchet_group_ticket = vscr_ratchet_group_ticket_new();
    zend_resource *ratchet_group_ticket_res = zend_register_resource(ratchet_group_ticket, le_vscr_ratchet_group_ticket_t());
    RETVAL_RES(ratchet_group_ticket_res);
}

//
// Wrap method: vscr_ratchet_group_ticket_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_ticket_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_ticket_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscr_ratchet_group_ticket_t *ratchet_group_ticket = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_ticket_t_php_res_name(), le_vscr_ratchet_group_ticket_t());
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscr_ratchet_group_ticket_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_ticket_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_ticket_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_ticket_t *ratchet_group_ticket = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_ticket_t_php_res_name(), le_vscr_ratchet_group_ticket_t());

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_group_ticket_setup_defaults(ratchet_group_ticket);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_group_ticket_setup_ticket_as_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_ticket_setup_ticket_as_new_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_session_id, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_ticket_setup_ticket_as_new_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_session_id = NULL;
    size_t in_session_id_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_session_id, in_session_id_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_ticket_t *ratchet_group_ticket = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_ticket_t_php_res_name(), le_vscr_ratchet_group_ticket_t());
    vsc_data_t session_id = vsc_data((const byte*)in_session_id, in_session_id_len);

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_group_ticket_setup_ticket_as_new(ratchet_group_ticket, session_id);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_group_ticket_get_ticket_message
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_ticket_get_ticket_message_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_ticket_get_ticket_message_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_ticket_t *ratchet_group_ticket = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_ticket_t_php_res_name(), le_vscr_ratchet_group_ticket_t());

    //
    // Call main function
    //
    vscr_ratchet_group_message_t *ratchet_group_message =(vscr_ratchet_group_message_t *)vscr_ratchet_group_ticket_get_ticket_message(ratchet_group_ticket);
    ratchet_group_message = vscr_ratchet_group_message_shallow_copy(ratchet_group_message);

    //
    // Write returned result
    //
    zend_resource *ratchet_group_message_res = zend_register_resource(ratchet_group_message, le_vscr_ratchet_group_message_t());
    RETVAL_RES(ratchet_group_message_res);
}

//
// Wrap method: vscr_ratchet_group_ticket_use_rng
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_ticket_use_rng_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_rng, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_ticket_use_rng_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_rng = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_rng, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_ticket_t *ratchet_group_ticket = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_ticket_t_php_res_name(), le_vscr_ratchet_group_ticket_t());
    vscf_impl_t *rng = zend_fetch_resource_ex(in_rng, vscf_impl_t_php_res_name(), le_vscf_impl_t());

    //
    // Call main function
    //
    vscr_ratchet_group_ticket_use_rng(ratchet_group_ticket, rng);
}

//
// Wrap method: vscr_ratchet_group_participants_ids_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_participants_ids_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_participants_ids_new_php) {
    vscr_ratchet_group_participants_ids_t *ratchet_group_participants_ids = vscr_ratchet_group_participants_ids_new();
    zend_resource *ratchet_group_participants_ids_res = zend_register_resource(ratchet_group_participants_ids, le_vscr_ratchet_group_participants_ids_t());
    RETVAL_RES(ratchet_group_participants_ids_res);
}

//
// Wrap method: vscr_ratchet_group_participants_ids_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_participants_ids_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_participants_ids_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscr_ratchet_group_participants_ids_t *ratchet_group_participants_ids = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_participants_ids_t_php_res_name(), le_vscr_ratchet_group_participants_ids_t());
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscr_ratchet_group_participants_ids_add_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_participants_ids_add_id_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_id, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_participants_ids_add_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_id = NULL;
    size_t in_id_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_id, in_id_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_participants_ids_t *ratchet_group_participants_ids = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_participants_ids_t_php_res_name(), le_vscr_ratchet_group_participants_ids_t());
    vsc_data_t id = vsc_data((const byte*)in_id, in_id_len);

    //
    // Call main function
    //
    vscr_ratchet_group_participants_ids_add_id(ratchet_group_participants_ids, id);
}

//
// Wrap method: vscr_ratchet_group_session_new
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_session_new_php,
        0 /*return_reference*/,
        0 /*required_num_args*/,
        IS_RESOURCE /*type*/,
        0 /*allow_null*/)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_new_php) {
    vscr_ratchet_group_session_t *ratchet_group_session = vscr_ratchet_group_session_new();
    zend_resource *ratchet_group_session_res = zend_register_resource(ratchet_group_session, le_vscr_ratchet_group_session_t());
    RETVAL_RES(ratchet_group_session_res);
}

//
// Wrap method: vscr_ratchet_group_session_delete
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
        arginfo_vscr_ratchet_group_session_delete_php,
        0 /*return_reference*/,
        1 /*required_num_args*/,
        IS_VOID /*type*/,
        0 /*allow_null*/)

        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_delete_php) {
    //
    // Declare input arguments
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Fetch for type checking and then release
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    zend_list_close(Z_RES_P(in_ctx));
    RETURN_TRUE;
}

//
// Wrap method: vscr_ratchet_group_session_is_initialized
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_is_initialized_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_is_initialized_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());

    //
    // Call main function
    //
    zend_bool res =vscr_ratchet_group_session_is_initialized(ratchet_group_session);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscr_ratchet_group_session_is_private_key_set
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_is_private_key_set_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_is_private_key_set_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());

    //
    // Call main function
    //
    zend_bool res =vscr_ratchet_group_session_is_private_key_set(ratchet_group_session);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscr_ratchet_group_session_is_my_id_set
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_is_my_id_set_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    _IS_BOOL /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_is_my_id_set_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());

    //
    // Call main function
    //
    zend_bool res =vscr_ratchet_group_session_is_my_id_set(ratchet_group_session);

    //
    // Write returned result
    //
    RETVAL_BOOL(res);
}

//
// Wrap method: vscr_ratchet_group_session_get_current_epoch
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_get_current_epoch_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_get_current_epoch_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());

    //
    // Call main function
    //
    int res =vscr_ratchet_group_session_get_current_epoch(ratchet_group_session);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscr_ratchet_group_session_setup_defaults
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_setup_defaults_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_setup_defaults_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_group_session_setup_defaults(ratchet_group_session);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_group_session_set_private_key
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_set_private_key_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_my_private_key, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_set_private_key_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_my_private_key = NULL;
    size_t in_my_private_key_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_my_private_key, in_my_private_key_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    vsc_data_t my_private_key = vsc_data((const byte*)in_my_private_key, in_my_private_key_len);

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_group_session_set_private_key(ratchet_group_session, my_private_key);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_group_session_set_my_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_set_my_id_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_my_id, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_set_my_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_my_id = NULL;
    size_t in_my_id_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_my_id, in_my_id_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    vsc_data_t my_id = vsc_data((const byte*)in_my_id, in_my_id_len);

    //
    // Call main function
    //
    vscr_ratchet_group_session_set_my_id(ratchet_group_session, my_id);
}

//
// Wrap method: vscr_ratchet_group_session_get_my_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_get_my_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_get_my_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscr_ratchet_group_session_get_my_id(ratchet_group_session);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscr_ratchet_group_session_get_session_id
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_get_session_id_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_get_session_id_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());

    //
    // Call main function
    //
    vsc_data_t out_data_temp =vscr_ratchet_group_session_get_session_id(ratchet_group_session);
    zend_string *out_data = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);

    //
    // Write returned result
    //
    RETVAL_STR(out_data);
}

//
// Wrap method: vscr_ratchet_group_session_get_participants_count
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_get_participants_count_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_get_participants_count_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());

    //
    // Call main function
    //
    int res =vscr_ratchet_group_session_get_participants_count(ratchet_group_session);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscr_ratchet_group_session_setup_session_state
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_setup_session_state_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_participants, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_setup_session_state_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message = NULL;
    zval *in_participants = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_participants, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    vscr_ratchet_group_message_t *message = zend_fetch_resource_ex(in_message, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());
    vscr_ratchet_group_participants_info_t *participants = zend_fetch_resource_ex(in_participants, vscr_ratchet_group_participants_info_t_php_res_name(), le_vscr_ratchet_group_participants_info_t());

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_group_session_setup_session_state(ratchet_group_session, message, participants);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_group_session_update_session_state
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_update_session_state_php,
    0 /*return_reference*/,
    4 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_add_participants, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_remove_participants, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_update_session_state_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message = NULL;
    zval *in_add_participants = NULL;
    zval *in_remove_participants = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 4, 4)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_add_participants, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_RESOURCE_EX(in_remove_participants, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    vscr_ratchet_group_message_t *message = zend_fetch_resource_ex(in_message, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());
    vscr_ratchet_group_participants_info_t *add_participants = zend_fetch_resource_ex(in_add_participants, vscr_ratchet_group_participants_info_t_php_res_name(), le_vscr_ratchet_group_participants_info_t());
    vscr_ratchet_group_participants_ids_t *remove_participants = zend_fetch_resource_ex(in_remove_participants, vscr_ratchet_group_participants_ids_t_php_res_name(), le_vscr_ratchet_group_participants_ids_t());

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_group_session_update_session_state(ratchet_group_session, message, add_participants, remove_participants);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);
}

//
// Wrap method: vscr_ratchet_group_session_encrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_encrypt_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_plain_text, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_encrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    char *in_plain_text = NULL;
    size_t in_plain_text_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_STRING_EX(in_plain_text, in_plain_text_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    vsc_data_t plain_text = vsc_data((const byte*)in_plain_text, in_plain_text_len);
    vscr_error_t error;
    vscr_error_reset(&error);

    //
    // Call main function
    //
    vscr_ratchet_group_message_t *ratchet_group_message =vscr_ratchet_group_session_encrypt(ratchet_group_session, plain_text, &error);

    //
    // Handle error
    //
    vscr_status_t status = vscr_error_status(&error);
    VSCR_HANDLE_STATUS(status);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        zend_resource *ratchet_group_message_res = zend_register_resource(ratchet_group_message, le_vscr_ratchet_group_message_t());
        RETVAL_RES(ratchet_group_message_res);
    }
}

//
// Wrap method: vscr_ratchet_group_session_decrypt_len
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_decrypt_len_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_LONG /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_decrypt_len_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    vscr_ratchet_group_message_t *message = zend_fetch_resource_ex(in_message, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());

    //
    // Call main function
    //
    size_t res =vscr_ratchet_group_session_decrypt_len(ratchet_group_session, message);

    //
    // Write returned result
    //
    RETVAL_LONG(res);
}

//
// Wrap method: vscr_ratchet_group_session_decrypt
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_decrypt_php,
    0 /*return_reference*/,
    3 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_message, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_sender_id, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_decrypt_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_message = NULL;
    char *in_sender_id = NULL;
    size_t in_sender_id_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 3)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_message, 1 /*check_null*/, 0 /*separate*/)
        Z_PARAM_STRING_EX(in_sender_id, in_sender_id_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    vscr_ratchet_group_message_t *message = zend_fetch_resource_ex(in_message, vscr_ratchet_group_message_t_php_res_name(), le_vscr_ratchet_group_message_t());
    vsc_data_t sender_id = vsc_data((const byte*)in_sender_id, in_sender_id_len);

    //
    // Allocate output buffer for output 'plain_text'
    //
    zend_string *out_plain_text = zend_string_alloc(vscr_ratchet_group_session_decrypt_len(ratchet_group_session, message), 0);
    vsc_buffer_t *plain_text = vsc_buffer_new();
    vsc_buffer_use(plain_text, (byte *)ZSTR_VAL(out_plain_text), ZSTR_LEN(out_plain_text));

    //
    // Call main function
    //
    vscr_status_t status =vscr_ratchet_group_session_decrypt(ratchet_group_session, message, sender_id, plain_text);

    //
    // Handle error
    //
    VSCR_HANDLE_STATUS(status);

    //
    // Correct string length to the actual
    //
    ZSTR_LEN(out_plain_text) = vsc_buffer_len(plain_text);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        RETVAL_STR(out_plain_text);
        vsc_buffer_destroy(&plain_text);
    }
    else {
        zend_string_free(out_plain_text);
    }
}

//
// Wrap method: vscr_ratchet_group_session_serialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_serialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_STRING /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_serialize_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());

    //
    // Call main function
    //
    vsc_buffer_t *out_buffer_temp =vscr_ratchet_group_session_serialize(ratchet_group_session);
    vsc_data_t out_data_temp = vsc_buffer_data(out_buffer_temp);
    zend_string *out_buffer = zend_string_init(out_data_temp.bytes, out_data_temp.len, 0);
    vsc_buffer_destroy(&out_buffer_temp);

    //
    // Write returned result
    //
    RETVAL_STR(out_buffer);
}

//
// Wrap method: vscr_ratchet_group_session_deserialize
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_deserialize_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_input, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_deserialize_php) {

    //
    // Declare input argument
    //
    char *in_input = NULL;
    size_t in_input_len = 0;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_STRING_EX(in_input, in_input_len, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vsc_data_t input = vsc_data((const byte*)in_input, in_input_len);
    vscr_error_t error;
    vscr_error_reset(&error);

    //
    // Call main function
    //
    vscr_ratchet_group_session_t *ratchet_group_session_rs =vscr_ratchet_group_session_deserialize(input, &error);

    //
    // Handle error
    //
    vscr_status_t status = vscr_error_status(&error);
    VSCR_HANDLE_STATUS(status);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        zend_resource *ratchet_group_session_res = zend_register_resource(ratchet_group_session_rs, le_vscr_ratchet_group_session_t());
        RETVAL_RES(ratchet_group_session_res);
    }
}

//
// Wrap method: vscr_ratchet_group_session_create_group_ticket
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_create_group_ticket_php,
    0 /*return_reference*/,
    1 /*required_num_args*/,
    IS_RESOURCE /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_create_group_ticket_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    vscr_error_t error;
    vscr_error_reset(&error);

    //
    // Call main function
    //
    vscr_ratchet_group_ticket_t *ratchet_group_ticket =vscr_ratchet_group_session_create_group_ticket(ratchet_group_session, &error);

    //
    // Handle error
    //
    vscr_status_t status = vscr_error_status(&error);
    VSCR_HANDLE_STATUS(status);

    //
    // Write returned result
    //
    if (status == vscr_status_SUCCESS) {
        zend_resource *ratchet_group_ticket_res = zend_register_resource(ratchet_group_ticket, le_vscr_ratchet_group_ticket_t());
        RETVAL_RES(ratchet_group_ticket_res);
    }
}

//
// Wrap method: vscr_ratchet_group_session_use_rng
//
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(
    arginfo_vscr_ratchet_group_session_use_rng_php,
    0 /*return_reference*/,
    2 /*required_num_args*/,
    IS_VOID /*type*/,
    0 /*allow_null*/)


    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, in_rng, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(vscr_ratchet_group_session_use_rng_php) {

    //
    // Declare input argument
    //
    zval *in_ctx = NULL;
    zval *in_rng = NULL;

    //
    // Parse arguments
    //
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)
        Z_PARAM_RESOURCE_EX(in_rng, 1 /*check_null*/, 0 /*separate*/)
    ZEND_PARSE_PARAMETERS_END();

    //
    // Proxy call
    //
    vscr_ratchet_group_session_t *ratchet_group_session = zend_fetch_resource_ex(in_ctx, vscr_ratchet_group_session_t_php_res_name(), le_vscr_ratchet_group_session_t());
    vscf_impl_t *rng = zend_fetch_resource_ex(in_rng, vscf_impl_t_php_res_name(), le_vscf_impl_t());

    //
    // Call main function
    //
    vscr_ratchet_group_session_use_rng(ratchet_group_session, rng);
}

//
// Define all function entries
//
static zend_function_entry vscr_ratchet_php_functions[] = {
    PHP_FE(vscr_ratchet_key_id_new_php, arginfo_vscr_ratchet_key_id_new_php)
    PHP_FE(vscr_ratchet_key_id_delete_php, arginfo_vscr_ratchet_key_id_delete_php)
    PHP_FE(vscr_ratchet_key_id_compute_public_key_id_php, arginfo_vscr_ratchet_key_id_compute_public_key_id_php)
    PHP_FE(vscr_ratchet_message_new_php, arginfo_vscr_ratchet_message_new_php)
    PHP_FE(vscr_ratchet_message_delete_php, arginfo_vscr_ratchet_message_delete_php)
    PHP_FE(vscr_ratchet_message_get_type_php, arginfo_vscr_ratchet_message_get_type_php)
    PHP_FE(vscr_ratchet_message_get_counter_php, arginfo_vscr_ratchet_message_get_counter_php)
    PHP_FE(vscr_ratchet_message_get_long_term_public_key_php, arginfo_vscr_ratchet_message_get_long_term_public_key_php)
    PHP_FE(vscr_ratchet_message_get_one_time_public_key_php, arginfo_vscr_ratchet_message_get_one_time_public_key_php)
    PHP_FE(vscr_ratchet_message_serialize_len_php, arginfo_vscr_ratchet_message_serialize_len_php)
    PHP_FE(vscr_ratchet_message_serialize_php, arginfo_vscr_ratchet_message_serialize_php)
    PHP_FE(vscr_ratchet_message_deserialize_php, arginfo_vscr_ratchet_message_deserialize_php)
    PHP_FE(vscr_ratchet_session_new_php, arginfo_vscr_ratchet_session_new_php)
    PHP_FE(vscr_ratchet_session_delete_php, arginfo_vscr_ratchet_session_delete_php)
    PHP_FE(vscr_ratchet_session_setup_defaults_php, arginfo_vscr_ratchet_session_setup_defaults_php)
    PHP_FE(vscr_ratchet_session_initiate_php, arginfo_vscr_ratchet_session_initiate_php)
    PHP_FE(vscr_ratchet_session_respond_php, arginfo_vscr_ratchet_session_respond_php)
    PHP_FE(vscr_ratchet_session_is_initiator_php, arginfo_vscr_ratchet_session_is_initiator_php)
    PHP_FE(vscr_ratchet_session_received_first_response_php, arginfo_vscr_ratchet_session_received_first_response_php)
    PHP_FE(vscr_ratchet_session_receiver_has_one_time_public_key_php, arginfo_vscr_ratchet_session_receiver_has_one_time_public_key_php)
    PHP_FE(vscr_ratchet_session_encrypt_php, arginfo_vscr_ratchet_session_encrypt_php)
    PHP_FE(vscr_ratchet_session_decrypt_len_php, arginfo_vscr_ratchet_session_decrypt_len_php)
    PHP_FE(vscr_ratchet_session_decrypt_php, arginfo_vscr_ratchet_session_decrypt_php)
    PHP_FE(vscr_ratchet_session_serialize_php, arginfo_vscr_ratchet_session_serialize_php)
    PHP_FE(vscr_ratchet_session_deserialize_php, arginfo_vscr_ratchet_session_deserialize_php)
    PHP_FE(vscr_ratchet_session_use_rng_php, arginfo_vscr_ratchet_session_use_rng_php)
    PHP_FE(vscr_ratchet_group_participants_info_new_php, arginfo_vscr_ratchet_group_participants_info_new_php)
    PHP_FE(vscr_ratchet_group_participants_info_delete_php, arginfo_vscr_ratchet_group_participants_info_delete_php)
    PHP_FE(vscr_ratchet_group_participants_info_add_participant_php, arginfo_vscr_ratchet_group_participants_info_add_participant_php)
    PHP_FE(vscr_ratchet_group_message_new_php, arginfo_vscr_ratchet_group_message_new_php)
    PHP_FE(vscr_ratchet_group_message_delete_php, arginfo_vscr_ratchet_group_message_delete_php)
    PHP_FE(vscr_ratchet_group_message_get_type_php, arginfo_vscr_ratchet_group_message_get_type_php)
    PHP_FE(vscr_ratchet_group_message_get_session_id_php, arginfo_vscr_ratchet_group_message_get_session_id_php)
    PHP_FE(vscr_ratchet_group_message_get_counter_php, arginfo_vscr_ratchet_group_message_get_counter_php)
    PHP_FE(vscr_ratchet_group_message_get_epoch_php, arginfo_vscr_ratchet_group_message_get_epoch_php)
    PHP_FE(vscr_ratchet_group_message_serialize_len_php, arginfo_vscr_ratchet_group_message_serialize_len_php)
    PHP_FE(vscr_ratchet_group_message_serialize_php, arginfo_vscr_ratchet_group_message_serialize_php)
    PHP_FE(vscr_ratchet_group_message_deserialize_php, arginfo_vscr_ratchet_group_message_deserialize_php)
    PHP_FE(vscr_ratchet_group_ticket_new_php, arginfo_vscr_ratchet_group_ticket_new_php)
    PHP_FE(vscr_ratchet_group_ticket_delete_php, arginfo_vscr_ratchet_group_ticket_delete_php)
    PHP_FE(vscr_ratchet_group_ticket_setup_defaults_php, arginfo_vscr_ratchet_group_ticket_setup_defaults_php)
    PHP_FE(vscr_ratchet_group_ticket_setup_ticket_as_new_php, arginfo_vscr_ratchet_group_ticket_setup_ticket_as_new_php)
    PHP_FE(vscr_ratchet_group_ticket_get_ticket_message_php, arginfo_vscr_ratchet_group_ticket_get_ticket_message_php)
    PHP_FE(vscr_ratchet_group_ticket_use_rng_php, arginfo_vscr_ratchet_group_ticket_use_rng_php)
    PHP_FE(vscr_ratchet_group_participants_ids_new_php, arginfo_vscr_ratchet_group_participants_ids_new_php)
    PHP_FE(vscr_ratchet_group_participants_ids_delete_php, arginfo_vscr_ratchet_group_participants_ids_delete_php)
    PHP_FE(vscr_ratchet_group_participants_ids_add_id_php, arginfo_vscr_ratchet_group_participants_ids_add_id_php)
    PHP_FE(vscr_ratchet_group_session_new_php, arginfo_vscr_ratchet_group_session_new_php)
    PHP_FE(vscr_ratchet_group_session_delete_php, arginfo_vscr_ratchet_group_session_delete_php)
    PHP_FE(vscr_ratchet_group_session_is_initialized_php, arginfo_vscr_ratchet_group_session_is_initialized_php)
    PHP_FE(vscr_ratchet_group_session_is_private_key_set_php, arginfo_vscr_ratchet_group_session_is_private_key_set_php)
    PHP_FE(vscr_ratchet_group_session_is_my_id_set_php, arginfo_vscr_ratchet_group_session_is_my_id_set_php)
    PHP_FE(vscr_ratchet_group_session_get_current_epoch_php, arginfo_vscr_ratchet_group_session_get_current_epoch_php)
    PHP_FE(vscr_ratchet_group_session_setup_defaults_php, arginfo_vscr_ratchet_group_session_setup_defaults_php)
    PHP_FE(vscr_ratchet_group_session_set_private_key_php, arginfo_vscr_ratchet_group_session_set_private_key_php)
    PHP_FE(vscr_ratchet_group_session_set_my_id_php, arginfo_vscr_ratchet_group_session_set_my_id_php)
    PHP_FE(vscr_ratchet_group_session_get_my_id_php, arginfo_vscr_ratchet_group_session_get_my_id_php)
    PHP_FE(vscr_ratchet_group_session_get_session_id_php, arginfo_vscr_ratchet_group_session_get_session_id_php)
    PHP_FE(vscr_ratchet_group_session_get_participants_count_php, arginfo_vscr_ratchet_group_session_get_participants_count_php)
    PHP_FE(vscr_ratchet_group_session_setup_session_state_php, arginfo_vscr_ratchet_group_session_setup_session_state_php)
    PHP_FE(vscr_ratchet_group_session_update_session_state_php, arginfo_vscr_ratchet_group_session_update_session_state_php)
    PHP_FE(vscr_ratchet_group_session_encrypt_php, arginfo_vscr_ratchet_group_session_encrypt_php)
    PHP_FE(vscr_ratchet_group_session_decrypt_len_php, arginfo_vscr_ratchet_group_session_decrypt_len_php)
    PHP_FE(vscr_ratchet_group_session_decrypt_php, arginfo_vscr_ratchet_group_session_decrypt_php)
    PHP_FE(vscr_ratchet_group_session_serialize_php, arginfo_vscr_ratchet_group_session_serialize_php)
    PHP_FE(vscr_ratchet_group_session_deserialize_php, arginfo_vscr_ratchet_group_session_deserialize_php)
    PHP_FE(vscr_ratchet_group_session_create_group_ticket_php, arginfo_vscr_ratchet_group_session_create_group_ticket_php)
    PHP_FE(vscr_ratchet_group_session_use_rng_php, arginfo_vscr_ratchet_group_session_use_rng_php)
    PHP_FE_END
};

//
// Extension module definition
//
zend_module_entry vscr_ratchet_php_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    VSCR_RATCHET_PHP_EXTNAME,
    vscr_ratchet_php_functions,
    PHP_MINIT(vscr_ratchet_php),
    PHP_MSHUTDOWN(vscr_ratchet_php),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    VSCR_RATCHET_PHP_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(vscr_ratchet_php)

//
// Extension init functions definition
//
static void vscr_ratchet_key_id_dtor_php(zend_resource *rsrc) {
    vscr_ratchet_key_id_delete((vscr_ratchet_key_id_t *)rsrc->ptr);
}
static void vscr_ratchet_message_dtor_php(zend_resource *rsrc) {
    vscr_ratchet_message_delete((vscr_ratchet_message_t *)rsrc->ptr);
}
static void vscr_ratchet_session_dtor_php(zend_resource *rsrc) {
    vscr_ratchet_session_delete((vscr_ratchet_session_t *)rsrc->ptr);
}
static void vscr_ratchet_group_participants_info_dtor_php(zend_resource *rsrc) {
    vscr_ratchet_group_participants_info_delete((vscr_ratchet_group_participants_info_t *)rsrc->ptr);
}
static void vscr_ratchet_group_message_dtor_php(zend_resource *rsrc) {
    vscr_ratchet_group_message_delete((vscr_ratchet_group_message_t *)rsrc->ptr);
}
static void vscr_ratchet_group_ticket_dtor_php(zend_resource *rsrc) {
    vscr_ratchet_group_ticket_delete((vscr_ratchet_group_ticket_t *)rsrc->ptr);
}
static void vscr_ratchet_group_participants_ids_dtor_php(zend_resource *rsrc) {
    vscr_ratchet_group_participants_ids_delete((vscr_ratchet_group_participants_ids_t *)rsrc->ptr);
}
static void vscr_ratchet_group_session_dtor_php(zend_resource *rsrc) {
    vscr_ratchet_group_session_delete((vscr_ratchet_group_session_t *)rsrc->ptr);
}
PHP_MINIT_FUNCTION(vscr_ratchet_php) {
    LE_VSCR_RATCHET_KEY_ID_T = zend_register_list_destructors_ex(vscr_ratchet_key_id_dtor_php, NULL, vscr_ratchet_key_id_t_php_res_name(), module_number);
    LE_VSCR_RATCHET_MESSAGE_T = zend_register_list_destructors_ex(vscr_ratchet_message_dtor_php, NULL, vscr_ratchet_message_t_php_res_name(), module_number);
    LE_VSCR_RATCHET_SESSION_T = zend_register_list_destructors_ex(vscr_ratchet_session_dtor_php, NULL, vscr_ratchet_session_t_php_res_name(), module_number);
    LE_VSCR_RATCHET_GROUP_PARTICIPANTS_INFO_T = zend_register_list_destructors_ex(vscr_ratchet_group_participants_info_dtor_php, NULL, vscr_ratchet_group_participants_info_t_php_res_name(), module_number);
    LE_VSCR_RATCHET_GROUP_MESSAGE_T = zend_register_list_destructors_ex(vscr_ratchet_group_message_dtor_php, NULL, vscr_ratchet_group_message_t_php_res_name(), module_number);
    LE_VSCR_RATCHET_GROUP_TICKET_T = zend_register_list_destructors_ex(vscr_ratchet_group_ticket_dtor_php, NULL, vscr_ratchet_group_ticket_t_php_res_name(), module_number);
    LE_VSCR_RATCHET_GROUP_PARTICIPANTS_IDS_T = zend_register_list_destructors_ex(vscr_ratchet_group_participants_ids_dtor_php, NULL, vscr_ratchet_group_participants_ids_t_php_res_name(), module_number);
    LE_VSCR_RATCHET_GROUP_SESSION_T = zend_register_list_destructors_ex(vscr_ratchet_group_session_dtor_php, NULL, vscr_ratchet_group_session_t_php_res_name(), module_number);
    return SUCCESS;
}
PHP_MSHUTDOWN_FUNCTION(vscr_ratchet_php) {
    return SUCCESS;
}
