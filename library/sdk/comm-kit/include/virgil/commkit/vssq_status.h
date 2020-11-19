//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Defines the library status codes.
// --------------------------------------------------------------------------

#ifndef VSSQ_STATUS_H_INCLUDED
#define VSSQ_STATUS_H_INCLUDED

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Defines the library status codes.
//
enum vssq_status_t {
    //
    //  No errors was occurred.
    //
    vssq_status_SUCCESS = 0,
    //
    //  Met internal inconsistency.
    //
    vssq_status_INTERNAL_ERROR = -1,
    //
    //  Failed to initialze RNG.
    //
    vssq_status_RNG_FAILED = -101,
    //
    //  Generic error for any find operation.
    //
    vssq_status_NOT_FOUND = -102,
    //
    //  Failed to parse Ejabberd JWT.
    //
    vssq_status_PARSE_EJABBERD_JWT_FAILED = -201,
    //
    //  Failed to generate identity.
    //
    vssq_status_GENERATE_IDENTITY_FAILED = -301,
    //
    //  Failed to generate private key.
    //
    vssq_status_GENERATE_PRIVATE_KEY_FAILED = -302,
    //
    //  Failed to import private key.
    //
    vssq_status_IMPORT_PRIVATE_KEY_FAILED = -303,
    //
    //  Failed to export private key.
    //
    vssq_status_EXPORT_PRIVATE_KEY_FAILED = -304,
    //
    //  Failed to calculate key id.
    //
    vssq_status_CALCULATE_KEY_ID_FAILED = -305,
    //
    //  Failed to create card manager.
    //
    vssq_status_CREATE_CARD_MANAGER_FAILED = -306,
    //
    //  Failed to generate card.
    //
    vssq_status_GENERATE_CARD_FAILED = -306,
    //
    //  Failed to generate HTTP authentication header.
    //
    vssq_status_GENERATE_AUTH_HEADER_FAILED = -308,
    //
    //  Failed to register card because send operation failed.
    //
    vssq_status_REGISTER_CARD_FAILED_REQUEST_FAILED = -401,
    //
    //  Failed to register card because of invalid response.
    //
    vssq_status_REGISTER_CARD_FAILED_INVALID_RESPONSE = -402,
    //
    //  Failed to register card because response with error was returned.
    //
    vssq_status_REGISTER_CARD_FAILED_RESPONSE_WITH_ERROR = -403,
    //
    //  Failed to register card because parsing raw card failed.
    //
    vssq_status_REGISTER_CARD_FAILED_PARSE_FAILED = -404,
    //
    //  Failed to register card because import raw card failed.
    //
    vssq_status_REGISTER_CARD_FAILED_IMPORT_FAILED = -405,
    //
    //  Failed to generate brain key because of crypto fail.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_CRYPTO_FAILED = -501,
    //
    //  Failed to generate brain key because of RNG fail.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_RNG_FAILED = -502,
    //
    //  Failed to generate brain key because of deblind fail.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_BLIND_FAILED = -503,
    //
    //  Failed to generate brain key because of blind fail.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_DEBLIND_FAILED = -504,
    //
    //  Failed to generate brain key because requesting seed from the service failed.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_SEED_REQUEST_FAILED = -505,
    //
    //  Failed to generate brain key because seed response was returned with error.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_SEED_RESPONSE_WITH_ERROR = -506,
    //
    //  Failed to generate brain key because parsing seed response failed.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_SEED_PARSE_FAILED = -507,
    //
    //  Failed to process Keyknox entry because send operation failed.
    //
    vssq_status_KEYKNOX_FAILED_REQUEST_FAILED = -601,
    //
    //  Failed to process Keyknox entry because response with error was returned.
    //
    vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR = -602,
    //
    //  Failed to process Keyknox entry because response parsing failed.
    //
    vssq_status_KEYKNOX_FAILED_PARSE_RESPONSE_FAILED = -603,
    //
    //  Failed to pack Keyknox entry because export private key failed.
    //
    vssq_status_KEYKNOX_PACK_ENTRY_FAILED_EXPORT_PRIVATE_KEY_FAILED = -604,
    //
    //  Failed to pack Keyknox entry because encrypt operation failed.
    //
    vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED = -605,
    //
    //  Failed to unpack Keyknox entry because decrypt operation failed.
    //
    vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED = -606,
    //
    //  Failed to unpack Keyknox entry because verifying signature failed.
    //
    vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED = -607,
    //
    //  Failed to unpack Keyknox entry because parse operation failed.
    //
    vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_PARSE_FAILED = -608,
    //
    //  Failed to unpack Keyknox entry because import private key failed.
    //
    vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_IMPORT_PRIVATE_KEY_FAILED = -609,
    //
    //  Failed to refresh JWT because send operation failed.
    //
    vssq_status_REFRESH_TOKEN_FAILED_REQUEST_FAILED = -701,
    //
    //  Failed to refresh JWT because response with error was returned.
    //
    vssq_status_REFRESH_TOKEN_FAILED_RESPONSE_WITH_ERROR = -702,
    //
    //  Failed to refresh JWT because response parsing failed.
    //
    vssq_status_REFRESH_TOKEN_FAILED_PARSE_RESPONSE_FAILED = -703,
    //
    //  Failed to refresh JWT because JWT parsing failed.
    //
    vssq_status_REFRESH_TOKEN_FAILED_PARSE_FAILED = -704,
    //
    //  Failed to reset password because send operation failed.
    //
    vssq_status_RESET_PASSWORD_FAILED_REQUEST_FAILED = -801,
    //
    //  Failed to reset password because response with error was returned.
    //
    vssq_status_RESET_PASSWORD_FAILED_RESPONSE_WITH_ERROR = -802,
    //
    //  Failed to search card because a card manager initialization failed.
    //
    vssq_status_SEARCH_CARD_FAILED_INIT_FAILED = -900,
    //
    //  Failed to search card because send operation failed.
    //
    vssq_status_SEARCH_CARD_FAILED_REQUEST_FAILED = -901,
    //
    //  Failed to search card because response with error was returned.
    //
    vssq_status_SEARCH_CARD_FAILED_RESPONSE_WITH_ERROR = -902,
    //
    //  Failed to search card because required card was not found.
    //
    vssq_status_SEARCH_CARD_FAILED_REQUIRED_NOT_FOUND = -903,
    //
    //  Failed to search card because found more then one active card.
    //
    vssq_status_SEARCH_CARD_FAILED_MULTIPLE_FOUND = -904,
    //
    //  Failed to search card because parsing raw card failed.
    //
    vssq_status_SEARCH_CARD_FAILED_PARSE_FAILED = -905,
    //
    //  Failed to search card because import raw card failed.
    //
    vssq_status_SEARCH_CARD_FAILED_IMPORT_FAILED = -906,
    //
    //  Failed to search card because required card is outdated.
    //
    vssq_status_SEARCH_CARD_FAILED_REQUIRED_IS_OUTDATED = -907,
    //
    //  Failed to export creentials because initializing crypto module failed.
    //
    vssq_status_EXPORT_CREDS_FAILED_INIT_CRYPTO_FAILED = -1000,
    //
    //  Failed to export creentials because exporting private key failed.
    //
    vssq_status_EXPORT_CREDS_FAILED_EXPORT_PRIVATE_KEY_FAILED = -1001,
    //
    //  Failed to import creentials because initializing crypto module failed.
    //
    vssq_status_IMPORT_CREDS_FAILED_INIT_CRYPTO_FAILED = -1002,
    //
    //  Failed to import creentials because parsing json failed.
    //
    vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED = -1003,
    //
    //  Failed to import creentials because importing private key failed.
    //
    vssq_status_IMPORT_CREDS_FAILED_IMPORT_PRIVATE_KEY_FAILED = -1004,
    //
    //  Username validation failed because it's length exceeds the allowed maximum (20).
    //
    vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_TOO_LONG = -1100,
    //
    //  Username validation failed because it contains invalid characters.
    //
    vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS = -1101,
    //
    //  The current user can not modify the group - permission violation.
    //
    vssq_status_MODIFY_GROUP_FAILED_PERMISSION_VIOLATION = -1200,
    //
    //  The current user can not access the group - permission violation.
    //
    vssq_status_ACCESS_GROUP_FAILED_PERMISSION_VIOLATION = -1201,
    //
    //  Failed to create group because underlying crypo module failed.
    //
    vssq_status_CREATE_GROUP_FAILED_CRYPTO_FAILED = -1202,
    //
    //  Failed to import group epoch because parsing json failed.
    //
    vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED = -1203,
    //
    //  Failed to process group message because session id doesnt match.
    //
    vssq_status_PROCESS_GROUP_MESSAGE_FAILED_SESSION_ID_DOESNT_MATCH = -1204,
    //
    //  Failed to process group message because epoch not found.
    //
    vssq_status_PROCESS_GROUP_MESSAGE_FAILED_EPOCH_NOT_FOUND = -1205,
    //
    //  Failed to process group message because wrong key type.
    //
    vssq_status_PROCESS_GROUP_MESSAGE_FAILED_WRONG_KEY_TYPE = -1206,
    //
    //  Failed to process group message because of invalid signature.
    //
    vssq_status_PROCESS_GROUP_MESSAGE_FAILED_INVALID_SIGNATURE = -1207,
    //
    //  Failed to process group message because ed25519 failed.
    //
    vssq_status_PROCESS_GROUP_MESSAGE_FAILED_ED25519_FAILED = -1208,
    //
    //  Failed to process group message because of duplicated epoch.
    //
    vssq_status_PROCESS_GROUP_MESSAGE_FAILED_DUPLICATE_EPOCH = -1209,
    //
    //  Failed to process group message because plain text too long.
    //
    vssq_status_PROCESS_GROUP_MESSAGE_FAILED_PLAIN_TEXT_TOO_LONG = -1210,
    //
    //  Failed to process group message because underlying crypo module failed.
    //
    vssq_status_PROCESS_GROUP_MESSAGE_FAILED_CRYPTO_FAILED = -1299
};
#ifndef VSSQ_STATUS_T_DEFINED
#define VSSQ_STATUS_T_DEFINED
    typedef enum vssq_status_t vssq_status_t;
#endif // VSSQ_STATUS_T_DEFINED


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_STATUS_H_INCLUDED
//  @end
