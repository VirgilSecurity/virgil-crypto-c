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
    //  Failed to initialize RNG.
    //
    vssq_status_RNG_FAILED = -101,
    //
    //  Generic error for any find operation.
    //
    vssq_status_NOT_FOUND = -102,
    //
    //  Failed to send HTTP request.
    //
    vssq_status_HTTP_SEND_FAILED = -103,
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
    vssq_status_GENERATE_CARD_FAILED = -307,
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
    //  Failed to generate brain key because of blind fail.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_BLIND_FAILED = -503,
    //
    //  Failed to generate brain key because of deblind fail.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_DEBLIND_FAILED = -504,
    //
    //  Failed to generate brain key because requesting hardened point from the service failed.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_HARDENED_POINT_REQUEST_FAILED = -505,
    //
    //  Failed to generate brain key because hardened point response was returned with error.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_HARDENED_POINT_RESPONSE_WITH_ERROR = -506,
    //
    //  Failed to generate brain key because parsing hardened point response failed.
    //
    vssq_status_GENERATE_BRAINKEY_FAILED_HARDENED_POINT_PARSE_FAILED = -507,
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
    vssq_status_REFRESH_JWT_FAILED_REQUEST_FAILED = -701,
    //
    //  Failed to refresh JWT because response with error was returned.
    //
    vssq_status_REFRESH_JWT_FAILED_RESPONSE_WITH_ERROR = -702,
    //
    //  Failed to refresh JWT because response parsing failed.
    //
    vssq_status_REFRESH_JWT_FAILED_PARSE_RESPONSE_FAILED = -703,
    //
    //  Failed to refresh JWT because JWT parsing failed.
    //
    vssq_status_REFRESH_JWT_FAILED_PARSE_FAILED = -704,
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
    //  Failed to export credentials because initializing crypto module failed.
    //
    vssq_status_EXPORT_CREDS_FAILED_INIT_CRYPTO_FAILED = -1000,
    //
    //  Failed to export credentials because exporting private key failed.
    //
    vssq_status_EXPORT_CREDS_FAILED_EXPORT_PRIVATE_KEY_FAILED = -1001,
    //
    //  Failed to import credentials because initializing crypto module failed.
    //
    vssq_status_IMPORT_CREDS_FAILED_INIT_CRYPTO_FAILED = -1002,
    //
    //  Failed to import credentials because parsing JSON failed.
    //
    vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED = -1003,
    //
    //  Failed to import credentials because importing private key failed.
    //
    vssq_status_IMPORT_CREDS_FAILED_IMPORT_PRIVATE_KEY_FAILED = -1004,
    //
    //  Failed to import user because parsing JSON failed.
    //
    vssq_status_IMPORT_USER_FAILED_PARSE_FAILED = -1010,
    //
    //  Failed to import user because met unexpected version within JSON.
    //
    vssq_status_IMPORT_USER_FAILED_VERSION_MISMATCH = -1011,
    //
    //  Failed to import user because failed to import a raw card.
    //
    vssq_status_IMPORT_USER_FAILED_IMPORT_CARD_FAILED = -1012,
    //
    //  Username validation failed because it's length exceeds the allowed maximum (20).
    //
    vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_TOO_LONG = -1100,
    //
    //  Username validation failed because it contains invalid characters.
    //
    vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS = -1101,
    //
    //  Phone number validation failed because it does not conform to E.164 standard.
    //
    vssq_status_CONTACT_VALIDATION_FAILED_PHONE_NUMBER_BAD_FORMAT = -1102,
    //
    //  Email validation failed because it has invalid format.
    //
    vssq_status_CONTACT_VALIDATION_FAILED_EMAIL_BAD_FORMAT = -1103,
    //
    //  The current user can not modify the group - permission violation.
    //
    vssq_status_MODIFY_GROUP_FAILED_PERMISSION_VIOLATION = -1200,
    //
    //  The current user can not access the group - permission violation.
    //
    vssq_status_ACCESS_GROUP_FAILED_PERMISSION_VIOLATION = -1201,
    //
    //  Failed to create group because underlying crypto module failed.
    //
    vssq_status_CREATE_GROUP_FAILED_CRYPTO_FAILED = -1202,
    //
    //  Failed to import group epoch because parsing JSON failed.
    //
    vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED = -1203,
    //
    //  Failed to process group message because session id doesn't match.
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
    //  Failed to import group because mismatch version within JSON.
    //
    vssq_status_IMPORT_GROUP_FAILED_VERSION_MISMATCH = -1211,
    //
    //  Failed to import group because parsing JSON failed.
    //
    vssq_status_IMPORT_GROUP_FAILED_PARSE_FAILED = -1212,
    //
    //  Failed to process group message because underlying crypto module failed.
    //
    vssq_status_PROCESS_GROUP_MESSAGE_FAILED_CRYPTO_FAILED = -1299,
    //
    //  Failed to decrypt regular message because of invalid encrypted message.
    //
    vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_INVALID_ENCRYPTED_MESSAGE = -1301,
    //
    //  Failed to decrypt regular message because a private key can not decrypt.
    //
    vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_WRONG_PRIVATE_KEY = -1302,
    //
    //  Failed to decrypt regular message because recipient was not found.
    //
    vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_RECIPIENT_NOT_FOUND = -1303,
    //
    //  Failed to decrypt regular message because failed to verify signature.
    //
    vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_VERIFY_SIGNATURE = -1304,
    //
    //  Failed to decrypt regular message because underlying crypto module failed.
    //
    vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED = -1398,
    //
    //  Failed to encrypt regular message because underlying crypto module failed.
    //
    vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED = -1399,
    //
    //  Failed to perform contacts operation because send operation failed.
    //
    vssq_status_CONTACTS_FAILED_SEND_REQUEST_FAILED = -1401,
    //
    //  Failed to perform contacts operation because response with error was returned.
    //
    vssq_status_CONTACTS_FAILED_RESPONSE_WITH_ERROR = -1402,
    //
    //  Failed to perform contacts operation because response parsing failed.
    //
    vssq_status_CONTACTS_FAILED_PARSE_RESPONSE_FAILED = -1403,
    //
    //  Communicate with Cloud FS failed because send request failed.
    //
    vssq_status_CLOUD_FS_FAILED_SEND_REQUEST_FAILED = -1500,
    //
    //  Cloud FS got a service error - internal server error (10000) - status 500.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_INTERNAL_SERVER_ERROR = -1501,
    //
    //  Cloud FS got a service error - entry not found - status 404.
    //
    vssq_status_CLOUD_FS_FAILED_ENTRY_NOT_FOUND = -1502,
    //
    //  Cloud FS got a service error - identity is invalid (40001) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_IDENTITY_IS_INVALID = -1503,
    //
    //  Cloud FS got a service error - user not found (40002) - status 404.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_USER_NOT_FOUND = -1504,
    //
    //  Cloud FS got a service error - folder not found (40003) - status 404.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_FOLDER_NOT_FOUND = -1505,
    //
    //  Cloud FS got a service error - invalid filename (40004) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FILENAME = -1506,
    //
    //  Cloud FS got a service error - invalid file id (40005) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FILE_ID = -1507,
    //
    //  Cloud FS got a service error - invalid file size (40006) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FILE_SIZE = -1508,
    //
    //  Cloud FS got a service error - invalid file type (40007) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FILE_TYPE = -1509,
    //
    //  Cloud FS got a service error - invalid folder id (40008) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FOLDER_ID = -1510,
    //
    //  Cloud FS got a service error - invalid folder name (40009) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FOLDER_NAME = -1511,
    //
    //  Cloud FS got a service error - invalid user permission (40010) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_USER_PERMISSION = -1512,
    //
    //  Cloud FS got a service error - group folder has limited depth (40011) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_GROUP_FOLDER_HAS_LIMITED_DEPTH = -1513,
    //
    //  Cloud FS got a service error - permission denied (40012) - status 403.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_PERMISSION_DENIED = -1514,
    //
    //  Cloud FS got a service error - key is not specified (40013) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_KEY_IS_NOT_SPECIFIED = -1515,
    //
    //  Cloud FS got a service error - file with such name already exists (40014) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_FILE_WITH_SUCH_NAME_ALREADY_EXISTS = -1516,
    //
    //  Cloud FS got a service error - file not found (40015) - status 404.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_FILE_NOT_FOUND = -1517,
    //
    //  Cloud FS got a service error - folder with such name already exists (40016) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_FOLDER_WITH_SUCH_NAME_ALREADY_EXISTS = -1518,
    //
    //  Cloud FS got a service error - invalid group id (40017) - status 400.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_GROUP_ID = -1519,
    //
    //  Cloud FS got a service error - group not found (40018) - status 404.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_GROUP_NOT_FOUND = -1520,
    //
    //  Cloud FS got a service error - undefined error - status 4xx.
    //
    vssq_status_CLOUD_FS_SERVICE_ERROR_UNDEFINED = -1529,
    //
    //  Communicate with Cloud FS failed because met unexpected HTTP content type, expected application/protobuf.
    //
    vssq_status_CLOUD_FS_FAILED_RESPONSE_UNEXPECTED_CONTENT_TYPE = -1530,
    //
    //  Communicate with Cloud FS failed because failed to parse response body.
    //
    vssq_status_CLOUD_FS_FAILED_PARSE_RESPONSE_FAILED = -1531,
    //
    //  Cloud FS operation failed because key generation failed.
    //
    vssq_status_CLOUD_FS_FAILED_GENERATE_KEY_FAILED = -1532,
    //
    //  Cloud FS operation failed because something went wrong during key encryption.
    //
    vssq_status_CLOUD_FS_FAILED_ENCRYPT_KEY_FAILED = -1533,
    //
    //  Cloud FS operation failed because import key failed.
    //
    vssq_status_CLOUD_FS_FAILED_IMPORT_KEY_FAILED = -1534,
    //
    //  Cloud FS operation failed because export key failed.
    //
    vssq_status_CLOUD_FS_FAILED_EXPORT_KEY_FAILED = -1535,
    //
    //  Cloud FS operation failed because encrypted key has invalid format.
    //
    vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_FAILED_INVALID_FORMAT = -1536,
    //
    //  Cloud FS operation failed because encrypted key can not be decrypted with a given key.
    //
    vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_WRONG_KEY = -1537,
    //
    //  Cloud FS operation failed because encrypted key can not be decrypted due to signer mismatch.
    //
    vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_SIGNER_MISMATCH = -1538,
    //
    //  Cloud FS operation failed because encrypted key can not be decrypted due to invalid signature.
    //
    vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_INVALID_SIGNATURE = -1539
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
