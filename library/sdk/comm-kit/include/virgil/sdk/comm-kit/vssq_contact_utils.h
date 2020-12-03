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
//  Helps to normalize and hash user contacts: username, email, phone, etc.
// --------------------------------------------------------------------------

#ifndef VSSQ_CONTACT_UTILS_H_INCLUDED
#define VSSQ_CONTACT_UTILS_H_INCLUDED

#include "vssq_library.h"
#include "vssq_status.h"
#include "vssq_error.h"

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_str_buffer.h>
#endif

#if !VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_string_list.h>
#   include <virgil/sdk/core/vssc_string_map.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#   include <VSCCommon/vsc_str_buffer.h>
#endif

#if VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSCore/vssc_string_list.h>
#   include <VSSCore/vssc_string_map.h>
#endif

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
//  Public integral constants.
//
enum {
    vssq_contact_utils_DIGEST_HEX_LEN = 64,
    vssq_contact_utils_USERNAME_LEN_MAX = 20
};

//
//  Validate and normalize username.
//
//  Validation rules:
//      1. Length in the range: [1..20]
//      2. Do not start or end with an underscore
//      3. Do not start with a number
//      4. Match regex: ^[a-zA-Z0-9_]+$
//
//  Normalization rules:
//      1. To lowercase
//
VSSQ_PUBLIC vssq_status_t
vssq_contact_utils_normalize_username(vsc_str_t username, vsc_str_buffer_t *normalized) VSSQ_NODISCARD;

//
//  Validate, normalize, and hash username.
//
VSSQ_PUBLIC vssq_status_t
vssq_contact_utils_hash_username(vsc_str_t username, vsc_str_buffer_t *digest_hex) VSSQ_NODISCARD;

//
//  Validate, normalize, and hash each username.
//
//  Return a map "username->hash".
//
//  Note, usernames in the returned map equals to the given.
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_contact_utils_hash_usernames(const vssc_string_list_t *usernames, vssq_error_t *error);

//
//  Validate phone number.
//
//  Validation rules:
//      1. Start with plus (+) sign.
//      2. Contains only digits after plus sign.
//      3. Phone number max 15 digits.
//
VSSQ_PUBLIC vssq_status_t
vssq_contact_utils_validate_phone_number(vsc_str_t phone_number) VSSQ_NODISCARD;

//
//  Validate, and hash phone number.
//
//  Validation rules:
//      1. Start with plus (+) sign.
//      2. Contains only digits after plus sign.
//      3. Phone number max 15 digits.
//
//  Note, for now given phone number is not formatted.
//
VSSQ_PUBLIC vssq_status_t
vssq_contact_utils_hash_phone_number(vsc_str_t phone_number, vsc_str_buffer_t *digest_hex) VSSQ_NODISCARD;

//
//  Validate, and hash each phone number.
//
//  Return a map "phone-number->hash".
//
//  Note, phone numbers in the returned map equals to the given.
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_contact_utils_hash_phone_numbers(const vssc_string_list_t *phone_numbers, vssq_error_t *error);

//
//  Validate email.
//
//  Validation rules:
//      1. Check email regex: "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+$)".
//
VSSQ_PUBLIC vssq_status_t
vssq_contact_utils_validate_email(vsc_str_t email) VSSQ_NODISCARD;

//
//  Validate, normalize and hash email.
//
//  Validation rules:
//      1. Check email regex: "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+$)".
//
//  Normalization rules:
//      1. To lowercase
//      2. Remove dots.
//      3. Remove suffix that starts with a plus sign.
//
VSSQ_PUBLIC vssq_status_t
vssq_contact_utils_hash_email(vsc_str_t email, vsc_str_buffer_t *digest_hex) VSSQ_NODISCARD;

//
//  Validate, normalize, and hash each email.
//
//  Return a map "email->hash".
//
//  Note, emails in the returned map equals to the given.
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_contact_utils_hash_emails(const vssc_string_list_t *emails, vssq_error_t *error);

//
//  Merge "contact request map" with "contact response map".
//
//  Contact request map : username | email | phone-number->hash
//  Contact response map: hash->identity
//  Final map : username | email | phone-number->identity
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_contact_utils_merge_contact_discovery_maps(const vssc_string_map_t *contact_request_map,
        const vssc_string_map_t *contact_response_map);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_CONTACT_UTILS_H_INCLUDED
//  @end
