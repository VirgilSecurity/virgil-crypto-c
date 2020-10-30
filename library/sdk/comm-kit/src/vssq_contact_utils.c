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


//  @description
// --------------------------------------------------------------------------
//  Helps to normalize and hash user contacts: username, email, phone, etc.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_contact_utils.h"
#include "vssq_memory.h"
#include "vssq_assert.h"

#include <ctype.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/private/vscf_sha256_defs.h>
#include <virgil/crypto/foundation/vscf_binary.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Validate and normalize username.
//
//  Valudation rules:
//      1. Length in the range: [1..20]
//      2. Do not start or end with an underscore
//      3. Do not start with a number
//      4. Match regex: ^[a-zA-Z0-9_]+$
//
//  Normalization rules:
//      1. All characters lowercase
//
VSSQ_PUBLIC vssq_status_t
vssq_contact_utils_normalize_username(vsc_str_t username, vsc_str_buffer_t *normalized) {

    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(username));
    VSSQ_ASSERT(vsc_str_buffer_is_valid(normalized));
    VSSQ_ASSERT(vsc_str_buffer_unused_len(normalized) >= username.len);

    //
    //  Validate rule 1 - Length in the range: [1..20].
    //
    if (username.len > vssq_contact_utils_USERNAME_LEN_MAX) {
        return vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_TOO_LONG;
    }

    //
    //  Validate rule 2 - Do not start or end with an underscore.
    //
    if (('_' == username.chars[0]) || ('_' == username.chars[username.len - 1])) {
        return vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS;
    }

    //
    //  Validate rule 3 - Do not start with a number.
    //
    if (isdigit(username.chars[0])) {
        return vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS;
    }

    //
    //  Validate, normalize and write to the output.
    //
    char *normalized_chars = vsc_str_buffer_unused_chars(normalized);

    for (size_t pos = 0; pos < username.len; ++pos) {
        const int ch = username.chars[pos];
        //
        //  Validate rule 4 - Match regex: ^[a-zA-Z0-9_]+$.
        //  And convert to the lowercase.
        //
        if (isalnum(ch) || (ch == '_')) {
            normalized_chars[pos] = (char)tolower(ch);
        } else {
            return vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS;
        }
    }

    vsc_str_buffer_inc_used(normalized, username.len);

    return vssq_status_SUCCESS;
}

//
//  Validate, normalize, and hash username.
//
VSSQ_PUBLIC vssq_status_t
vssq_contact_utils_hash_username(vsc_str_t username, vsc_str_buffer_t *digest_hex) {

    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(username));
    VSSQ_ASSERT(vsc_str_buffer_is_valid(digest_hex));
    VSSQ_ASSERT(vsc_str_buffer_unused_len(digest_hex) >= vssq_contact_utils_DIGEST_HEX_LEN);

    //
    //  Validate rule 1 - Length in the range: [1..20].
    //
    if (username.len > vssq_contact_utils_USERNAME_LEN_MAX) {
        return vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_TOO_LONG;
    }

    //
    //  Validate rule 2 - Do not start or end with an underscore.
    //
    if (('_' == username.chars[0]) || ('_' == username.chars[username.len - 1])) {
        return vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS;
    }

    //
    //  Validate rule 3 - Do not start with a number.
    //
    if (isdigit(username.chars[0])) {
        return vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS;
    }

    //
    //  Validate, normalize and hash.
    //
    vscf_sha256_t hash;
    vscf_sha256_init(&hash);

    for (size_t pos = 0; pos < username.len; ++pos) {
        const int ch = username.chars[pos];
        //
        //  Validate rule 4 - Match regex: ^[a-zA-Z0-9_]+$.
        //  And convert to the lowercase.
        //
        if (isalnum(ch) || (ch == '_')) {
            const byte normalized_byte = (byte)tolower(ch);
            vscf_sha256_update(&hash, vsc_data(&normalized_byte, 1));
        } else {
            return vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS;
        }
    }

    byte digest_bytes[vscf_sha256_DIGEST_LEN] = {0x00};
    vsc_buffer_t digest;
    vsc_buffer_init(&digest);
    vsc_buffer_use(&digest, digest_bytes, sizeof(digest_bytes));

    vscf_sha256_finish(&hash, &digest);

    vscf_binary_to_hex(vsc_buffer_data(&digest), digest_hex);

    return vssq_status_SUCCESS;
}
