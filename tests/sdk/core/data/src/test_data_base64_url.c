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

#include "test_data_base64_url.h"

// ==========================================================================
static byte DECODED_CONTAINS_PLUS[] = {
    0x69, 0xf6, 0xbe
};

const vsc_data_t test_data_base64_url_DECODED_CONTAINS_PLUS = {
    DECODED_CONTAINS_PLUS, sizeof(DECODED_CONTAINS_PLUS)
};

// ==========================================================================
static const char ENCODED_REPLACED_PLUS[] = "afa-";

const vsc_str_t test_data_base64_url_ENCODED_REPLACED_PLUS = {
    ENCODED_REPLACED_PLUS, sizeof(ENCODED_REPLACED_PLUS) - 1
};

// ==========================================================================
static byte DECODED_CONTAINS_SLASH[] = {
    0x69, 0xf6, 0xbf
};

const vsc_data_t test_data_base64_url_DECODED_CONTAINS_SLASH = {
    DECODED_CONTAINS_SLASH, sizeof(DECODED_CONTAINS_SLASH)
};

// ==========================================================================
static const char ENCODED_REPLACED_SLASH[] = "afa_";

const vsc_str_t test_data_base64_url_ENCODED_REPLACED_SLASH = {
    ENCODED_REPLACED_SLASH, sizeof(ENCODED_REPLACED_SLASH) - 1
};


// ==========================================================================
static const byte DECODED_CONTAINS_1_PADDING[] = {
    0x69, 0xf6
};

const vsc_data_t test_data_base64_url_DECODED_CONTAINS_1_PADDING = {
    DECODED_CONTAINS_1_PADDING, sizeof(DECODED_CONTAINS_1_PADDING)
};

// ==========================================================================
static const char ENCODED_REMOVED_1_PADDING[] = "afY";

const vsc_str_t test_data_base64_url_ENCODED_REMOVED_1_PADDING = {
    ENCODED_REMOVED_1_PADDING, sizeof(ENCODED_REMOVED_1_PADDING) - 1
};

// ==========================================================================
static const byte DECODED_CONTAINS_2_PADDINGS[] = {
    0x69
};

const vsc_data_t test_data_base64_url_DECODED_CONTAINS_2_PADDINGS = {
    DECODED_CONTAINS_2_PADDINGS, sizeof(DECODED_CONTAINS_2_PADDINGS)
};

// ==========================================================================
static const char ENCODED_REMOVED_2_PADDINGS[] = "aQ";

const vsc_str_t test_data_base64_url_ENCODED_REMOVED_2_PADDINGS = {
    ENCODED_REMOVED_2_PADDINGS, sizeof(ENCODED_REMOVED_2_PADDINGS) - 1
};
