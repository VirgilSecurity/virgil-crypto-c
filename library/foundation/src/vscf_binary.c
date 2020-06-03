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
//  Contains utils for convertion from bytes to HEX and vice-versa.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_binary.h"
#include "vscf_memory.h"
#include "vscf_assert.h"

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
//  Return buffer length enaugh to hold hexed data.
//
VSCF_PUBLIC size_t
vscf_binary_to_hex_len(size_t data_len) {

    return data_len << 1;
}

//
//  Converts byte array to hex.
//  Output length should be twice bigger then input.
//
VSCF_PUBLIC void
vscf_binary_to_hex(vsc_data_t data, vsc_str_buffer_t *hex_str) {

    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(vsc_str_buffer_is_valid(hex_str));
    VSCF_ASSERT(vsc_str_buffer_unused_len(hex_str) >= vscf_binary_to_hex_len(vsc_data_len(data)));

    for (size_t i = 0; i < data.len; ++i) {
        const uint8_t h = data.bytes[i] / 16;
        const uint8_t l = data.bytes[i] % 16;

        if (h < 10) {
            vsc_str_buffer_write_char(hex_str, '0' + h);
        } else {
            vsc_str_buffer_write_char(hex_str, 'a' + h - 10);
        }

        if (l < 10) {
            vsc_str_buffer_write_char(hex_str, '0' + l);
        } else {
            vsc_str_buffer_write_char(hex_str, 'a' + l - 10);
        }
    }
}

//
//  Return buffer length enaugh to hold unhexed data.
//
VSCF_PUBLIC size_t
vscf_binary_from_hex_len(size_t hex_len) {

    return hex_len >> 1;
}

//
//  Converts hex string to byte array.
//  Output length should be at least half of the input hex string.
//
VSCF_PUBLIC vscf_status_t
vscf_binary_from_hex(vsc_str_t hex_str, vsc_buffer_t *data) {

    VSCF_ASSERT(vsc_str_is_valid(hex_str));
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(data));
    VSCF_ASSERT(vsc_buffer_unused_len(data) >= vscf_binary_from_hex_len(vsc_str_len(hex_str)));

    if (hex_str.len % 2 != 0) {
        return vscf_status_HEX_TO_BYTES_FAILED;
    }

    for (size_t i = 0; i < hex_str.len; i += 2) {
        char c1 = hex_str.chars[i];
        if (c1 >= '0' && c1 <= '9') {
            c1 -= '0';
        } else if (c1 >= 'a' && c1 <= 'f') {
            c1 -= 'a' - 10;
        } else if (c1 >= 'A' && c1 <= 'F') {
            c1 -= 'A' - 10;
        } else {
            return vscf_status_HEX_TO_BYTES_FAILED;
        }

        char c2 = hex_str.chars[i + 1];
        if (c2 >= '0' && c2 <= '9') {
            c2 -= '0';
        } else if (c2 >= 'a' && c2 <= 'f') {
            c2 -= 'a' - 10;
        } else if (c2 >= 'A' && c2 <= 'F') {
            c2 -= 'A' - 10;
        } else {
            assert(0);
        }

        vsc_buffer_write_byte(data, (c1 << 4) | c2);
    }

    return vscf_status_SUCCESS;
}
