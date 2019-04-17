//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

#ifndef VSCR_RATCHET_COMMON_HIDDEN_H_INCLUDED
#define VSCR_RATCHET_COMMON_HIDDEN_H_INCLUDED

#include "vscr_library.h"

#include <pb_decode.h>
#include <pb_encode.h>

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
    vscr_ratchet_common_hidden_RATCHET_REGULAR_MESSAGE_VERSION = 1,
    vscr_ratchet_common_hidden_RATCHET_PROTOCOL_VERSION = 1,
    vscr_ratchet_common_hidden_RATCHET_MESSAGE_VERSION = 1,
    vscr_ratchet_common_hidden_RATCHET_GROUP_INFO_VERSION = 1,
    vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LEN = 32,
    vscr_ratchet_common_hidden_RATCHET_KEY_LEN = 32,
    vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES = 40,
    vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS = 5,
    vscr_ratchet_common_hidden_MAX_MESSAGE_GAP = 2000,
    vscr_ratchet_common_hidden_SIGNATURE_LEN = 64,
    vscr_ratchet_common_hidden_MAX_REGULAR_MESSAGE_LEN = 32834,
    vscr_ratchet_common_hidden_MAX_PREKEY_MESSAGE_LEN = 32975,
    vscr_ratchet_common_hidden_MAX_GROUP_REGULAR_MESSAGE_LEN = 32906,
    vscr_ratchet_common_hidden_MAX_GROUP_INFO_MESSAGE_LEN = 10845,
    vscr_ratchet_common_hidden_PARTICIPANT_LEN = 108,
    vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN = 32768,
    vscr_ratchet_common_hidden_MAX_EPOCHES_COUNT = 5
};

VSCR_PUBLIC bool
vscr_ratchet_common_hidden_buffer_decode_callback(pb_istream_t *stream, const pb_field_t *field, void**arg,
        size_t max_size);

VSCR_PUBLIC bool
vscr_ratchet_common_hidden_buffer_encode_callback(pb_ostream_t *stream, const pb_field_t *field, void *const *arg);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_COMMON_HIDDEN_H_INCLUDED
//  @end
