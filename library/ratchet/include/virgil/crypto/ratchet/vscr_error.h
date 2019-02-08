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


//  @description
// --------------------------------------------------------------------------
//  Error codes
// --------------------------------------------------------------------------

#ifndef VSCR_ERROR_H_INCLUDED
#define VSCR_ERROR_H_INCLUDED

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
//  Error codes
//
enum vscr_error_t {
    //
    //  No errors was occurred.
    //
    vscr_SUCCESS = 0,
    //
    //  Error during protobuf deserialization
    //
    vscr_error_PROTOBUF_DECODE = 1,
    //
    //  Message version doesn't match
    //
    vscr_error_MESSAGE_VERSION_DOESN_T_MATCH = 2,
    //
    //  Bad message type
    //
    vscr_error_BAD_MESSAGE_TYPE = 3,
    //
    //  AES error
    //
    vscr_error_AES = 4,
    //
    //  RNG failed
    //
    vscr_error_RNG_FAILED = 5,
    //
    //  Curve25519 error
    //
    vscr_error_CURVE25519 = 6,
    //
    //  Key deserialization error
    //
    vscr_error_KEY_DESERIALIZATION = 7,
    //
    //  Invalid key type
    //
    vscr_error_INVALID_KEY_TYPE = 8,
    //
    //  Identity key doesn't match
    //
    vscr_error_IDENTITY_KEY_DOESNT_MATCH = 9,
    //
    //  Message already decrypted
    //
    vscr_error_MESSAGE_ALREADY_DECRYPTED = 10,
    //
    //  Too many lost messages
    //
    vscr_error_TOO_MANY_LOST_MESSAGES = 11,
    //
    //  Sender chain missing
    //
    vscr_error_SENDER_CHAIN_MISSING = 12,
    //
    //  Skipped message missing
    //
    vscr_error_SKIPPED_MESSAGE_MISSING = 13,
    //
    //  Can't encrypt yet
    //
    vscr_error_CAN_T_ENCRYPT_YET = 14,
    //
    //  Exceeded max plain text len
    //
    vscr_error_EXCEEDED_MAX_PLAIN_TEXT_LEN = 15,
    //
    //  Too many messages for sender chain
    //
    vscr_error_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN = 16,
    //
    //  Too many messages for receiver chain
    //
    vscr_error_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN = 17
};
typedef enum vscr_error_t vscr_error_t;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_ERROR_H_INCLUDED
//  @end
