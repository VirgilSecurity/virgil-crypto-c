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

#ifndef VSCR_STATUS_H_INCLUDED
#define VSCR_STATUS_H_INCLUDED

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
enum vscr_status_t {
    //
    //  No errors was occurred.
    //
    vscr_status_SUCCESS = 0,
    //
    //  Error during protobuf deserialization.
    //
    vscr_status_ERROR_PROTOBUF_DECODE = -1,
    //
    //  Bad message type.
    //
    vscr_status_ERROR_BAD_MESSAGE_TYPE = -2,
    //
    //  AES error.
    //
    vscr_status_ERROR_AES = -3,
    //
    //  RNG failed.
    //
    vscr_status_ERROR_RNG_FAILED = -4,
    //
    //  Curve25519 error.
    //
    vscr_status_ERROR_CURVE25519 = -5,
    //
    //  Curve25519 error.
    //
    vscr_status_ERROR_ED25519 = -6,
    //
    //  Key deserialization failed.
    //
    vscr_status_ERROR_KEY_DESERIALIZATION_FAILED = -7,
    //
    //  Invalid key type.
    //
    vscr_status_ERROR_INVALID_KEY_TYPE = -8,
    //
    //  Identity key doesn't match.
    //
    vscr_status_ERROR_IDENTITY_KEY_DOESNT_MATCH = -9,
    //
    //  Message already decrypted.
    //
    vscr_status_ERROR_MESSAGE_ALREADY_DECRYPTED = -10,
    //
    //  Too many lost messages.
    //
    vscr_status_ERROR_TOO_MANY_LOST_MESSAGES = -11,
    //
    //  Sender chain missing.
    //
    vscr_status_ERROR_SENDER_CHAIN_MISSING = -12,
    //
    //  Skipped message missing.
    //
    vscr_status_ERROR_SKIPPED_MESSAGE_MISSING = -13,
    //
    //  Session is not initialized.
    //
    vscr_status_ERROR_SESSION_IS_NOT_INITIALIZED = -14,
    //
    //  Exceeded max plain text len.
    //
    vscr_status_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN = -15,
    //
    //  Too many messages for sender chain.
    //
    vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN = -16,
    //
    //  Too many messages for receiver chain.
    //
    vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN = -17,
    //
    //  Invalid padding.
    //
    vscr_status_ERROR_INVALID_PADDING = -18,
    //
    //  Too many participants.
    //
    vscr_status_ERROR_TOO_MANY_PARTICIPANTS = -19,
    //
    //  Too few participants.
    //
    vscr_status_ERROR_TOO_FEW_PARTICIPANTS = -20,
    //
    //  Sender not found.
    //
    vscr_status_ERROR_SENDER_NOT_FOUND = -21,
    //
    //  Cannot decrypt own messages.
    //
    vscr_status_ERROR_CANNOT_DECRYPT_OWN_MESSAGES = -22,
    //
    //  Invalid signature.
    //
    vscr_status_ERROR_INVALID_SIGNATURE = -23,
    //
    //  Cannot remove myself.
    //
    vscr_status_ERROR_CANNOT_REMOVE_MYSELF = -24,
    //
    //  Epoch mismatch.
    //
    vscr_status_ERROR_EPOCH_MISMATCH = -25,
    //
    //  Epoch not found.
    //
    vscr_status_ERROR_EPOCH_NOT_FOUND = -26,
    //
    //  Session id mismatch.
    //
    vscr_status_ERROR_SESSION_ID_MISMATCH = -27,
    //
    //  Simultaneous group user operation.
    //
    vscr_status_ERROR_SIMULTANEOUS_GROUP_USER_OPERATION = -28,
    //
    //  Myself is included in info.
    //
    vscr_status_ERROR_MYSELF_IS_INCLUDED_IN_INFO = -29,
    //
    //  Round5 error.
    //
    vscr_status_ERROR_ROUND5 = -30,
    //
    //  Falcon error.
    //
    vscr_status_ERROR_FALCON = -31,
    //
    //  Decaps signature is invalid.
    //
    vscr_status_ERROR_DECAPS_SIGNATURE_INVALID = -32,
    //
    //  Error importing round5 key.
    //
    vscr_status_ERROR_ROUND5_IMPORT_KEY = -33
};
typedef enum vscr_status_t vscr_status_t;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_STATUS_H_INCLUDED
//  @end
