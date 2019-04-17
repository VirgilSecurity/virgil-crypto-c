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
    //  Message version doesn't match.
    //
    vscr_status_ERROR_MESSAGE_VERSION_DOESN_T_MATCH = -2,
    //
    //  Bad message type.
    //
    vscr_status_ERROR_BAD_MESSAGE_TYPE = -3,
    //
    //  AES error.
    //
    vscr_status_ERROR_AES = -4,
    //
    //  RNG failed.
    //
    vscr_status_ERROR_RNG_FAILED = -5,
    //
    //  Curve25519 error.
    //
    vscr_status_ERROR_CURVE25519 = -6,
    //
    //  Curve25519 error.
    //
    vscr_status_ERROR_ED25519 = -7,
    //
    //  Key deserialization failed.
    //
    vscr_status_ERROR_KEY_DESERIALIZATION_FAILED = -8,
    //
    //  Invalid key type.
    //
    vscr_status_ERROR_INVALID_KEY_TYPE = -9,
    //
    //  Identity key doesn't match.
    //
    vscr_status_ERROR_IDENTITY_KEY_DOESNT_MATCH = -10,
    //
    //  Message already decrypted.
    //
    vscr_status_ERROR_MESSAGE_ALREADY_DECRYPTED = -11,
    //
    //  Too many lost messages.
    //
    vscr_status_ERROR_TOO_MANY_LOST_MESSAGES = -12,
    //
    //  Sender chain missing.
    //
    vscr_status_ERROR_SENDER_CHAIN_MISSING = -13,
    //
    //  Skipped message missing.
    //
    vscr_status_ERROR_SKIPPED_MESSAGE_MISSING = -14,
    //
    //  Session is not initialized.
    //
    vscr_status_ERROR_SESSION_IS_NOT_INITIALIZED = -15,
    //
    //  Exceeded max plain text len.
    //
    vscr_status_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN = -16,
    //
    //  Too many messages for sender chain.
    //
    vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN = -17,
    //
    //  Too many messages for receiver chain.
    //
    vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN = -18,
    //
    //  Invalid padding.
    //
    vscr_status_ERROR_INVALID_PADDING = -19,
    //
    //  Too many participants.
    //
    vscr_status_ERROR_TOO_MANY_PARTICIPANTS = -20,
    //
    //  Too few participants.
    //
    vscr_status_ERROR_TOO_FEW_PARTICIPANTS = -21,
    //
    //  Sender not found.
    //
    vscr_status_ERROR_SENDER_NOT_FOUND = -22,
    //
    //  Cannot decrypt own messages.
    //
    vscr_status_ERROR_CANNOT_DECRYPT_OWN_MESSAGES = -23,
    //
    //  Duplicate id.
    //
    vscr_status_ERROR_DUPLICATE_ID = -24,
    //
    //  Invalid signature.
    //
    vscr_status_ERROR_INVALID_SIGNATURE = -25,
    //
    //  User is not present in group message.
    //
    vscr_status_ERROR_USER_IS_NOT_PRESENT_IN_GROUP_MESSAGE = -26,
    //
    //  Epoch mismatch.
    //
    vscr_status_ERROR_EPOCH_MISMATCH = -27,
    //
    //  Participant not found.
    //
    vscr_status_ERROR_PARTICIPANT_NOT_FOUND = -28,
    //
    //  Epoch not found.
    //
    vscr_status_ERROR_EPOCH_NOT_FOUND = -29,
    //
    //  Session id mismatch.
    //
    vscr_status_ERROR_SESSION_ID_MISMATCH = -30
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
