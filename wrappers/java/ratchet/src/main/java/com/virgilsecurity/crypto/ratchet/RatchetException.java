/*
* Copyright (C) 2015-2022 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
*/

package com.virgilsecurity.crypto.ratchet;

public class RatchetException {

    public int SUCCESS;

    public int ERROR_PROTOBUF_DECODE;

    public int ERROR_BAD_MESSAGE_TYPE;

    public int ERROR_AES;

    public int ERROR_RNG_FAILED;

    public int ERROR_CURVE25519;

    public int ERROR_ED25519;

    public int ERROR_KEY_DESERIALIZATION_FAILED;

    public int ERROR_INVALID_KEY_TYPE;

    public int ERROR_IDENTITY_KEY_DOESNT_MATCH;

    public int ERROR_MESSAGE_ALREADY_DECRYPTED;

    public int ERROR_TOO_MANY_LOST_MESSAGES;

    public int ERROR_SENDER_CHAIN_MISSING;

    public int ERROR_SKIPPED_MESSAGE_MISSING;

    public int ERROR_SESSION_IS_NOT_INITIALIZED;

    public int ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN;

    public int ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN;

    public int ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;

    public int ERROR_INVALID_PADDING;

    public int ERROR_TOO_MANY_PARTICIPANTS;

    public int ERROR_TOO_FEW_PARTICIPANTS;

    public int ERROR_SENDER_NOT_FOUND;

    public int ERROR_CANNOT_DECRYPT_OWN_MESSAGES;

    public int ERROR_INVALID_SIGNATURE;

    public int ERROR_CANNOT_REMOVE_MYSELF;

    public int ERROR_EPOCH_MISMATCH;

    public int ERROR_EPOCH_NOT_FOUND;

    public int ERROR_SESSION_ID_MISMATCH;

    public int ERROR_SIMULTANEOUS_GROUP_USER_OPERATION;

    public int ERROR_MYSELF_IS_INCLUDED_IN_INFO;

    public int ERROR_ROUND5;

    public int ERROR_FALCON;

    public int ERROR_DECAPS_SIGNATURE_INVALID;

    public int ERROR_ROUND5_IMPORT_KEY;

    private int statusCode;

    public RatchetException(int statusCode) {
        super();
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return this.statusCode;
    }

    public String getMessage() {
        switch (this.statusCode) {
        case SUCCESS:
            return "No errors was occurred.";
        case ERROR_PROTOBUF_DECODE:
            return "Error during protobuf deserialization.";
        case ERROR_BAD_MESSAGE_TYPE:
            return "Bad message type.";
        case ERROR_AES:
            return "AES error.";
        case ERROR_RNG_FAILED:
            return "RNG failed.";
        case ERROR_CURVE25519:
            return "Curve25519 error.";
        case ERROR_ED25519:
            return "Curve25519 error.";
        case ERROR_KEY_DESERIALIZATION_FAILED:
            return "Key deserialization failed.";
        case ERROR_INVALID_KEY_TYPE:
            return "Invalid key type.";
        case ERROR_IDENTITY_KEY_DOESNT_MATCH:
            return "Identity key doesn't match.";
        case ERROR_MESSAGE_ALREADY_DECRYPTED:
            return "Message already decrypted.";
        case ERROR_TOO_MANY_LOST_MESSAGES:
            return "Too many lost messages.";
        case ERROR_SENDER_CHAIN_MISSING:
            return "Sender chain missing.";
        case ERROR_SKIPPED_MESSAGE_MISSING:
            return "Skipped message missing.";
        case ERROR_SESSION_IS_NOT_INITIALIZED:
            return "Session is not initialized.";
        case ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN:
            return "Exceeded max plain text len.";
        case ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN:
            return "Too many messages for sender chain.";
        case ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN:
            return "Too many messages for receiver chain.";
        case ERROR_INVALID_PADDING:
            return "Invalid padding.";
        case ERROR_TOO_MANY_PARTICIPANTS:
            return "Too many participants.";
        case ERROR_TOO_FEW_PARTICIPANTS:
            return "Too few participants.";
        case ERROR_SENDER_NOT_FOUND:
            return "Sender not found.";
        case ERROR_CANNOT_DECRYPT_OWN_MESSAGES:
            return "Cannot decrypt own messages.";
        case ERROR_INVALID_SIGNATURE:
            return "Invalid signature.";
        case ERROR_CANNOT_REMOVE_MYSELF:
            return "Cannot remove myself.";
        case ERROR_EPOCH_MISMATCH:
            return "Epoch mismatch.";
        case ERROR_EPOCH_NOT_FOUND:
            return "Epoch not found.";
        case ERROR_SESSION_ID_MISMATCH:
            return "Session id mismatch.";
        case ERROR_SIMULTANEOUS_GROUP_USER_OPERATION:
            return "Simultaneous group user operation.";
        case ERROR_MYSELF_IS_INCLUDED_IN_INFO:
            return "Myself is included in info.";
        case ERROR_ROUND5:
            return "Round5 error.";
        case ERROR_FALCON:
            return "Falcon error.";
        case ERROR_DECAPS_SIGNATURE_INVALID:
            return "Decaps signature is invalid.";
        case ERROR_ROUND5_IMPORT_KEY:
            return "Error importing round5 key.";
        default:
            return "Unknown error";
        }
    }

}
