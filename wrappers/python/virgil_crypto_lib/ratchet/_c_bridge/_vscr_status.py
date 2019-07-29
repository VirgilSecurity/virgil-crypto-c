# Copyright (C) 2015-2019 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


from ctypes import *


class VirgilCryptoRatchetError(Exception):
    pass


class VscrStatus(object):
    """Defines the library status codes."""

    # No errors was occurred.
    SUCCESS = 0
    # Error during protobuf deserialization.
    ERROR_PROTOBUF_DECODE = -1
    # Bad message type.
    ERROR_BAD_MESSAGE_TYPE = -2
    # AES error.
    ERROR_AES = -3
    # RNG failed.
    ERROR_RNG_FAILED = -4
    # Curve25519 error.
    ERROR_CURVE25519 = -5
    # Curve25519 error.
    ERROR_ED25519 = -6
    # Key deserialization failed.
    ERROR_KEY_DESERIALIZATION_FAILED = -7
    # Invalid key type.
    ERROR_INVALID_KEY_TYPE = -8
    # Identity key doesn't match.
    ERROR_IDENTITY_KEY_DOESNT_MATCH = -9
    # Message already decrypted.
    ERROR_MESSAGE_ALREADY_DECRYPTED = -10
    # Too many lost messages.
    ERROR_TOO_MANY_LOST_MESSAGES = -11
    # Sender chain missing.
    ERROR_SENDER_CHAIN_MISSING = -12
    # Skipped message missing.
    ERROR_SKIPPED_MESSAGE_MISSING = -13
    # Session is not initialized.
    ERROR_SESSION_IS_NOT_INITIALIZED = -14
    # Exceeded max plain text len.
    ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN = -15
    # Too many messages for sender chain.
    ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN = -16
    # Too many messages for receiver chain.
    ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN = -17
    # Invalid padding.
    ERROR_INVALID_PADDING = -18
    # Too many participants.
    ERROR_TOO_MANY_PARTICIPANTS = -19
    # Too few participants.
    ERROR_TOO_FEW_PARTICIPANTS = -20
    # Sender not found.
    ERROR_SENDER_NOT_FOUND = -21
    # Cannot decrypt own messages.
    ERROR_CANNOT_DECRYPT_OWN_MESSAGES = -22
    # Invalid signature.
    ERROR_INVALID_SIGNATURE = -23
    # Cannot remove myself.
    ERROR_CANNOT_REMOVE_MYSELF = -24
    # Epoch mismatch.
    ERROR_EPOCH_MISMATCH = -25
    # Epoch not found.
    ERROR_EPOCH_NOT_FOUND = -26
    # Session id mismatch.
    ERROR_SESSION_ID_MISMATCH = -27
    # Simultaneous group user operation.
    ERROR_SIMULTANEOUS_GROUP_USER_OPERATION = -28
    # Myself is included in info.
    ERROR_MYSELF_IS_INCLUDED_IN_INFO = -29

    STATUS_DICT = {
        0: "No errors was occurred.",
        -1: "Error during protobuf deserialization.",
        -2: "Bad message type.",
        -3: "AES error.",
        -4: "RNG failed.",
        -5: "Curve25519 error.",
        -6: "Curve25519 error.",
        -7: "Key deserialization failed.",
        -8: "Invalid key type.",
        -9: "Identity key doesn't match.",
        -10: "Message already decrypted.",
        -11: "Too many lost messages.",
        -12: "Sender chain missing.",
        -13: "Skipped message missing.",
        -14: "Session is not initialized.",
        -15: "Exceeded max plain text len.",
        -16: "Too many messages for sender chain.",
        -17: "Too many messages for receiver chain.",
        -18: "Invalid padding.",
        -19: "Too many participants.",
        -20: "Too few participants.",
        -21: "Sender not found.",
        -22: "Cannot decrypt own messages.",
        -23: "Invalid signature.",
        -24: "Cannot remove myself.",
        -25: "Epoch mismatch.",
        -26: "Epoch not found.",
        -27: "Session id mismatch.",
        -28: "Simultaneous group user operation.",
        -29: "Myself is included in info."
    }

    @classmethod
    def handle_status(cls, status):
        """Handle low level lib status"""
        if status != 0:
            try:
                raise VirgilCryptoRatchetError(cls.STATUS_DICT[status])
            except KeyError:
                raise VirgilCryptoRatchetError("Unknown error")
