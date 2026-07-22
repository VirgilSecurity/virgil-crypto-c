// Copyright (C) 2015-2026 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#pragma once

#include <cstdint>

namespace virgil::crypto::ratchet {

/// Runtime error reported by the C++ SDK (maps the C status codes).
/// Only recoverable C status codes appear here; C assertions abort and
/// are never surfaced as an Error.
enum class Error : int {
    /// Error during protobuf deserialization.
    ProtobufDecode = -1,
    /// Bad message type.
    BadMessageType = -2,
    /// AES error.
    Aes = -3,
    /// RNG failed.
    RngFailed = -4,
    /// Curve25519 error.
    Curve25519 = -5,
    /// Curve25519 error.
    Ed25519 = -6,
    /// Key deserialization failed.
    KeyDeserializationFailed = -7,
    /// Invalid key type.
    InvalidKeyType = -8,
    /// Identity key doesn't match.
    IdentityKeyDoesntMatch = -9,
    /// Message already decrypted.
    MessageAlreadyDecrypted = -10,
    /// Too many lost messages.
    TooManyLostMessages = -11,
    /// Sender chain missing.
    SenderChainMissing = -12,
    /// Skipped message missing.
    SkippedMessageMissing = -13,
    /// Session is not initialized.
    SessionIsNotInitialized = -14,
    /// Exceeded max plain text len.
    ExceededMaxPlainTextLen = -15,
    /// Too many messages for sender chain.
    TooManyMessagesForSenderChain = -16,
    /// Too many messages for receiver chain.
    TooManyMessagesForReceiverChain = -17,
    /// Invalid padding.
    InvalidPadding = -18,
    /// Too many participants.
    TooManyParticipants = -19,
    /// Too few participants.
    TooFewParticipants = -20,
    /// Sender not found.
    SenderNotFound = -21,
    /// Cannot decrypt own messages.
    CannotDecryptOwnMessages = -22,
    /// Invalid signature.
    InvalidSignature = -23,
    /// Cannot remove myself.
    CannotRemoveMyself = -24,
    /// Epoch mismatch.
    EpochMismatch = -25,
    /// Epoch not found.
    EpochNotFound = -26,
    /// Session id mismatch.
    SessionIdMismatch = -27,
    /// Simultaneous group user operation.
    SimultaneousGroupUserOperation = -28,
    /// Myself is included in info.
    MyselfIsIncludedInInfo = -29,
    /// KEM encapsulate or decapsulate operation failed.
    KemFailed = -30,
    /// Signing operation failed.
    SignFailed = -31,
    /// Decaps signature is invalid.
    DecapsSignatureInvalid = -32,
};

}  // namespace virgil::crypto::ratchet
