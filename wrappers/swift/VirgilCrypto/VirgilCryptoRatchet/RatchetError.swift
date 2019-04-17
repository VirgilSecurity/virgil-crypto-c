/// Copyright (C) 2015-2019 Virgil Security, Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
///     (1) Redistributions of source code must retain the above copyright
///     notice, this list of conditions and the following disclaimer.
///
///     (2) Redistributions in binary form must reproduce the above copyright
///     notice, this list of conditions and the following disclaimer in
///     the documentation and/or other materials provided with the
///     distribution.
///
///     (3) Neither the name of the copyright holder nor the names of its
///     contributors may be used to endorse or promote products derived from
///     this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
/// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
/// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
/// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
/// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
/// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
/// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
/// POSSIBILITY OF SUCH DAMAGE.
///
/// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


import Foundation
import VSCRatchet

/// Defines the library status codes.
@objc(VSCRRatchetError) public enum RatchetError: Int, Error {

    /// Error during protobuf deserialization.
    case errorProtobufDecode = -1

    /// Message version doesn't match.
    case errorMessageVersionDoesnTMatch = -2

    /// Bad message type.
    case errorBadMessageType = -3

    /// AES error.
    case errorAes = -4

    /// RNG failed.
    case errorRngFailed = -5

    /// Curve25519 error.
    case errorCurve25519 = -6

    /// Curve25519 error.
    case errorEd25519 = -7

    /// Key deserialization failed.
    case errorKeyDeserializationFailed = -8

    /// Invalid key type.
    case errorInvalidKeyType = -9

    /// Identity key doesn't match.
    case errorIdentityKeyDoesntMatch = -10

    /// Message already decrypted.
    case errorMessageAlreadyDecrypted = -11

    /// Too many lost messages.
    case errorTooManyLostMessages = -12

    /// Sender chain missing.
    case errorSenderChainMissing = -13

    /// Skipped message missing.
    case errorSkippedMessageMissing = -14

    /// Session is not initialized.
    case errorSessionIsNotInitialized = -15

    /// Exceeded max plain text len.
    case errorExceededMaxPlainTextLen = -16

    /// Too many messages for sender chain.
    case errorTooManyMessagesForSenderChain = -17

    /// Too many messages for receiver chain.
    case errorTooManyMessagesForReceiverChain = -18

    /// Invalid padding.
    case errorInvalidPadding = -19

    /// Too many participants.
    case errorTooManyParticipants = -20

    /// Too few participants.
    case errorTooFewParticipants = -21

    /// Sender not found.
    case errorSenderNotFound = -22

    /// Cannot decrypt own messages.
    case errorCannotDecryptOwnMessages = -23

    /// Duplicate id.
    case errorDuplicateId = -24

    /// Invalid signature.
    case errorInvalidSignature = -25

    /// User is not present in group message.
    case errorUserIsNotPresentInGroupMessage = -26

    /// Epoch mismatch.
    case errorEpochMismatch = -27

    /// Participant not found.
    case errorParticipantNotFound = -28

    /// Epoch not found.
    case errorEpochNotFound = -29

    /// Session id mismatch.
    case errorSessionIdMismatch = -30

    /// Create enumeration value from the correspond C enumeration value.
    internal init(fromC status: vscr_status_t) {
        self.init(rawValue: Int(status.rawValue))!
    }

    /// Check given C status, and if it's not "success" then throw correspond exception.
    internal static func handleStatus(fromC code: vscr_status_t) throws {
        if code != vscr_status_SUCCESS {
            throw RatchetError(fromC: code)
        }
    }
}
