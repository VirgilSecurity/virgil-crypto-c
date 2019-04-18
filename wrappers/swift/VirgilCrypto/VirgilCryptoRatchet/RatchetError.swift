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

    /// Bad message type.
    case errorBadMessageType = -2

    /// AES error.
    case errorAes = -3

    /// RNG failed.
    case errorRngFailed = -4

    /// Curve25519 error.
    case errorCurve25519 = -5

    /// Curve25519 error.
    case errorEd25519 = -6

    /// Key deserialization failed.
    case errorKeyDeserializationFailed = -7

    /// Invalid key type.
    case errorInvalidKeyType = -8

    /// Identity key doesn't match.
    case errorIdentityKeyDoesntMatch = -9

    /// Message already decrypted.
    case errorMessageAlreadyDecrypted = -10

    /// Too many lost messages.
    case errorTooManyLostMessages = -11

    /// Sender chain missing.
    case errorSenderChainMissing = -12

    /// Skipped message missing.
    case errorSkippedMessageMissing = -13

    /// Session is not initialized.
    case errorSessionIsNotInitialized = -14

    /// Exceeded max plain text len.
    case errorExceededMaxPlainTextLen = -15

    /// Too many messages for sender chain.
    case errorTooManyMessagesForSenderChain = -16

    /// Too many messages for receiver chain.
    case errorTooManyMessagesForReceiverChain = -17

    /// Invalid padding.
    case errorInvalidPadding = -18

    /// Too many participants.
    case errorTooManyParticipants = -19

    /// Too few participants.
    case errorTooFewParticipants = -20

    /// Sender not found.
    case errorSenderNotFound = -21

    /// Cannot decrypt own messages.
    case errorCannotDecryptOwnMessages = -22

    /// Duplicate id.
    case errorDuplicateId = -23

    /// Invalid signature.
    case errorInvalidSignature = -24

    /// User is not present in group message.
    case errorUserIsNotPresentInGroupMessage = -25

    /// Epoch mismatch.
    case errorEpochMismatch = -26

    /// Participant not found.
    case errorParticipantNotFound = -27

    /// Epoch not found.
    case errorEpochNotFound = -28

    /// Session id mismatch.
    case errorSessionIdMismatch = -29

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
