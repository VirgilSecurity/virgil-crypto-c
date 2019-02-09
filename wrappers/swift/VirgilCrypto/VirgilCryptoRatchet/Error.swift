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

/// Error codes
@objc(VSCRRatchetError) public enum RatchetError: Int, Error {

    /// Error during protobuf deserialization
    case protobufDecode = 1

    /// Message version doesn't match
    case messageVersionDoesnTMatch = 2

    /// Bad message type
    case badMessageType = 3

    /// AES error
    case aes = 4

    /// RNG failed
    case rngFailed = 5

    /// Curve25519 error
    case curve25519 = 6

    /// Key deserialization error
    case keyDeserialization = 7

    /// Invalid key type
    case invalidKeyType = 8

    /// Identity key doesn't match
    case identityKeyDoesntMatch = 9

    /// Message already decrypted
    case messageAlreadyDecrypted = 10

    /// Too many lost messages
    case tooManyLostMessages = 11

    /// Sender chain missing
    case senderChainMissing = 12

    /// Skipped message missing
    case skippedMessageMissing = 13

    /// Can't encrypt yet
    case canTEncryptYet = 14

    /// Exceeded max plain text len
    case exceededMaxPlainTextLen = 15

    /// Too many messages for sender chain
    case tooManyMessagesForSenderChain = 16

    /// Too many messages for receiver chain
    case tooManyMessagesForReceiverChain = 17

    /// Create enumeration value from the correspond C enumeration value.
    internal init(fromC error: vscr_error_t) {
        self.init(rawValue: Int(error.rawValue))!
    }

    /// Check given C error (result), and if it's not "success" then throw correspond exception.
    internal static func handleError(fromC code: vscr_error_t) throws {
        if code != vscr_SUCCESS {
            throw RatchetError(fromC: code)
        }
    }
}
