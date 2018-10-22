/// Copyright (C) 2015-2018 Virgil Security Inc.
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
import VSCFoundation

/// Defines library error codes.
@objc(VSCFFoundationError) public enum FoundationError: Int, Error {

    /// This error should not be returned if assertions is enabled.
    case badArguments = -1

    /// Can be used to define that not all context prerequisites are satisfied.
    /// Note, this error should not be returned if assertions is enabled.
    case uninitialized = -2

    /// Define that error code from one of third-party module was not handled.
    /// Note, this error should not be returned if assertions is enabled.
    case unhandledThirdpartyError = -3

    /// Buffer capacity is not enaugh to hold result.
    case smallBuffer = -101

    /// Authentication failed during decryption.
    case authFailed = -201

    /// Attempt to read data out of buffer bounds.
    case outOfData = -202

    /// ASN.1 encoded data is corrupted.
    case badAsn1 = -203

    /// Attempt to read ASN.1 type that is bigger then requested C type.
    case asn1LossyTypeNarrowing = -204

    /// ASN.1 representation of PKCS#1 public key is corrupted.
    case badPkcs1PublicKey = -205

    /// ASN.1 representation of PKCS#1 private key is corrupted.
    case badPkcs1PrivateKey = -206

    /// Encrypted data is corrupted.
    case badEncryptedData = -207

    /// Underlying random operation returns error.
    case randomFailed = -208

    /// Generation of the private or secret key failed.
    case keyGenerationFailed = -209

    /// Create enumeration value from the correspond C enumeration value.
    internal init(fromC error: vscf_error_t) {
        self.init(rawValue: Int(error.rawValue))!
    }

    /// Check given C error (result), and if it's not "success" then throw correspond exception.
    internal static func handleError(fromC code: vscf_error_t) throws {
        if code != vscf_SUCCESS {
            throw FoundationError(fromC: code)
        }
    }
}
