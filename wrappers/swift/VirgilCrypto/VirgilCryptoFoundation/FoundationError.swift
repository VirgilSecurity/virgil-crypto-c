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
import VSCFoundation

/// Defines the library status codes.
@objc(VSCFFoundationError) public enum FoundationError: Int, Error {

    /// This error should not be returned if assertions is enabled.
    case errorBadArguments = -1

    /// Can be used to define that not all context prerequisites are satisfied.
    /// Note, this error should not be returned if assertions is enabled.
    case errorUninitialized = -2

    /// Define that error code from one of third-party module was not handled.
    /// Note, this error should not be returned if assertions is enabled.
    case errorUnhandledThirdpartyError = -3

    /// Buffer capacity is not enough to hold result.
    case errorSmallBuffer = -101

    /// Unsupported algorithm.
    case errorUnsupportedAlgorithm = -200

    /// Authentication failed during decryption.
    case errorAuthFailed = -201

    /// Attempt to read data out of buffer bounds.
    case errorOutOfData = -202

    /// ASN.1 encoded data is corrupted.
    case errorBadAsn1 = -203

    /// Attempt to read ASN.1 type that is bigger then requested C type.
    case errorAsn1LossyTypeNarrowing = -204

    /// ASN.1 representation of PKCS#1 public key is corrupted.
    case errorBadPkcs1PublicKey = -205

    /// ASN.1 representation of PKCS#1 private key is corrupted.
    case errorBadPkcs1PrivateKey = -206

    /// ASN.1 representation of PKCS#8 public key is corrupted.
    case errorBadPkcs8PublicKey = -207

    /// ASN.1 representation of PKCS#8 private key is corrupted.
    case errorBadPkcs8PrivateKey = -208

    /// Encrypted data is corrupted.
    case errorBadEncryptedData = -209

    /// Underlying random operation returns error.
    case errorRandomFailed = -210

    /// Generation of the private or secret key failed.
    case errorKeyGenerationFailed = -211

    /// One of the entropy sources failed.
    case errorEntropySourceFailed = -212

    /// Requested data to be generated is too big.
    case errorRngRequestedDataTooBig = -213

    /// Base64 encoded string contains invalid characters.
    case errorBadBase64 = -214

    /// PEM data is corrupted.
    case errorBadPem = -215

    /// Exchange key return zero.
    case errorSharedKeyExchangeFailed = -216

    /// Ed25519 public key is corrupted.
    case errorBadEd25519PublicKey = -217

    /// Ed25519 private key is corrupted.
    case errorBadEd25519PrivateKey = -218

    /// CURVE25519 public key is corrupted.
    case errorBadCurve25519PublicKey = -219

    /// CURVE25519 private key is corrupted.
    case errorBadCurve25519PrivateKey = -220

    /// Elliptic curve public key format is corrupted see RFC 5480.
    case errorBadSec1PublicKey = -221

    /// Elliptic curve public key format is corrupted see RFC 5915.
    case errorBadSec1PrivateKey = -222

    /// ASN.1 representation of a public key is corrupted.
    case errorBadDerPublicKey = -223

    /// ASN.1 representation of a private key is corrupted.
    case errorBadDerPrivateKey = -224

    /// Decryption failed, because message info was not given explicitly,
    /// and was not part of an encrypted message.
    case errorNoMessageInfo = -301

    /// Message info is corrupted.
    case errorBadMessageInfo = -302

    /// Recipient defined with id is not found within message info
    /// during data decryption.
    case errorKeyRecipientIsNotFound = -303

    /// Content encryption key can not be decrypted with a given private key.
    case errorKeyRecipientPrivateKeyIsWrong = -304

    /// Content encryption key can not be decrypted with a given password.
    case errorPasswordRecipientPasswordIsWrong = -305

    /// Custom parameter with a given key is not found within message info.
    case errorMessageInfoCustomParamNotFound = -306

    /// A custom parameter with a given key is found, but the requested value
    /// type does not correspond to the actual type.
    case errorMessageInfoCustomParamTypeMismatch = -307

    /// Signature format is corrupted.
    case errorBadSignature = -308

    /// Brainkey password length is out of range.
    case errorInvalidBrainkeyPasswordLen = -401

    /// Brainkey number length should be 32 byte.
    case errorInvalidBrainkeyFactorLen = -402

    /// Brainkey point length should be 65 bytes.
    case errorInvalidBrainkeyPointLen = -403

    /// Brainkey name is out of range.
    case errorInvalidBrainkeyKeyNameLen = -404

    /// Brainkey internal error.
    case errorBrainkeyInternal = -405

    /// Brainkey point is invalid.
    case errorBrainkeyInvalidPoint = -406

    /// Brainkey number buffer length capacity should be >= 32 byte.
    case errorInvalidBrainkeyFactorBufferLen = -407

    /// Brainkey point buffer length capacity should be >= 32 byte.
    case errorInvalidBrainkeyPointBufferLen = -408

    /// Brainkey seed buffer length capacity should be >= 32 byte.
    case errorInvalidBrainkeySeedBufferLen = -409

    /// Brainkey identity secret is invalid.
    case errorInvalidIdentitySecret = -410

    /// Invalid padding.
    case errorInvalidPadding = -501

    /// Create enumeration value from the correspond C enumeration value.
    internal init(fromC status: vscf_status_t) {
        self.init(rawValue: Int(status.rawValue))!
    }

    /// Check given C status, and if it's not "success" then throw correspond exception.
    internal static func handleStatus(fromC code: vscf_status_t) throws {
        if code != vscf_status_SUCCESS {
            throw FoundationError(fromC: code)
        }
    }
}
