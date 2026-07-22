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

namespace virgil::crypto::foundation {

/// Runtime error reported by the C++ SDK (maps the C status codes).
/// Only recoverable C status codes appear here; C assertions abort and
/// are never surfaced as an Error.
enum class Error : int {
    /// This error should not be returned if assertions is enabled.
    BadArguments = -1,
    /// Can be used to define that not all context prerequisites are satisfied.
    /// Note, this error should not be returned if assertions is enabled.
    Uninitialized = -2,
    /// Define that error code from one of third-party module was not handled.
    /// Note, this error should not be returned if assertions is enabled.
    UnhandledThirdpartyError = -3,
    /// Buffer capacity is not enough to hold result.
    SmallBuffer = -101,
    /// Unsupported algorithm.
    UnsupportedAlgorithm = -200,
    /// Authentication failed during decryption.
    AuthFailed = -201,
    /// Attempt to read data out of buffer bounds.
    OutOfData = -202,
    /// ASN.1 encoded data is corrupted.
    BadAsn1 = -203,
    /// Attempt to read ASN.1 type that is bigger then requested C type.
    Asn1LossyTypeNarrowing = -204,
    /// ASN.1 representation of PKCS#1 public key is corrupted.
    BadPkcs1PublicKey = -205,
    /// ASN.1 representation of PKCS#1 private key is corrupted.
    BadPkcs1PrivateKey = -206,
    /// ASN.1 representation of PKCS#8 public key is corrupted.
    BadPkcs8PublicKey = -207,
    /// ASN.1 representation of PKCS#8 private key is corrupted.
    BadPkcs8PrivateKey = -208,
    /// Encrypted data is corrupted.
    BadEncryptedData = -209,
    /// Underlying random operation returns error.
    RandomFailed = -210,
    /// Generation of the private or secret key failed.
    KeyGenerationFailed = -211,
    /// One of the entropy sources failed.
    EntropySourceFailed = -212,
    /// Requested data to be generated is too big.
    RngRequestedDataTooBig = -213,
    /// Base64 encoded string contains invalid characters.
    BadBase64 = -214,
    /// PEM data is corrupted.
    BadPem = -215,
    /// Exchange key return zero.
    SharedKeyExchangeFailed = -216,
    /// Ed25519 public key is corrupted.
    BadEd25519PublicKey = -217,
    /// Ed25519 private key is corrupted.
    BadEd25519PrivateKey = -218,
    /// CURVE25519 public key is corrupted.
    BadCurve25519PublicKey = -219,
    /// CURVE25519 private key is corrupted.
    BadCurve25519PrivateKey = -220,
    /// Elliptic curve public key format is corrupted see RFC 5480.
    BadSec1PublicKey = -221,
    /// Elliptic curve public key format is corrupted see RFC 5915.
    BadSec1PrivateKey = -222,
    /// ASN.1 representation of a public key is corrupted.
    BadDerPublicKey = -223,
    /// ASN.1 representation of a private key is corrupted.
    BadDerPrivateKey = -224,
    /// Key algorithm does not accept given type of public key.
    MismatchPublicKeyAndAlgorithm = -225,
    /// Key algorithm does not accept given type of private key.
    MismatchPrivateKeyAndAlgorithm = -226,
    /// Post-quantum Falcon-Sign public key is corrupted.
    BadFalconPublicKey = -227,
    /// Post-quantum Falcon-Sign private key is corrupted.
    BadFalconPrivateKey = -228,
    /// Compound public key is corrupted.
    BadCompoundPublicKey = -232,
    /// Compound private key is corrupted.
    BadCompoundPrivateKey = -233,
    /// Compound public hybrid key is corrupted.
    BadHybridPublicKey = -234,
    /// Compound private hybrid key is corrupted.
    BadHybridPrivateKey = -235,
    /// ASN.1 AlgorithmIdentifer is corrupted.
    BadAsn1Algorithm = -236,
    /// ASN.1 AlgorithmIdentifer with ECParameters is corrupted.
    BadAsn1AlgorithmEcc = -237,
    /// ASN.1 AlgorithmIdentifer with CompoundKeyParams is corrupted.
    BadAsn1AlgorithmCompoundKey = -238,
    /// ASN.1 AlgorithmIdentifer with HybridKeyParams is corrupted.
    BadAsn1AlgorithmHybridKey = -239,
    /// Post-quantum ML-KEM-768 public key is corrupted.
    BadMlKemPublicKey = -240,
    /// Post-quantum ML-KEM-768 private key is corrupted.
    BadMlKemPrivateKey = -241,
    /// Post-quantum ML-DSA-65 public key is corrupted.
    BadMlDsaPublicKey = -242,
    /// Post-quantum ML-DSA-65 private key is corrupted.
    BadMlDsaPrivateKey = -243,
    /// Decryption failed, because message info was not given explicitly,
    /// and was not part of an encrypted message.
    NoMessageInfo = -301,
    /// Message Info is corrupted.
    BadMessageInfo = -302,
    /// Recipient defined with id is not found within message info
    /// during data decryption.
    KeyRecipientIsNotFound = -303,
    /// Content encryption key can not be decrypted with a given private key.
    KeyRecipientPrivateKeyIsWrong = -304,
    /// Content encryption key can not be decrypted with a given password.
    PasswordRecipientPasswordIsWrong = -305,
    /// Custom parameter with a given key is not found within message info.
    MessageInfoCustomParamNotFound = -306,
    /// A custom parameter with a given key is found, but the requested value
    /// type does not correspond to the actual type.
    MessageInfoCustomParamTypeMismatch = -307,
    /// Signature format is corrupted.
    BadSignature = -308,
    /// Message Info footer is corrupted.
    BadMessageInfoFooter = -309,
    /// Chunk cipher frame counter limit is reached,
    /// so no more chunks can be processed under the same key and nonce.
    ChunkCounterLimitReached = -310,
    /// Content encryption key can not be decrypted with a given
    /// key encryption key (KEK).
    KeyRecipientKekIsWrong = -311,
    /// Brainkey password length is out of range.
    InvalidBrainkeyPasswordLen = -401,
    /// Brainkey number length should be 32 byte.
    InvalidBrainkeyFactorLen = -402,
    /// Brainkey point length should be 65 bytes.
    InvalidBrainkeyPointLen = -403,
    /// Brainkey name is out of range.
    InvalidBrainkeyKeyNameLen = -404,
    /// Brainkey internal error.
    BrainkeyInternal = -405,
    /// Brainkey point is invalid.
    BrainkeyInvalidPoint = -406,
    /// Brainkey number buffer length capacity should be >= 32 byte.
    InvalidBrainkeyFactorBufferLen = -407,
    /// Brainkey point buffer length capacity should be >= 32 byte.
    InvalidBrainkeyPointBufferLen = -408,
    /// Brainkey seed buffer length capacity should be >= 32 byte.
    InvalidBrainkeySeedBufferLen = -409,
    /// Brainkey identity secret is invalid.
    InvalidIdentitySecret = -410,
    /// KEM encapsulated key is invalid or does not correspond to the private key.
    InvalidKemEncapsulatedKey = -411,
    /// Invalid padding.
    InvalidPadding = -501,
    /// Protobuf error.
    Protobuf = -601,
    /// Session id doesnt match.
    SessionIdDoesntMatch = -701,
    /// Epoch not found.
    EpochNotFound = -702,
    /// Wrong key type.
    WrongKeyType = -703,
    /// Invalid signature.
    InvalidSignature = -704,
    /// Ed25519 error.
    Ed25519 = -705,
    /// Duplicate epoch.
    DuplicateEpoch = -706,
    /// Plain text too long.
    PlainTextTooLong = -707,
    /// Shamir secret-sharing recovery failed: the given shares are wrong,
    /// tampered, insufficient, or do not belong to the same split. Returned
    /// as a single generic code so that the failure cause cannot be probed.
    ShamirRecoveryFailed = -708,
};

}  // namespace virgil::crypto::foundation
