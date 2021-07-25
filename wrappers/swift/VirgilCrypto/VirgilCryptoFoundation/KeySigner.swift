/// Copyright (C) 2015-2021 Virgil Security, Inc.
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

/// Provide an interface for signing and verifying data digest
/// with asymmetric keys.
@objc(VSCFKeySigner) public protocol KeySigner : KeyAlg {

    /// Check if algorithm can sign data digest with a given key.
    @objc func canSign(privateKey: PrivateKey) -> Bool

    /// Return length in bytes required to hold signature.
    /// Return zero if a given private key can not produce signatures.
    @objc func signatureLen(privateKey: PrivateKey) -> Int

    /// Sign data digest with a given private key.
    @objc func signHash(privateKey: PrivateKey, hashId: AlgId, digest: Data) throws -> Data

    /// Check if algorithm can verify data digest with a given key.
    @objc func canVerify(publicKey: PublicKey) -> Bool

    /// Verify data digest with a given public key and signature.
    @objc func verifyHash(publicKey: PublicKey, hashId: AlgId, digest: Data, signature: Data) -> Bool
}
