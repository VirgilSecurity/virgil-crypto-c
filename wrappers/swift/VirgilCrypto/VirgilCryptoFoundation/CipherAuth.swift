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

/// Mix-in interface that provides specific functionality to authenticated
/// encryption and decryption (AEAD ciphers).
@objc(VSCFCipherAuth) public protocol CipherAuth : Cipher, AuthEncrypt, AuthDecrypt {

    /// Set additional data for for AEAD ciphers.
    @objc func setAuthData(authData: Data)

    /// Accomplish an authenticated encryption and place tag separately.
    ///
    /// Note, if authentication tag should be added to an encrypted data,
    /// method "finish" can be used.
    @objc func finishAuthEncryption() throws -> CipherAuthFinishAuthEncryptionResult

    /// Accomplish an authenticated decryption with explicitly given tag.
    ///
    /// Note, if authentication tag is a part of an encrypted data then,
    /// method "finish" can be used for simplicity.
    @objc func finishAuthDecryption(tag: Data) throws -> Data
}

/// Encapsulate result of method CipherAuth.finishAuthEncryption()
@objc(VSCFCipherAuthFinishAuthEncryptionResult) public class CipherAuthFinishAuthEncryptionResult: NSObject {

    @objc public let out: Data

    @objc public let tag: Data

    /// Initialize all properties.
    internal init(out: Data, tag: Data) {
        self.out = out
        self.tag = tag
        super.init()
    }
}
