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

/// Handle information about recipient that is defined by a password.
@objc(VSCFPasswordRecipientInfo) public class PasswordRecipientInfo: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_password_recipient_info_new()
        super.init()
    }

    /// Acquire C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Acquire retained C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_password_recipient_info_shallow_copy(c_ctx)
        super.init()
    }

    /// Create object and define all properties.
    public init(keyEncryptionAlgorithm: AlgInfo, encryptedKey: Data) {
        let proxyResult = encryptedKey.withUnsafeBytes({ (encryptedKeyPointer: UnsafePointer<byte>) -> OpaquePointer? in

            var keyEncryptionAlgorithmCopy = vscf_impl_shallow_copy(keyEncryptionAlgorithm.c_ctx)

            return vscf_password_recipient_info_new_with_members(&keyEncryptionAlgorithmCopy, vsc_data(encryptedKeyPointer, encryptedKey.count))
        })

        self.c_ctx = proxyResult!
    }

    /// Release underlying C context.
    deinit {
        vscf_password_recipient_info_delete(self.c_ctx)
    }

    /// Return algorithm information that was used for encryption
    /// a data encryption key.
    @objc public func keyEncryptionAlgorithm() -> AlgInfo {
        let proxyResult = vscf_password_recipient_info_key_encryption_algorithm(self.c_ctx)

        return AlgInfoProxy.init(c_ctx: proxyResult!)
    }

    /// Return an encrypted data encryption key.
    @objc public func encryptedKey() -> Data {
        let proxyResult = vscf_password_recipient_info_encrypted_key(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }
}
