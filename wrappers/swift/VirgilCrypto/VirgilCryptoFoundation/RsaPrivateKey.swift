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

/// Handles RSA private key.
@objc(VSCFRsaPrivateKey) public class RsaPrivateKey: NSObject, Key, PrivateKey {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_rsa_private_key_new()
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
        self.c_ctx = vscf_rsa_private_key_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_rsa_private_key_delete(self.c_ctx)
    }

    /// Algorithm identifier the key belongs to.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_rsa_private_key_alg_id(self.c_ctx)

        return AlgId.init(fromC: proxyResult)
    }

    /// Return algorithm information that can be used for serialization.
    @objc public func algInfo() -> AlgInfo {
        let proxyResult = vscf_rsa_private_key_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(use: proxyResult!)
    }

    /// Length of the key in bytes.
    @objc public func len() -> Int {
        let proxyResult = vscf_rsa_private_key_len(self.c_ctx)

        return proxyResult
    }

    /// Length of the key in bits.
    @objc public func bitlen() -> Int {
        let proxyResult = vscf_rsa_private_key_bitlen(self.c_ctx)

        return proxyResult
    }

    /// Check that key is valid.
    /// Note, this operation can be slow.
    @objc public func isValid() -> Bool {
        let proxyResult = vscf_rsa_private_key_is_valid(self.c_ctx)

        return proxyResult
    }

    /// Extract public key from the private key.
    @objc public func extractPublicKey() -> PublicKey {
        let proxyResult = vscf_rsa_private_key_extract_public_key(self.c_ctx)

        return FoundationImplementation.wrapPublicKey(take: proxyResult!)
    }
}
