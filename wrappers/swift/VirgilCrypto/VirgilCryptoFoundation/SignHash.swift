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

/// Provide interface for signing data with private key.
@objc(VSCFSignHash) public protocol SignHash : CContext {

    /// Return length in bytes required to hold signature.
    @objc func signatureLen() -> Int

    /// Sign data given private key.
    @objc func signHash(hashDigest: Data, hashId: AlgId) throws -> Data
}

/// Implement interface methods
@objc(VSCFSignHashProxy) internal class SignHashProxy: NSObject, SignHash {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Take C context that implements this interface
    public init(c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_impl_delete(self.c_ctx)
    }

    /// Return length in bytes required to hold signature.
    @objc public func signatureLen() -> Int {
        let proxyResult = vscf_sign_hash_signature_len(self.c_ctx)

        return proxyResult
    }

    /// Sign data given private key.
    @objc public func signHash(hashDigest: Data, hashId: AlgId) throws -> Data {
        let signatureCount = self.signatureLen()
        var signature = Data(count: signatureCount)
        var signatureBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(signatureBuf)
        }

        let proxyResult = hashDigest.withUnsafeBytes({ (hashDigestPointer: UnsafePointer<byte>) -> vscf_status_t in
            signature.withUnsafeMutableBytes({ (signaturePointer: UnsafeMutablePointer<byte>) -> vscf_status_t in
                vsc_buffer_init(signatureBuf)
                vsc_buffer_use(signatureBuf, signaturePointer, signatureCount)

                return vscf_sign_hash(self.c_ctx, vsc_data(hashDigestPointer, hashDigest.count), vscf_alg_id_t(rawValue: UInt32(hashId.rawValue)), signatureBuf)
            })
        })
        signature.count = vsc_buffer_len(signatureBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return signature
    }
}
