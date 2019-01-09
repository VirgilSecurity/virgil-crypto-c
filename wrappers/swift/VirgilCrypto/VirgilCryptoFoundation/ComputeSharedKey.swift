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
import VirgilCryptoCommon

/// Provide interface to compute shared key for 2 asymmetric keys.
/// Assume that this interface is implemented on the private key.
@objc(VSCFComputeSharedKey) public protocol ComputeSharedKey : CContext {

    /// Compute shared key for 2 asymmetric keys.
    /// Note, shared key can be used only for symmetric cryptography.
    @objc func computeSharedKey(publicKey: PublicKey) throws -> Data

    /// Return number of bytes required to hold shared key.
    @objc func sharedKeyLen() -> Int
}

/// Implement interface methods
@objc(VSCFComputeSharedKeyProxy) internal class ComputeSharedKeyProxy: NSObject, ComputeSharedKey {

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

    /// Compute shared key for 2 asymmetric keys.
    /// Note, shared key can be used only for symmetric cryptography.
    @objc public func computeSharedKey(publicKey: PublicKey) throws -> Data {
        let sharedKeyCount = self.sharedKeyLen()
        var sharedKey = Data(count: sharedKeyCount)
        var sharedKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(sharedKeyBuf)
        }

        let proxyResult = sharedKey.withUnsafeMutableBytes({ (sharedKeyPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
            vsc_buffer_init(sharedKeyBuf)
            vsc_buffer_use(sharedKeyBuf, sharedKeyPointer, sharedKeyCount)
            return vscf_compute_shared_key(self.c_ctx, publicKey.c_ctx, sharedKeyBuf)
        })
        sharedKey.count = vsc_buffer_len(sharedKeyBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return sharedKey
    }

    /// Return number of bytes required to hold shared key.
    @objc public func sharedKeyLen() -> Int {
        let proxyResult = vscf_compute_shared_key_shared_key_len(self.c_ctx)

        return proxyResult
    }
}
