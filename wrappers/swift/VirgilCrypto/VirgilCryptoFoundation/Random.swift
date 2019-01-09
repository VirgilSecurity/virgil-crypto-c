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

/// Common interface to get random data.
@objc(VSCFRandom) public protocol Random : CContext {

    /// Generate random bytes.
    @objc func random(dataLen: Int) throws -> Data

    /// Retreive new seed data from the entropy sources.
    @objc func reseed() throws
}

/// Implement interface methods
@objc(VSCFRandomProxy) internal class RandomProxy: NSObject, Random {

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

    /// Generate random bytes.
    @objc public func random(dataLen: Int) throws -> Data {
        let dataCount = dataLen
        var data = Data(count: dataCount)
        var dataBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(dataBuf)
        }

        let proxyResult = data.withUnsafeMutableBytes({ (dataPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
            vsc_buffer_init(dataBuf)
            vsc_buffer_use(dataBuf, dataPointer, dataCount)
            return vscf_random(self.c_ctx, dataLen, dataBuf)
        })
        data.count = vsc_buffer_len(dataBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return data
    }

    /// Retreive new seed data from the entropy sources.
    @objc public func reseed() throws {
        let proxyResult = vscf_random_reseed(self.c_ctx)

        try FoundationError.handleError(fromC: proxyResult)
    }
}
