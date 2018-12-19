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
import VirgilCryptoCommon

/// Random number generator that is used for test purposes only.
@objc(VSCFFakeRandom) public class FakeRandom: NSObject, Random, EntropySource {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_fake_random_new()
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
        self.c_ctx = vscf_fake_random_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_fake_random_delete(self.c_ctx)
    }

    /// Configure random number generator to generate sequence filled with given byte.
    @objc public func setupSourceByte(byteSource: UInt8) {
        vscf_fake_random_setup_source_byte(self.c_ctx, byteSource)
    }

    /// Configure random number generator to generate random sequence from given data.
    /// Note, that given data is used as circular source.
    @objc public func setupSourceData(dataSource: Data) {
        dataSource.withUnsafeBytes({ (dataSourcePointer: UnsafePointer<byte>) -> Void in
            vscf_fake_random_setup_source_data(self.c_ctx, vsc_data(dataSourcePointer, dataSource.count))
        })
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
            return vscf_fake_random_random(self.c_ctx, dataLen, dataBuf)
        })
        data.count = vsc_buffer_len(dataBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return data
    }

    /// Retreive new seed data from the entropy sources.
    @objc public func reseed() throws {
        let proxyResult = vscf_fake_random_reseed(self.c_ctx)

        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Defines that implemented source is strong.
    @objc public func isStrong() -> Bool {
        let proxyResult = vscf_fake_random_is_strong(self.c_ctx)

        return proxyResult
    }

    /// Gather entropy of the requested length.
    @objc public func gather(len: Int) throws -> Data {
        let outCount = len
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)
            return vscf_fake_random_gather(self.c_ctx, len, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }
}
