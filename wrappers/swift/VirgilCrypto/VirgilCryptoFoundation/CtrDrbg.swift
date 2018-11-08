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

/// Implementation of the RNG using deterministic random bit generators
/// based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
@objc(VSCFCtrDrbg) public class CtrDrbg: NSObject, Random {

    /// The interval before reseed is performed by default.
    @objc public let reseedInterval: Int = 10000

    /// The amount of entropy used per seed by default.
    @objc public let entropyLen: Int = 48

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_ctr_drbg_new()
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
        self.c_ctx = vscf_ctr_drbg_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_ctr_drbg_delete(self.c_ctx)
    }

    @objc public func setEntropySource(entropySource: EntropySource) {
        vscf_ctr_drbg_release_entropy_source(self.c_ctx)
        let proxyResult = vscf_ctr_drbg_use_entropy_source(self.c_ctx, entropySource.c_ctx)
        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Setup entropy sources available for the current system.
    @objc public func setupDefaults() {
        vscf_ctr_drbg_setup_defaults(self.c_ctx)
    }

    /// Force entropy to be gathered at the beginning of every call to
    /// the random() method.
    /// Note, use this if your entropy source has sufficient throughput.
    @objc public func enablePredictionResistance() {
        vscf_ctr_drbg_enable_prediction_resistance(self.c_ctx)
    }

    /// Sets the reseed interval.
    /// Default value is reseed interval.
    @objc public func setReseedInterval(interval: Int) {
        vscf_ctr_drbg_set_reseed_interval(self.c_ctx, interval)
    }

    /// Sets the amount of entropy grabbed on each seed or reseed.
    /// The default value is entropy len.
    @objc public func setEntropyLen(len: Int) {
        vscf_ctr_drbg_set_entropy_len(self.c_ctx, len)
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
            return vscf_ctr_drbg_random(self.c_ctx, dataLen, dataBuf)
        })
        data.count = vsc_buffer_len(dataBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return data
    }

    /// Retreive new seed data from the entropy sources.
    @objc public func reseed() throws {
        let proxyResult = vscf_ctr_drbg_reseed(self.c_ctx)

        try FoundationError.handleError(fromC: proxyResult)
    }
}
