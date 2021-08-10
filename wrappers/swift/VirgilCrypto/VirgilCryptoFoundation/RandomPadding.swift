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

/// Append a random number of padding bytes to a data.
@objc(VSCFRandomPadding) public class RandomPadding: NSObject, Alg, Padding {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_random_padding_new()
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
        self.c_ctx = vscf_random_padding_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_random_padding_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_random_padding_release_random(self.c_ctx)
        vscf_random_padding_use_random(self.c_ctx, random.c_ctx)
    }

    /// Provide algorithm identificator.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_random_padding_alg_id(self.c_ctx)

        return AlgId.init(fromC: proxyResult)
    }

    /// Produce object with algorithm information and configuration parameters.
    @objc public func produceAlgInfo() -> AlgInfo {
        let proxyResult = vscf_random_padding_produce_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(take: proxyResult!)
    }

    /// Restore algorithm configuration from the given object.
    @objc public func restoreAlgInfo(algInfo: AlgInfo) throws {
        let proxyResult = vscf_random_padding_restore_alg_info(self.c_ctx, algInfo.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Set new padding parameters.
    @objc public func configure(params: PaddingParams) {
        vscf_random_padding_configure(self.c_ctx, params.c_ctx)
    }

    /// Return length in bytes of a data with a padding.
    @objc public func paddedDataLen(dataLen: Int) -> Int {
        let proxyResult = vscf_random_padding_padded_data_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return an actual number of padding in bytes.
    /// Note, this method might be called right before "finish data processing".
    @objc public func len() -> Int {
        let proxyResult = vscf_random_padding_len(self.c_ctx)

        return proxyResult
    }

    /// Return a maximum number of padding in bytes.
    @objc public func lenMax() -> Int {
        let proxyResult = vscf_random_padding_len_max(self.c_ctx)

        return proxyResult
    }

    /// Prepare the algorithm to process data.
    @objc public func startDataProcessing() {
        vscf_random_padding_start_data_processing(self.c_ctx)
    }

    /// Only data length is needed to produce padding later.
    /// Return data that should be further proceeded.
    @objc public func processData(data: Data) -> Data {
        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) in

            return vscf_random_padding_process_data(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count))
        })

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Accomplish data processing and return padding.
    @objc public func finishDataProcessing() throws -> Data {
        let outCount = self.len()
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_random_padding_finish_data_processing(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Prepare the algorithm to process padded data.
    @objc public func startPaddedDataProcessing() {
        vscf_random_padding_start_padded_data_processing(self.c_ctx)
    }

    /// Process padded data.
    /// Return filtered data without padding.
    @objc public func processPaddedData(data: Data) -> Data {
        let outCount = data.count
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> Void in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> Void in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                vscf_random_padding_process_padded_data(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        return out
    }

    /// Return length in bytes required hold output of the method
    /// "finish padded data processing".
    @objc public func finishPaddedDataProcessingOutLen() -> Int {
        let proxyResult = vscf_random_padding_finish_padded_data_processing_out_len(self.c_ctx)

        return proxyResult
    }

    /// Accomplish padded data processing and return left data without a padding.
    @objc public func finishPaddedDataProcessing() throws -> Data {
        let outCount = self.finishPaddedDataProcessingOutLen()
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_random_padding_finish_padded_data_processing(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }
}
