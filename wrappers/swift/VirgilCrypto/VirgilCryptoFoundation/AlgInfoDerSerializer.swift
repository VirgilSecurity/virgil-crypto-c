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

/// Provide DER serializer of algorithm information.
@objc(VSCFAlgInfoDerSerializer) public class AlgInfoDerSerializer: NSObject, Defaults, AlgInfoSerializer {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_alg_info_der_serializer_new()
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
        self.c_ctx = vscf_alg_info_der_serializer_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_alg_info_der_serializer_delete(self.c_ctx)
    }

    @objc public func setAsn1Writer(asn1Writer: Asn1Writer) {
        vscf_alg_info_der_serializer_release_asn1_writer(self.c_ctx)
        vscf_alg_info_der_serializer_use_asn1_writer(self.c_ctx, asn1Writer.c_ctx)
    }

    /// Serialize by using internal ASN.1 writer.
    /// Note, that caller code is responsible to reset ASN.1 writer with
    /// an output buffer.
    @objc public func serializeInplace(algInfo: AlgInfo) -> Int {
        let proxyResult = vscf_alg_info_der_serializer_serialize_inplace(self.c_ctx, algInfo.c_ctx)

        return proxyResult
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_alg_info_der_serializer_setup_defaults(self.c_ctx)

        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Return buffer size enough to hold serialized algorithm.
    @objc public func serializedLen(algInfo: AlgInfo) -> Int {
        let proxyResult = vscf_alg_info_der_serializer_serialized_len(self.c_ctx, algInfo.c_ctx)

        return proxyResult
    }

    /// Serialize algorithm info to buffer class.
    @objc public func serialize(algInfo: AlgInfo) -> Data {
        let outCount = self.serializedLen(algInfo: algInfo)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> Void in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)
            vscf_alg_info_der_serializer_serialize(self.c_ctx, algInfo.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        return out
    }
}
