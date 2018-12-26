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

/// Provide serialization of algorithms
@objc(VSCFAlgInfoDerSerializer) public protocol AlgInfoDerSerializer : CContext {

    /// Serializer of algorithm information from public key in DER to buffer
    @objc func toDerData(algInfo: AlgInfo, derData: Data) throws -> Data
}

/// Implement interface methods
@objc(VSCFAlgInfoDerSerializerProxy) internal class AlgInfoDerSerializerProxy: NSObject, AlgInfoDerSerializer {

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

    /// Serializer of algorithm information from public key in DER to buffer
    @objc public func toDerData(algInfo: AlgInfo, derData: Data) throws -> Data {
        let derDataCount = len
        var derData = Data(count: derDataCount)
        var derDataBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(derDataBuf)
        }

        let proxyResult = derData.withUnsafeBytes({ (derDataPointer: UnsafePointer<byte>) -> vscf_error_t in
            derData.withUnsafeMutableBytes({ (derDataPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                vsc_buffer_init(derDataBuf)
                vsc_buffer_use(derDataBuf, derDataPointer, derDataCount)

                var derDataBuf = vsc_buffer_new_with_data(vsc_data(derDataPointer, derData.count))
                defer {
                    vsc_buffer_delete(derDataBuf)
                }
                return vscf_alg_info_der_serializer_to_der_data(self.c_ctx, algInfo.c_ctx, derDataBuf)
            })
        })
        derData.count = vsc_buffer_len(derDataBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return derData
    }
}
