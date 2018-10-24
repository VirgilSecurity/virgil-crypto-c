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

/// Provide interface for signing data with private key.
@objc(VSCFSign) public protocol Sign : CProtocol {

    @objc func sign(data: Data) throws -> Data

    @objc func signatureLen() -> Int
}

/// Implement interface methods
@objc(VSCFSignProxy) internal class SignProxy: NSObject, Sign {

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

    /// Sign data given private key.
    @objc public func sign(data: Data) throws -> Data {
        let signatureCount = self.signatureLen()
        var signature = Data(count: signatureCount)
        var signatureBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(signatureBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            signature.withUnsafeMutableBytes({ (signaturePointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                vsc_buffer_init(signatureBuf)
                vsc_buffer_use(signatureBuf, signaturePointer, signatureCount)
                return vscf_sign(self.c_ctx, vsc_data(dataPointer, data.count), signatureBuf)
            })
        })

        try! FoundationError.handleError(fromC: proxyResult)

        return signature
    }

    /// Return length in bytes required to hold signature.
    @objc public func signatureLen() -> Int {
        let proxyResult = vscf_sign_signature_len(self.c_ctx)
        return proxyResult
    }
}
