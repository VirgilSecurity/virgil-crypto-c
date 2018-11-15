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

/// Implements PKCS#8 key serialzation to DER format.
@objc(VSCFPkcs8DerSerializer) public class Pkcs8DerSerializer: NSObject, KeySerializer {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_pkcs8_der_serializer_new()
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
        self.c_ctx = vscf_pkcs8_der_serializer_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_pkcs8_der_serializer_delete(self.c_ctx)
    }

    /// Calculate buffer size enough to hold serialized public key.
    ///
    /// Precondition: public key must be exportable.
    @objc public func serializedPublicKeyLen(publicKey: PublicKey) -> Int {
        let proxyResult = vscf_pkcs8_der_serializer_serialized_public_key_len(self.c_ctx, publicKey.c_ctx)

        return proxyResult
    }

    /// Serialize given public key to an interchangeable format.
    ///
    /// Precondition: public key must be exportable.
    @objc public func serializePublicKey(publicKey: PublicKey) throws -> Data {
        let outCount = self.serializedPublicKeyLen(publicKey: publicKey)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)
            return vscf_pkcs8_der_serializer_serialize_public_key(self.c_ctx, publicKey.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Calculate buffer size enough to hold serialized private key.
    ///
    /// Precondition: private key must be exportable.
    @objc public func serializedPrivateKeyLen(privateKey: PrivateKey) -> Int {
        let proxyResult = vscf_pkcs8_der_serializer_serialized_private_key_len(self.c_ctx, privateKey.c_ctx)

        return proxyResult
    }

    /// Serialize given private key to an interchangeable format.
    ///
    /// Precondition: private key must be exportable.
    @objc public func serializePrivateKey(privateKey: PrivateKey) throws -> Data {
        let outCount = self.serializedPrivateKeyLen(privateKey: privateKey)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)
            return vscf_pkcs8_der_serializer_serialize_private_key(self.c_ctx, privateKey.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }
}
