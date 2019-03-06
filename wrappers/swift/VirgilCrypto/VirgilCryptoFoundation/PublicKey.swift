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

/// Contains public part of the key.
@objc(VSCFPublicKey) public protocol PublicKey : Key {
    /// Define whether a public key can be exported or not.
    @objc var canExportPublicKey: Bool { get }
    /// Defines whether a public key can be imported or not.
    @objc var canImportPublicKey: Bool { get }

    /// Export public key in the binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be exported in format defined in
    /// RFC 3447 Appendix A.1.1.
    @objc func exportPublicKey() throws -> Data

    /// Return length in bytes required to hold exported public key.
    @objc func exportedPublicKeyLen() -> Int

    /// Import public key from the binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.1.
    @objc func importPublicKey(data: Data) throws
}

/// Implement interface methods
@objc(VSCFPublicKeyProxy) internal class PublicKeyProxy: NSObject, PublicKey {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Define whether a public key can be exported or not.
    @objc public var canExportPublicKey: Bool {
        return vscf_public_key_can_export_public_key(vscf_public_key_api(self.c_ctx))
    }

    /// Defines whether a public key can be imported or not.
    @objc public var canImportPublicKey: Bool {
        return vscf_public_key_can_import_public_key(vscf_public_key_api(self.c_ctx))
    }

    /// Take C context that implements this interface
    public init(c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_impl_delete(self.c_ctx)
    }

    /// Provide algorithm identificator.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_alg_alg_id(self.c_ctx)

        return AlgId.init(fromC: proxyResult)
    }

    /// Produce object with algorithm information and configuration parameters.
    @objc public func produceAlgInfo() -> AlgInfo {
        let proxyResult = vscf_alg_produce_alg_info(self.c_ctx)

        return AlgInfoProxy.init(c_ctx: proxyResult!)
    }

    /// Restore algorithm configuration from the given object.
    @objc public func restoreAlgInfo(algInfo: AlgInfo) throws {
        let proxyResult = vscf_alg_restore_alg_info(self.c_ctx, algInfo.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Length of the key in bytes.
    @objc public func keyLen() -> Int {
        let proxyResult = vscf_key_key_len(self.c_ctx)

        return proxyResult
    }

    /// Length of the key in bits.
    @objc public func keyBitlen() -> Int {
        let proxyResult = vscf_key_key_bitlen(self.c_ctx)

        return proxyResult
    }

    /// Export public key in the binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be exported in format defined in
    /// RFC 3447 Appendix A.1.1.
    @objc public func exportPublicKey() throws -> Data {
        let outCount = self.exportedPublicKeyLen()
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_status_t in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)
            return vscf_public_key_export_public_key(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Return length in bytes required to hold exported public key.
    @objc public func exportedPublicKeyLen() -> Int {
        let proxyResult = vscf_public_key_exported_public_key_len(self.c_ctx)

        return proxyResult
    }

    /// Import public key from the binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.1.
    @objc public func importPublicKey(data: Data) throws {
        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_status_t in
            return vscf_public_key_import_public_key(self.c_ctx, vsc_data(dataPointer, data.count))
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }
}
