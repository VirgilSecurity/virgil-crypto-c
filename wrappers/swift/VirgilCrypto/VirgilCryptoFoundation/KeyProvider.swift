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

/// Provide functionality for private key generation and importing that
/// relies on the software default implementations.
@objc(VSCFKeyProvider) public class KeyProvider: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_key_provider_new()
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
        self.c_ctx = vscf_key_provider_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_key_provider_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_key_provider_release_random(self.c_ctx)
        vscf_key_provider_use_random(self.c_ctx, random.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_key_provider_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Setup parameters that is used during RSA key generation.
    @objc public func setRsaParams(bitlen: Int) {
        vscf_key_provider_set_rsa_params(self.c_ctx, bitlen)
    }

    /// Generate new private key from the given id.
    @objc public func generatePrivateKey(algId: AlgId) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_key_provider_generate_private_key(self.c_ctx, vscf_alg_id_t(rawValue: UInt32(algId.rawValue)), &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    /// Import private key from the PKCS#8 format.
    @objc public func importPrivateKey(keyData: Data) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = keyData.withUnsafeBytes({ (keyDataPointer: UnsafeRawBufferPointer) in

            return vscf_key_provider_import_private_key(self.c_ctx, vsc_data(keyDataPointer.bindMemory(to: byte.self).baseAddress, keyData.count), &error)
        })

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    /// Import public key from the PKCS#8 format.
    @objc public func importPublicKey(keyData: Data) throws -> PublicKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = keyData.withUnsafeBytes({ (keyDataPointer: UnsafeRawBufferPointer) in

            return vscf_key_provider_import_public_key(self.c_ctx, vsc_data(keyDataPointer.bindMemory(to: byte.self).baseAddress, keyData.count), &error)
        })

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPublicKey(take: proxyResult!)
    }

    /// Calculate buffer size enough to hold exported public key.
    ///
    /// Precondition: public key must be exportable.
    @objc public func exportedPublicKeyLen(publicKey: PublicKey) -> Int {
        let proxyResult = vscf_key_provider_exported_public_key_len(self.c_ctx, publicKey.c_ctx)

        return proxyResult
    }

    /// Export given public key to the PKCS#8 DER format.
    ///
    /// Precondition: public key must be exportable.
    @objc public func exportPublicKey(publicKey: PublicKey) throws -> Data {
        let outCount = self.exportedPublicKeyLen(publicKey: publicKey)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_key_provider_export_public_key(self.c_ctx, publicKey.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Calculate buffer size enough to hold exported private key.
    ///
    /// Precondition: private key must be exportable.
    @objc public func exportedPrivateKeyLen(privateKey: PrivateKey) -> Int {
        let proxyResult = vscf_key_provider_exported_private_key_len(self.c_ctx, privateKey.c_ctx)

        return proxyResult
    }

    /// Export given private key to the PKCS#8 or SEC1 DER format.
    ///
    /// Precondition: private key must be exportable.
    @objc public func exportPrivateKey(privateKey: PrivateKey) throws -> Data {
        let outCount = self.exportedPrivateKeyLen(privateKey: privateKey)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_key_provider_export_private_key(self.c_ctx, privateKey.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }
}
