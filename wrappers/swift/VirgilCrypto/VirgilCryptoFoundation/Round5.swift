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

/// Provide post-quantum encryption based on the round5 implementation.
/// For algorithm details check https://github.com/round5/code
@objc(VSCFRound5) public class Round5: NSObject, KeyAlg, Kem {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Defines whether a public key can be imported or not.
    @objc public let canImportPublicKey: Bool = true

    /// Define whether a public key can be exported or not.
    @objc public let canExportPublicKey: Bool = true

    /// Define whether a private key can be imported or not.
    @objc public let canImportPrivateKey: Bool = true

    /// Define whether a private key can be exported or not.
    @objc public let canExportPrivateKey: Bool = true

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_round5_new()
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
        self.c_ctx = vscf_round5_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_round5_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_round5_release_random(self.c_ctx)
        vscf_round5_use_random(self.c_ctx, random.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_round5_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Generate new private key.
    /// Note, this operation might be slow.
    @objc public func generateKey(algId: AlgId) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_round5_generate_key(self.c_ctx, vscf_alg_id_t(rawValue: UInt32(algId.rawValue)), &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    /// Generate ephemeral private key of the same type.
    /// Note, this operation might be slow.
    @objc public func generateEphemeralKey(key: Key) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_round5_generate_ephemeral_key(self.c_ctx, key.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    /// Import public key from the raw binary format.
    ///
    /// Return public key that is adopted and optimized to be used
    /// with this particular algorithm.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.1.
    @objc public func importPublicKey(rawKey: RawPublicKey) throws -> PublicKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_round5_import_public_key(self.c_ctx, rawKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPublicKey(take: proxyResult!)
    }

    /// Export public key to the raw binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be exported in format defined in
    /// RFC 3447 Appendix A.1.1.
    @objc public func exportPublicKey(publicKey: PublicKey) throws -> RawPublicKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_round5_export_public_key(self.c_ctx, publicKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPublicKey.init(take: proxyResult!)
    }

    /// Import private key from the raw binary format.
    ///
    /// Return private key that is adopted and optimized to be used
    /// with this particular algorithm.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA private key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.2.
    @objc public func importPrivateKey(rawKey: RawPrivateKey) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_round5_import_private_key(self.c_ctx, rawKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    /// Export private key in the raw binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA private key must be exported in format defined in
    /// RFC 3447 Appendix A.1.2.
    @objc public func exportPrivateKey(privateKey: PrivateKey) throws -> RawPrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_round5_export_private_key(self.c_ctx, privateKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPrivateKey.init(take: proxyResult!)
    }

    /// Return length in bytes required to hold encapsulated shared key.
    @objc public func kemSharedKeyLen(key: Key) -> Int {
        let proxyResult = vscf_round5_kem_shared_key_len(self.c_ctx, key.c_ctx)

        return proxyResult
    }

    /// Return length in bytes required to hold encapsulated key.
    @objc public func kemEncapsulatedKeyLen(publicKey: PublicKey) -> Int {
        let proxyResult = vscf_round5_kem_encapsulated_key_len(self.c_ctx, publicKey.c_ctx)

        return proxyResult
    }

    /// Generate a shared key and a key encapsulated message.
    @objc public func kemEncapsulate(publicKey: PublicKey) throws -> KemKemEncapsulateResult {
        let sharedKeyCount = self.kemSharedKeyLen(key: publicKey)
        var sharedKey = Data(count: sharedKeyCount)
        let sharedKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(sharedKeyBuf)
        }

        let encapsulatedKeyCount = self.kemEncapsulatedKeyLen(publicKey: publicKey)
        var encapsulatedKey = Data(count: encapsulatedKeyCount)
        let encapsulatedKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(encapsulatedKeyBuf)
        }

        let proxyResult = sharedKey.withUnsafeMutableBytes({ (sharedKeyPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            encapsulatedKey.withUnsafeMutableBytes({ (encapsulatedKeyPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(sharedKeyBuf, sharedKeyPointer.bindMemory(to: byte.self).baseAddress, sharedKeyCount)

                vsc_buffer_use(encapsulatedKeyBuf, encapsulatedKeyPointer.bindMemory(to: byte.self).baseAddress, encapsulatedKeyCount)

                return vscf_round5_kem_encapsulate(self.c_ctx, publicKey.c_ctx, sharedKeyBuf, encapsulatedKeyBuf)
            })
        })
        sharedKey.count = vsc_buffer_len(sharedKeyBuf)
        encapsulatedKey.count = vsc_buffer_len(encapsulatedKeyBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return KemKemEncapsulateResult(sharedKey: sharedKey, encapsulatedKey: encapsulatedKey)
    }

    /// Decapsulate the shared key.
    @objc public func kemDecapsulate(encapsulatedKey: Data, privateKey: PrivateKey) throws -> Data {
        let sharedKeyCount = self.kemSharedKeyLen(key: privateKey)
        var sharedKey = Data(count: sharedKeyCount)
        let sharedKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(sharedKeyBuf)
        }

        let proxyResult = encapsulatedKey.withUnsafeBytes({ (encapsulatedKeyPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            sharedKey.withUnsafeMutableBytes({ (sharedKeyPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(sharedKeyBuf, sharedKeyPointer.bindMemory(to: byte.self).baseAddress, sharedKeyCount)

                return vscf_round5_kem_decapsulate(self.c_ctx, vsc_data(encapsulatedKeyPointer.bindMemory(to: byte.self).baseAddress, encapsulatedKey.count), privateKey.c_ctx, sharedKeyBuf)
            })
        })
        sharedKey.count = vsc_buffer_len(sharedKeyBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return sharedKey
    }
}
