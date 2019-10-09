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

/// Provide post-quantum signature based on the falcon implementation.
/// For algorithm details check https://falcon-sign.info.
@objc(VSCFFalcon) public class Falcon: NSObject, Alg, KeyAlg, KeySigner {

    @objc public static let seedLen: Int = 48
    @objc public static let logn512: Int = 9
    @objc public static let logn1024: Int = 10

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
        self.c_ctx = vscf_falcon_new()
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
        self.c_ctx = vscf_falcon_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_falcon_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_falcon_release_random(self.c_ctx)
        vscf_falcon_use_random(self.c_ctx, random.c_ctx)
    }

    /// Generate new private key.
    /// Note, this operation might be slow.
    @objc public func generateKey() throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_falcon_generate_key(self.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    /// Provide algorithm identificator.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_falcon_alg_id(self.c_ctx)

        return AlgId.init(fromC: proxyResult)
    }

    /// Produce object with algorithm information and configuration parameters.
    @objc public func produceAlgInfo() -> AlgInfo {
        let proxyResult = vscf_falcon_produce_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(take: proxyResult!)
    }

    /// Restore algorithm configuration from the given object.
    @objc public func restoreAlgInfo(algInfo: AlgInfo) throws {
        let proxyResult = vscf_falcon_restore_alg_info(self.c_ctx, algInfo.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Generate ephemeral private key of the same type.
    /// Note, this operation might be slow.
    @objc public func generateEphemeralKey(key: Key) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_falcon_generate_ephemeral_key(self.c_ctx, key.c_ctx, &error)

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

        let proxyResult = vscf_falcon_import_public_key(self.c_ctx, rawKey.c_ctx, &error)

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

        let proxyResult = vscf_falcon_export_public_key(self.c_ctx, publicKey.c_ctx, &error)

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

        let proxyResult = vscf_falcon_import_private_key(self.c_ctx, rawKey.c_ctx, &error)

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

        let proxyResult = vscf_falcon_export_private_key(self.c_ctx, privateKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPrivateKey.init(take: proxyResult!)
    }

    /// Check if algorithm can sign data digest with a given key.
    @objc public func canSign(privateKey: PrivateKey) -> Bool {
        let proxyResult = vscf_falcon_can_sign(self.c_ctx, privateKey.c_ctx)

        return proxyResult
    }

    /// Return length in bytes required to hold signature.
    /// Return zero if a given private key can not produce signatures.
    @objc public func signatureLen(key: Key) -> Int {
        let proxyResult = vscf_falcon_signature_len(self.c_ctx, key.c_ctx)

        return proxyResult
    }

    /// Sign data digest with a given private key.
    @objc public func signHash(privateKey: PrivateKey, hashId: AlgId, digest: Data) throws -> Data {
        let signatureCount = self.signatureLen(key: privateKey)
        var signature = Data(count: signatureCount)
        var signatureBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(signatureBuf)
        }

        let proxyResult = digest.withUnsafeBytes({ (digestPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            signature.withUnsafeMutableBytes({ (signaturePointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(signatureBuf, signaturePointer.bindMemory(to: byte.self).baseAddress, signatureCount)

                return vscf_falcon_sign_hash(self.c_ctx, privateKey.c_ctx, vscf_alg_id_t(rawValue: UInt32(hashId.rawValue)), vsc_data(digestPointer.bindMemory(to: byte.self).baseAddress, digest.count), signatureBuf)
            })
        })
        signature.count = vsc_buffer_len(signatureBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return signature
    }

    /// Check if algorithm can verify data digest with a given key.
    @objc public func canVerify(publicKey: PublicKey) -> Bool {
        let proxyResult = vscf_falcon_can_verify(self.c_ctx, publicKey.c_ctx)

        return proxyResult
    }

    /// Verify data digest with a given public key and signature.
    @objc public func verifyHash(publicKey: PublicKey, hashId: AlgId, digest: Data, signature: Data) -> Bool {
        let proxyResult = digest.withUnsafeBytes({ (digestPointer: UnsafeRawBufferPointer) -> Bool in
            signature.withUnsafeBytes({ (signaturePointer: UnsafeRawBufferPointer) -> Bool in

                return vscf_falcon_verify_hash(self.c_ctx, publicKey.c_ctx, vscf_alg_id_t(rawValue: UInt32(hashId.rawValue)), vsc_data(digestPointer.bindMemory(to: byte.self).baseAddress, digest.count), vsc_data(signaturePointer.bindMemory(to: byte.self).baseAddress, signature.count))
            })
        })

        return proxyResult
    }
}
