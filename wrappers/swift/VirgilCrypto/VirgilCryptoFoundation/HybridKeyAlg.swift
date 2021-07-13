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

/// Implements public key cryptography over hybrid keys.
/// Hybrid encryption - TODO
/// Hybrid signatures - TODO
@objc(VSCFHybridKeyAlg) public class HybridKeyAlg: NSObject, KeyAlg, KeyCipher, KeySigner {

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
        self.c_ctx = vscf_hybrid_key_alg_new()
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
        self.c_ctx = vscf_hybrid_key_alg_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_hybrid_key_alg_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_hybrid_key_alg_release_random(self.c_ctx)
        vscf_hybrid_key_alg_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setCipher(cipher: CipherAuth) {
        vscf_hybrid_key_alg_release_cipher(self.c_ctx)
        vscf_hybrid_key_alg_use_cipher(self.c_ctx, cipher.c_ctx)
    }

    @objc public func setHash(hash: Hash) {
        vscf_hybrid_key_alg_release_hash(self.c_ctx)
        vscf_hybrid_key_alg_use_hash(self.c_ctx, hash.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_hybrid_key_alg_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Make hybrid private key from given keys.
    @objc public func makeKey(firstKey: PrivateKey, secondKey: PrivateKey) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_hybrid_key_alg_make_key(self.c_ctx, firstKey.c_ctx, secondKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    /// Generate ephemeral private key of the same type.
    /// Note, this operation might be slow.
    @objc public func generateEphemeralKey(key: Key) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_hybrid_key_alg_generate_ephemeral_key(self.c_ctx, key.c_ctx, &error)

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

        let proxyResult = vscf_hybrid_key_alg_import_public_key(self.c_ctx, rawKey.c_ctx, &error)

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

        let proxyResult = vscf_hybrid_key_alg_export_public_key(self.c_ctx, publicKey.c_ctx, &error)

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

        let proxyResult = vscf_hybrid_key_alg_import_private_key(self.c_ctx, rawKey.c_ctx, &error)

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

        let proxyResult = vscf_hybrid_key_alg_export_private_key(self.c_ctx, privateKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPrivateKey.init(take: proxyResult!)
    }

    /// Check if algorithm can encrypt data with a given key.
    @objc public func canEncrypt(publicKey: PublicKey, dataLen: Int) -> Bool {
        let proxyResult = vscf_hybrid_key_alg_can_encrypt(self.c_ctx, publicKey.c_ctx, dataLen)

        return proxyResult
    }

    /// Calculate required buffer length to hold the encrypted data.
    @objc public func encryptedLen(publicKey: PublicKey, dataLen: Int) -> Int {
        let proxyResult = vscf_hybrid_key_alg_encrypted_len(self.c_ctx, publicKey.c_ctx, dataLen)

        return proxyResult
    }

    /// Encrypt data with a given public key.
    @objc public func encrypt(publicKey: PublicKey, data: Data) throws -> Data {
        let outCount = self.encryptedLen(publicKey: publicKey, dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_hybrid_key_alg_encrypt(self.c_ctx, publicKey.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Check if algorithm can decrypt data with a given key.
    /// However, success result of decryption is not guaranteed.
    @objc public func canDecrypt(privateKey: PrivateKey, dataLen: Int) -> Bool {
        let proxyResult = vscf_hybrid_key_alg_can_decrypt(self.c_ctx, privateKey.c_ctx, dataLen)

        return proxyResult
    }

    /// Calculate required buffer length to hold the decrypted data.
    @objc public func decryptedLen(privateKey: PrivateKey, dataLen: Int) -> Int {
        let proxyResult = vscf_hybrid_key_alg_decrypted_len(self.c_ctx, privateKey.c_ctx, dataLen)

        return proxyResult
    }

    /// Decrypt given data.
    @objc public func decrypt(privateKey: PrivateKey, data: Data) throws -> Data {
        let outCount = self.decryptedLen(privateKey: privateKey, dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_hybrid_key_alg_decrypt(self.c_ctx, privateKey.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Check if algorithm can sign data digest with a given key.
    @objc public func canSign(privateKey: PrivateKey) -> Bool {
        let proxyResult = vscf_hybrid_key_alg_can_sign(self.c_ctx, privateKey.c_ctx)

        return proxyResult
    }

    /// Return length in bytes required to hold signature.
    /// Return zero if a given private key can not produce signatures.
    @objc public func signatureLen(privateKey: PrivateKey) -> Int {
        let proxyResult = vscf_hybrid_key_alg_signature_len(self.c_ctx, privateKey.c_ctx)

        return proxyResult
    }

    /// Sign data digest with a given private key.
    @objc public func signHash(privateKey: PrivateKey, hashId: AlgId, digest: Data) throws -> Data {
        let signatureCount = self.signatureLen(privateKey: privateKey)
        var signature = Data(count: signatureCount)
        var signatureBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(signatureBuf)
        }

        let proxyResult = digest.withUnsafeBytes({ (digestPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            signature.withUnsafeMutableBytes({ (signaturePointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(signatureBuf, signaturePointer.bindMemory(to: byte.self).baseAddress, signatureCount)

                return vscf_hybrid_key_alg_sign_hash(self.c_ctx, privateKey.c_ctx, vscf_alg_id_t(rawValue: UInt32(hashId.rawValue)), vsc_data(digestPointer.bindMemory(to: byte.self).baseAddress, digest.count), signatureBuf)
            })
        })
        signature.count = vsc_buffer_len(signatureBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return signature
    }

    /// Check if algorithm can verify data digest with a given key.
    @objc public func canVerify(publicKey: PublicKey) -> Bool {
        let proxyResult = vscf_hybrid_key_alg_can_verify(self.c_ctx, publicKey.c_ctx)

        return proxyResult
    }

    /// Verify data digest with a given public key and signature.
    @objc public func verifyHash(publicKey: PublicKey, hashId: AlgId, digest: Data, signature: Data) -> Bool {
        let proxyResult = digest.withUnsafeBytes({ (digestPointer: UnsafeRawBufferPointer) -> Bool in
            signature.withUnsafeBytes({ (signaturePointer: UnsafeRawBufferPointer) -> Bool in

                return vscf_hybrid_key_alg_verify_hash(self.c_ctx, publicKey.c_ctx, vscf_alg_id_t(rawValue: UInt32(hashId.rawValue)), vsc_data(digestPointer.bindMemory(to: byte.self).baseAddress, digest.count), vsc_data(signaturePointer.bindMemory(to: byte.self).baseAddress, signature.count))
            })
        })

        return proxyResult
    }
}
