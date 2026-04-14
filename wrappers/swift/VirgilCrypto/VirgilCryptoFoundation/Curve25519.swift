// Copyright (C) 2015-2022 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

import Foundation
import VSCFoundation

/// This is implementation of Curve25519 elliptic curve algorithms.
@objc(VSCFCurve25519) public class Curve25519: NSObject, KeyAlg, KeyCipher, ComputeSharedKey, Kem {
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
    override public init() {
        c_ctx = vscf_curve25519_new()
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
        self.c_ctx = vscf_curve25519_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_curve25519_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_curve25519_release_random(c_ctx)
        vscf_curve25519_use_random(c_ctx, random.c_ctx)
    }

    @objc public func setEcies(ecies: Ecies) {
        vscf_curve25519_release_ecies(c_ctx)
        vscf_curve25519_use_ecies(c_ctx, ecies.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_curve25519_setup_defaults(c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Generate new private key.
    /// Note, this operation might be slow.
    @objc public func generateKey() throws -> PrivateKey {
        var error = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_generate_key(c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    /// Generate ephemeral private key of the same type.
    /// Note, this operation might be slow.
    @objc public func generateEphemeralKey(key: Key) throws -> PrivateKey {
        var error = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_generate_ephemeral_key(c_ctx, key.c_ctx, &error)

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
        var error = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_import_public_key(c_ctx, rawKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPublicKey(take: proxyResult!)
    }

    /// Export public key to the raw binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA public key must be exported in format defined in
    /// RFC 3447 Appendix A.1.1.
    @objc public func exportPublicKey(publicKey: PublicKey) throws -> RawPublicKey {
        var error = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_export_public_key(c_ctx, publicKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPublicKey(take: proxyResult!)
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
        var error = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_import_private_key(c_ctx, rawKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    /// Export private key in the raw binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA private key must be exported in format defined in
    /// RFC 3447 Appendix A.1.2.
    @objc public func exportPrivateKey(privateKey: PrivateKey) throws -> RawPrivateKey {
        var error = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_export_private_key(c_ctx, privateKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPrivateKey(take: proxyResult!)
    }

    /// Check if algorithm can encrypt data with a given key.
    @objc public func canEncrypt(publicKey: PublicKey, dataLen: Int) -> Bool {
        return vscf_curve25519_can_encrypt(c_ctx, publicKey.c_ctx, dataLen)
    }

    /// Calculate required buffer length to hold the encrypted data.
    @objc public func encryptedLen(publicKey: PublicKey, dataLen: Int) -> Int {
        return vscf_curve25519_encrypted_len(c_ctx, publicKey.c_ctx, dataLen)
    }

    /// Encrypt data with a given public key.
    @objc public func encrypt(publicKey: PublicKey, data: Data) throws -> Data {
        let outCount = encryptedLen(publicKey: publicKey, dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes { (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes { (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_curve25519_encrypt(self.c_ctx, publicKey.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            }
        }
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Check if algorithm can decrypt data with a given key.
    /// However, success result of decryption is not guaranteed.
    @objc public func canDecrypt(privateKey: PrivateKey, dataLen: Int) -> Bool {
        return vscf_curve25519_can_decrypt(c_ctx, privateKey.c_ctx, dataLen)
    }

    /// Calculate required buffer length to hold the decrypted data.
    @objc public func decryptedLen(privateKey: PrivateKey, dataLen: Int) -> Int {
        return vscf_curve25519_decrypted_len(c_ctx, privateKey.c_ctx, dataLen)
    }

    /// Decrypt given data.
    @objc public func decrypt(privateKey: PrivateKey, data: Data) throws -> Data {
        let outCount = decryptedLen(privateKey: privateKey, dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes { (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes { (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_curve25519_decrypt(self.c_ctx, privateKey.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            }
        }
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Compute shared key for 2 asymmetric keys.
    /// Note, computed shared key can be used only within symmetric cryptography.
    @objc public func computeSharedKey(publicKey: PublicKey, privateKey: PrivateKey) throws -> Data {
        let sharedKeyCount = sharedKeyLen(key: privateKey)
        var sharedKey = Data(count: sharedKeyCount)
        let sharedKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(sharedKeyBuf)
        }

        let proxyResult = sharedKey.withUnsafeMutableBytes { (sharedKeyPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(sharedKeyBuf, sharedKeyPointer.bindMemory(to: byte.self).baseAddress, sharedKeyCount)

            return vscf_curve25519_compute_shared_key(self.c_ctx, publicKey.c_ctx, privateKey.c_ctx, sharedKeyBuf)
        }
        sharedKey.count = vsc_buffer_len(sharedKeyBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return sharedKey
    }

    /// Return number of bytes required to hold shared key.
    /// Expect Public Key or Private Key.
    @objc public func sharedKeyLen(key: Key) -> Int {
        return vscf_curve25519_shared_key_len(c_ctx, key.c_ctx)
    }

    /// Return length in bytes required to hold encapsulated shared key.
    @objc public func kemSharedKeyLen(key: Key) -> Int {
        return vscf_curve25519_kem_shared_key_len(c_ctx, key.c_ctx)
    }

    /// Return length in bytes required to hold encapsulated key.
    @objc public func kemEncapsulatedKeyLen(publicKey: PublicKey) -> Int {
        return vscf_curve25519_kem_encapsulated_key_len(c_ctx, publicKey.c_ctx)
    }

    /// Generate a shared key and a key encapsulated message.
    @objc public func kemEncapsulate(publicKey: PublicKey) throws -> KemKemEncapsulateResult {
        let sharedKeyCount = kemSharedKeyLen(key: publicKey)
        var sharedKey = Data(count: sharedKeyCount)
        let sharedKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(sharedKeyBuf)
        }

        let encapsulatedKeyCount = kemEncapsulatedKeyLen(publicKey: publicKey)
        var encapsulatedKey = Data(count: encapsulatedKeyCount)
        let encapsulatedKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(encapsulatedKeyBuf)
        }

        let proxyResult = sharedKey.withUnsafeMutableBytes { (sharedKeyPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            encapsulatedKey.withUnsafeMutableBytes { (encapsulatedKeyPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(sharedKeyBuf, sharedKeyPointer.bindMemory(to: byte.self).baseAddress, sharedKeyCount)

                vsc_buffer_use(encapsulatedKeyBuf, encapsulatedKeyPointer.bindMemory(to: byte.self).baseAddress, encapsulatedKeyCount)

                return vscf_curve25519_kem_encapsulate(self.c_ctx, publicKey.c_ctx, sharedKeyBuf, encapsulatedKeyBuf)
            }
        }
        sharedKey.count = vsc_buffer_len(sharedKeyBuf)
        encapsulatedKey.count = vsc_buffer_len(encapsulatedKeyBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return KemKemEncapsulateResult(sharedKey: sharedKey, encapsulatedKey: encapsulatedKey)
    }

    /// Decapsulate the shared key.
    @objc public func kemDecapsulate(encapsulatedKey: Data, privateKey: PrivateKey) throws -> Data {
        let sharedKeyCount = kemSharedKeyLen(key: privateKey)
        var sharedKey = Data(count: sharedKeyCount)
        let sharedKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(sharedKeyBuf)
        }

        let proxyResult = encapsulatedKey.withUnsafeBytes { (encapsulatedKeyPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            sharedKey.withUnsafeMutableBytes { (sharedKeyPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(sharedKeyBuf, sharedKeyPointer.bindMemory(to: byte.self).baseAddress, sharedKeyCount)

                return vscf_curve25519_kem_decapsulate(self.c_ctx, vsc_data(encapsulatedKeyPointer.bindMemory(to: byte.self).baseAddress, encapsulatedKey.count), privateKey.c_ctx, sharedKeyBuf)
            }
        }
        sharedKey.count = vsc_buffer_len(sharedKeyBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return sharedKey
    }
}
