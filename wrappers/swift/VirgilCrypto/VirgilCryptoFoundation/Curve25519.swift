/// Copyright (C) 2015-2022 Virgil Security, Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
/// (1) Redistributions of source code must retain the above copyright
/// notice, this list of conditions and the following disclaimer.
///
/// (2) Redistributions in binary form must reproduce the above copyright
/// notice, this list of conditions and the following disclaimer in
/// the documentation and/or other materials provided with the
/// distribution.
///
/// (3) Neither the name of the copyright holder nor the names of its
/// contributors may be used to endorse or promote products derived from
/// this software without specific prior written permission.
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

    public override init() {
        self.c_ctx = vscf_curve25519_new()
        super.init()
    }

    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_curve25519_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_curve25519_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_curve25519_release_random(self.c_ctx)
        vscf_curve25519_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setEcies(ecies: Ecies) {
        vscf_curve25519_release_ecies(self.c_ctx)
        vscf_curve25519_use_ecies(self.c_ctx, ecies.c_ctx)
    }

    @objc public func setupDefaults() throws {
        let proxyResult = vscf_curve25519_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    @objc public func generateKey() throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_generate_key(self.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    @objc public func generateEphemeralKey(key: Key) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_generate_ephemeral_key(self.c_ctx, key.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    @objc public func importPublicKey(rawKey: RawPublicKey) throws -> PublicKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_import_public_key(self.c_ctx, rawKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPublicKey(take: proxyResult!)
    }

    @objc public func exportPublicKey(publicKey: PublicKey) throws -> RawPublicKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_export_public_key(self.c_ctx, publicKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPublicKey.init(take: proxyResult!)
    }

    @objc public func importPrivateKey(rawKey: RawPrivateKey) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_import_private_key(self.c_ctx, rawKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }

    @objc public func exportPrivateKey(privateKey: PrivateKey) throws -> RawPrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_curve25519_export_private_key(self.c_ctx, privateKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return RawPrivateKey.init(take: proxyResult!)
    }

    @objc public func canEncrypt(publicKey: PublicKey, dataLen: Int) -> Bool {
        let proxyResult = vscf_curve25519_can_encrypt(self.c_ctx, publicKey.c_ctx, dataLen)

        return proxyResult
    }

    @objc public func encryptedLen(publicKey: PublicKey, dataLen: Int) -> Int {
        let proxyResult = vscf_curve25519_encrypted_len(self.c_ctx, publicKey.c_ctx, dataLen)

        return proxyResult
    }

    @objc public func encrypt(publicKey: PublicKey, data: Data) throws -> Data {
        let outCount = self.encryptedLen(publicKey: publicKey, dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_curve25519_encrypt(self.c_ctx, publicKey.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    @objc public func canDecrypt(privateKey: PrivateKey, dataLen: Int) -> Bool {
        let proxyResult = vscf_curve25519_can_decrypt(self.c_ctx, privateKey.c_ctx, dataLen)

        return proxyResult
    }

    @objc public func decryptedLen(privateKey: PrivateKey, dataLen: Int) -> Int {
        let proxyResult = vscf_curve25519_decrypted_len(self.c_ctx, privateKey.c_ctx, dataLen)

        return proxyResult
    }

    @objc public func decrypt(privateKey: PrivateKey, data: Data) throws -> Data {
        let outCount = self.decryptedLen(privateKey: privateKey, dataLen: data.count)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_curve25519_decrypt(self.c_ctx, privateKey.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    @objc public func computeSharedKey(publicKey: PublicKey, privateKey: PrivateKey) throws -> Data {
        let sharedKeyCount = self.sharedKeyLen(key: privateKey)
        var sharedKey = Data(count: sharedKeyCount)
        let sharedKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(sharedKeyBuf)
        }

        let proxyResult = sharedKey.withUnsafeMutableBytes({ (sharedKeyPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(sharedKeyBuf, sharedKeyPointer.bindMemory(to: byte.self).baseAddress, sharedKeyCount)

            return vscf_curve25519_compute_shared_key(self.c_ctx, publicKey.c_ctx, privateKey.c_ctx, sharedKeyBuf)
        })
        sharedKey.count = vsc_buffer_len(sharedKeyBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return sharedKey
    }

    @objc public func sharedKeyLen(key: Key) -> Int {
        let proxyResult = vscf_curve25519_shared_key_len(self.c_ctx, key.c_ctx)

        return proxyResult
    }

    @objc public func kemSharedKeyLen(key: Key) -> Int {
        let proxyResult = vscf_curve25519_kem_shared_key_len(self.c_ctx, key.c_ctx)

        return proxyResult
    }

    @objc public func kemEncapsulatedKeyLen(publicKey: PublicKey) -> Int {
        let proxyResult = vscf_curve25519_kem_encapsulated_key_len(self.c_ctx, publicKey.c_ctx)

        return proxyResult
    }

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

                return vscf_curve25519_kem_encapsulate(self.c_ctx, publicKey.c_ctx, sharedKeyBuf, encapsulatedKeyBuf)
            })
        })
        sharedKey.count = vsc_buffer_len(sharedKeyBuf)
        encapsulatedKey.count = vsc_buffer_len(encapsulatedKeyBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return KemKemEncapsulateResult(sharedKey: sharedKey, encapsulatedKey: encapsulatedKey)
    }

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

                return vscf_curve25519_kem_decapsulate(self.c_ctx, vsc_data(encapsulatedKeyPointer.bindMemory(to: byte.self).baseAddress, encapsulatedKey.count), privateKey.c_ctx, sharedKeyBuf)
            })
        })
        sharedKey.count = vsc_buffer_len(sharedKeyBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return sharedKey
    }

}
