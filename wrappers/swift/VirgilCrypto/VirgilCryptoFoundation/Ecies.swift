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

/// Virgil implementation of the ECIES algorithm.
@objc(VSCFEcies) public class Ecies: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_ecies_new()
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
        self.c_ctx = vscf_ecies_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_ecies_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_ecies_release_random(self.c_ctx)
        vscf_ecies_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setCipher(cipher: Cipher) {
        vscf_ecies_release_cipher(self.c_ctx)
        vscf_ecies_use_cipher(self.c_ctx, cipher.c_ctx)
    }

    @objc public func setMac(mac: Mac) {
        vscf_ecies_release_mac(self.c_ctx)
        vscf_ecies_use_mac(self.c_ctx, mac.c_ctx)
    }

    @objc public func setKdf(kdf: Kdf) {
        vscf_ecies_release_kdf(self.c_ctx)
        vscf_ecies_use_kdf(self.c_ctx, kdf.c_ctx)
    }

    /// Set ephemeral key that used for data encryption.
    /// Public and ephemeral keys should belong to the same curve.
    /// This dependency is optional.
    @objc public func setEphemeralKey(ephemeralKey: PrivateKey) {
        vscf_ecies_release_ephemeral_key(self.c_ctx)
        vscf_ecies_use_ephemeral_key(self.c_ctx, ephemeralKey.c_ctx)
    }

    /// Set weak reference to the key algorithm.
    /// Key algorithm MUST support shared key computation as well.
    @objc public func setKeyAlg(keyAlg: KeyAlg) {
        vscf_ecies_set_key_alg(self.c_ctx, keyAlg.c_ctx)
    }

    /// Release weak reference to the key algorithm.
    @objc public func releaseKeyAlg() {
        vscf_ecies_release_key_alg(self.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_ecies_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Setup predefined values to the uninitialized class dependencies
    /// except random.
    @objc public func setupDefaultsNoRandom() {
        vscf_ecies_setup_defaults_no_random(self.c_ctx)
    }

    /// Calculate required buffer length to hold the encrypted data.
    @objc public func encryptedLen(publicKey: PublicKey, dataLen: Int) -> Int {
        let proxyResult = vscf_ecies_encrypted_len(self.c_ctx, publicKey.c_ctx, dataLen)

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

                return vscf_ecies_encrypt(self.c_ctx, publicKey.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the decrypted data.
    @objc public func decryptedLen(privateKey: PrivateKey, dataLen: Int) -> Int {
        let proxyResult = vscf_ecies_decrypted_len(self.c_ctx, privateKey.c_ctx, dataLen)

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

                return vscf_ecies_decrypt(self.c_ctx, privateKey.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }
}
