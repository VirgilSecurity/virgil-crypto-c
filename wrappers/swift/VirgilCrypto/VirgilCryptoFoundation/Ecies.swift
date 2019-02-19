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

/// Virgil implementation of the ECIES algorithm.
@objc(VSCFEcies) public class Ecies: NSObject, Defaults, Encrypt, Decrypt {

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

    /// Set public key that is used for data encryption.
    ///
    /// If ephemeral key is not defined, then Public Key, must be conformed
    /// to the interface "generate ephemeral key".
    ///
    /// In turn, Ephemeral Key must be conformed to the interface
    /// "compute shared key".
    @objc public func setEncryptionKey(encryptionKey: PublicKey) {
        vscf_ecies_release_encryption_key(self.c_ctx)
        vscf_ecies_use_encryption_key(self.c_ctx, encryptionKey.c_ctx)
    }

    /// Set private key that used for data decryption.
    ///
    /// Private Key must be conformed to the interface "compute shared key".
    @objc public func setDecryptionKey(decryptionKey: PrivateKey) {
        vscf_ecies_release_decryption_key(self.c_ctx)
        vscf_ecies_use_decryption_key(self.c_ctx, decryptionKey.c_ctx)
    }

    /// Set private key that used for data decryption.
    ///
    /// Ephemeral Key must be conformed to the interface "compute shared key".
    @objc public func setEphemeralKey(ephemeralKey: PrivateKey) {
        vscf_ecies_release_ephemeral_key(self.c_ctx)
        vscf_ecies_use_ephemeral_key(self.c_ctx, ephemeralKey.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_ecies_setup_defaults(self.c_ctx)

        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Encrypt given data.
    @objc public func encrypt(data: Data) throws -> Data {
        let outCount = self.encryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                vsc_buffer_init(outBuf)
                vsc_buffer_use(outBuf, outPointer, outCount)
                return vscf_ecies_encrypt(self.c_ctx, vsc_data(dataPointer, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the encrypted data.
    @objc public func encryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_ecies_encrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Decrypt given data.
    @objc public func decrypt(data: Data) throws -> Data {
        let outCount = self.decryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                vsc_buffer_init(outBuf)
                vsc_buffer_use(outBuf, outPointer, outCount)
                return vscf_ecies_decrypt(self.c_ctx, vsc_data(dataPointer, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the decrypted data.
    @objc public func decryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_ecies_decrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }
}
