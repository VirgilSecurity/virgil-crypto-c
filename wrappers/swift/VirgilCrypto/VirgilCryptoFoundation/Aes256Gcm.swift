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

/// Implementation of the symmetric cipher AES-256 bit in a GCM mode.
/// Note, this implementation contains dynamic memory allocations,
/// this should be improved in the future releases.
@objc(VSCFAes256Gcm) public class Aes256Gcm: NSObject, Alg, Encrypt, Decrypt, CipherInfo, Cipher, CipherAuthInfo, AuthEncrypt, AuthDecrypt, CipherAuth {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    @objc public let nonceLen: Int = 12

    /// Cipher key length in bytes.
    @objc public let keyLen: Int = 32

    /// Cipher key length in bits.
    @objc public let keyBitlen: Int = 256

    /// Cipher block length in bytes.
    @objc public let blockLen: Int = 16

    /// Defines authentication tag length in bytes.
    @objc public let authTagLen: Int = 16

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_aes256_gcm_new()
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
        self.c_ctx = vscf_aes256_gcm_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_aes256_gcm_delete(self.c_ctx)
    }

    /// Provide algorithm identificator.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_aes256_gcm_alg_id(self.c_ctx)

        return AlgId.init(fromC: proxyResult)
    }

    /// Produce object with algorithm information and configuration parameters.
    @objc public func produceAlgInfo() -> AlgInfo {
        let proxyResult = vscf_aes256_gcm_produce_alg_info(self.c_ctx)

        return AlgInfoProxy.init(c_ctx: proxyResult!)
    }

    /// Restore algorithm configuration from the given object.
    @objc public func restoreAlgInfo(algInfo: AlgInfo) throws {
        let proxyResult = vscf_aes256_gcm_restore_alg_info(self.c_ctx, algInfo.c_ctx)

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
                return vscf_aes256_gcm_encrypt(self.c_ctx, vsc_data(dataPointer, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the encrypted data.
    @objc public func encryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_aes256_gcm_encrypted_len(self.c_ctx, dataLen)

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
                return vscf_aes256_gcm_decrypt(self.c_ctx, vsc_data(dataPointer, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the decrypted data.
    @objc public func decryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_aes256_gcm_decrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Setup IV or nonce.
    @objc public func setNonce(nonce: Data) {
        nonce.withUnsafeBytes({ (noncePointer: UnsafePointer<byte>) -> Void in
            vscf_aes256_gcm_set_nonce(self.c_ctx, vsc_data(noncePointer, nonce.count))
        })
    }

    /// Set cipher encryption / decryption key.
    @objc public func setKey(key: Data) {
        key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> Void in
            vscf_aes256_gcm_set_key(self.c_ctx, vsc_data(keyPointer, key.count))
        })
    }

    /// Start sequential encryption.
    @objc public func startEncryption() {
        vscf_aes256_gcm_start_encryption(self.c_ctx)
    }

    /// Start sequential decryption.
    @objc public func startDecryption() {
        vscf_aes256_gcm_start_decryption(self.c_ctx)
    }

    /// Process encryption or decryption of the given data chunk.
    @objc public func update(data: Data) -> Data {
        let outCount = self.outLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> Void in
                vsc_buffer_init(outBuf)
                vsc_buffer_use(outBuf, outPointer, outCount)
                vscf_aes256_gcm_update(self.c_ctx, vsc_data(dataPointer, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        return out
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an current mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func outLen(dataLen: Int) -> Int {
        let proxyResult = vscf_aes256_gcm_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an encryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func encryptedOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_aes256_gcm_encrypted_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an decryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func decryptedOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_aes256_gcm_decrypted_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Accomplish encryption or decryption process.
    @objc public func finish() throws -> Data {
        let outCount = self.outLen(dataLen: 0)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)
            return vscf_aes256_gcm_finish(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Encrypt given data.
    /// If 'tag' is not give, then it will written to the 'enc'.
    @objc public func authEncrypt(data: Data, authData: Data) throws -> AuthEncryptAuthEncryptResult {
        let outCount = self.authEncryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let tagCount = self.authTagLen
        var tag = Data(count: tagCount)
        var tagBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(tagBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            authData.withUnsafeBytes({ (authDataPointer: UnsafePointer<byte>) -> vscf_error_t in
                out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                    tag.withUnsafeMutableBytes({ (tagPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                        vsc_buffer_init(outBuf)
                        vsc_buffer_use(outBuf, outPointer, outCount)

                        vsc_buffer_init(tagBuf)
                        vsc_buffer_use(tagBuf, tagPointer, tagCount)
                        return vscf_aes256_gcm_auth_encrypt(self.c_ctx, vsc_data(dataPointer, data.count), vsc_data(authDataPointer, authData.count), outBuf, tagBuf)
                    })
                })
            })
        })
        out.count = vsc_buffer_len(outBuf)
        tag.count = vsc_buffer_len(tagBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return AuthEncryptAuthEncryptResult(out: out, tag: tag)
    }

    /// Calculate required buffer length to hold the authenticated encrypted data.
    @objc public func authEncryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_aes256_gcm_auth_encrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Decrypt given data.
    /// If 'tag' is not give, then it will be taken from the 'enc'.
    @objc public func authDecrypt(data: Data, authData: Data, tag: Data) throws -> Data {
        let outCount = self.authDecryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            authData.withUnsafeBytes({ (authDataPointer: UnsafePointer<byte>) -> vscf_error_t in
                tag.withUnsafeBytes({ (tagPointer: UnsafePointer<byte>) -> vscf_error_t in
                    out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                        vsc_buffer_init(outBuf)
                        vsc_buffer_use(outBuf, outPointer, outCount)
                        return vscf_aes256_gcm_auth_decrypt(self.c_ctx, vsc_data(dataPointer, data.count), vsc_data(authDataPointer, authData.count), vsc_data(tagPointer, tag.count), outBuf)
                    })
                })
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the authenticated decrypted data.
    @objc public func authDecryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_aes256_gcm_auth_decrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }
}
