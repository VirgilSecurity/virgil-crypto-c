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

/// Wraps any symmetric cipher algorithm to add padding to plaintext
/// to prevent message guessing attacks based on a ciphertext length.
@objc(VSCFPaddingCipher) public class PaddingCipher: NSObject, Encrypt, Decrypt, CipherInfo, Cipher {

    @objc public static let paddingFrameDefault: Int = 160
    @objc public static let paddingFrameMin: Int = 32
    @objc public static let paddingFrameMax: Int = 8 * 1024
    @objc public static let paddingSizeLen: Int = 4
    @objc public static let paddingLenMin: Int = vscf_padding_cipher_PADDING_SIZE_LEN + 1

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_padding_cipher_new()
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
        self.c_ctx = vscf_padding_cipher_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_padding_cipher_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_padding_cipher_release_random(self.c_ctx)
        vscf_padding_cipher_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setCipher(cipher: Cipher) {
        vscf_padding_cipher_release_cipher(self.c_ctx)
        vscf_padding_cipher_use_cipher(self.c_ctx, cipher.c_ctx)
    }

    /// Setup padding frame in bytes.
    /// The padding frame defines the multiplicator of data length.
    @objc public func setPaddingFrame(paddingFrame: Int) {
        vscf_padding_cipher_set_padding_frame(self.c_ctx, paddingFrame)
    }

    /// Encrypt given data.
    @objc public func encrypt(data: Data) throws -> Data {
        let outCount = self.encryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_padding_cipher_encrypt(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the encrypted data.
    @objc public func encryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_padding_cipher_encrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Precise length calculation of encrypted data.
    @objc public func preciseEncryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_padding_cipher_precise_encrypted_len(self.c_ctx, dataLen)

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

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_padding_cipher_decrypt(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the decrypted data.
    @objc public func decryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_padding_cipher_decrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return cipher's nonce length or IV length in bytes,
    /// or 0 if nonce is not required.
    @objc public func nonceLen() -> Int {
        let proxyResult = vscf_padding_cipher_nonce_len(self.c_ctx)

        return proxyResult
    }

    /// Return cipher's key length in bytes.
    @objc public func keyLen() -> Int {
        let proxyResult = vscf_padding_cipher_key_len(self.c_ctx)

        return proxyResult
    }

    /// Return cipher's key length in bits.
    @objc public func keyBitlen() -> Int {
        let proxyResult = vscf_padding_cipher_key_bitlen(self.c_ctx)

        return proxyResult
    }

    /// Return cipher's block length in bytes.
    @objc public func blockLen() -> Int {
        let proxyResult = vscf_padding_cipher_block_len(self.c_ctx)

        return proxyResult
    }

    /// Setup IV or nonce.
    @objc public func setNonce(nonce: Data) {
        nonce.withUnsafeBytes({ (noncePointer: UnsafeRawBufferPointer) -> Void in

            vscf_padding_cipher_set_nonce(self.c_ctx, vsc_data(noncePointer.bindMemory(to: byte.self).baseAddress, nonce.count))
        })
    }

    /// Set cipher encryption / decryption key.
    @objc public func setKey(key: Data) {
        key.withUnsafeBytes({ (keyPointer: UnsafeRawBufferPointer) -> Void in

            vscf_padding_cipher_set_key(self.c_ctx, vsc_data(keyPointer.bindMemory(to: byte.self).baseAddress, key.count))
        })
    }

    /// Start sequential encryption.
    @objc public func startEncryption() {
        vscf_padding_cipher_start_encryption(self.c_ctx)
    }

    /// Start sequential decryption.
    @objc public func startDecryption() {
        vscf_padding_cipher_start_decryption(self.c_ctx)
    }

    /// Process encryption or decryption of the given data chunk.
    @objc public func update(data: Data) -> Data {
        let outCount = self.outLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> Void in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> Void in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                vscf_padding_cipher_update(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        return out
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an current mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func outLen(dataLen: Int) -> Int {
        let proxyResult = vscf_padding_cipher_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an encryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func encryptedOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_padding_cipher_encrypted_out_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an decryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    @objc public func decryptedOutLen(dataLen: Int) -> Int {
        let proxyResult = vscf_padding_cipher_decrypted_out_len(self.c_ctx, dataLen)

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

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

            return vscf_padding_cipher_finish(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }
}
