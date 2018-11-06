/// Copyright (C) 2015-2018 Virgil Security Inc.
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
import VSCRatchet
import VirgilCryptoCommon
import VirgilCryptoFoundation

@objc(VSCRRatchetCipher) public class RatchetCipher: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: UnsafeMutablePointer<vscr_ratchet_cipher_t>

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscr_ratchet_cipher_new()
        super.init()
    }

    /// Acquire C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(take c_ctx: UnsafeMutablePointer<vscr_ratchet_cipher_t>) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Acquire retained C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(use c_ctx: UnsafeMutablePointer<vscr_ratchet_cipher_t>) {
        self.c_ctx = vscr_ratchet_cipher_copy(c_ctx)
        super.init()
    }

    public init(kdfInfo: Data) {
        let proxyResult = kdfInfo.withUnsafeBytes({ (kdfInfoPointer: UnsafePointer<byte>) -> UnsafeMutablePointer<vscr_ratchet_cipher_t> in
            return vscr_ratchet_cipher_new_with_members(vsc_data(kdfInfoPointer, kdfInfo.count))
        })

        self.c_ctx = proxyResult
    }

    /// Release underlying C context.
    deinit {
        vscr_ratchet_cipher_delete(self.c_ctx)
    }

    @objc public func setAes256Gcm(aes256Gcm: Aes256Gcm) {
        vscr_ratchet_cipher_release_aes256_gcm(self.c_ctx)
        vscr_ratchet_cipher_use_aes256_gcm(self.c_ctx, aes256Gcm.c_ctx)
    }

    @objc public func encryptLen(plainTextLen: Int) -> Int {
        let proxyResult = vscr_ratchet_cipher_encrypt_len(self.c_ctx, plainTextLen)

        return proxyResult
    }

    @objc public func decryptLen(cipherTextLen: Int) -> Int {
        let proxyResult = vscr_ratchet_cipher_decrypt_len(self.c_ctx, cipherTextLen)

        return proxyResult
    }

    @objc public func encrypt(key: Data, plainText: Data) throws -> Data {
        let bufferCount = self.encryptLen(plainTextLen: plainText.count)
        var buffer = Data(count: bufferCount)
        var bufferBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(bufferBuf)
        }

        let proxyResult = key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> vscr_error_t in
            plainText.withUnsafeBytes({ (plainTextPointer: UnsafePointer<byte>) -> vscr_error_t in
                buffer.withUnsafeMutableBytes({ (bufferPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
                    vsc_buffer_init(bufferBuf)
                    vsc_buffer_use(bufferBuf, bufferPointer, bufferCount)
                    return vscr_ratchet_cipher_encrypt(self.c_ctx, vsc_data(keyPointer, key.count), vsc_data(plainTextPointer, plainText.count), bufferBuf)
                })
            })
        })
        buffer.count = vsc_buffer_len(bufferBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return buffer
    }

    @objc public func decrypt(key: Data, cipherText: Data) throws -> Data {
        let bufferCount = self.decryptLen(cipherTextLen: cipherText.count)
        var buffer = Data(count: bufferCount)
        var bufferBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(bufferBuf)
        }

        let proxyResult = key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> vscr_error_t in
            cipherText.withUnsafeBytes({ (cipherTextPointer: UnsafePointer<byte>) -> vscr_error_t in
                buffer.withUnsafeMutableBytes({ (bufferPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
                    vsc_buffer_init(bufferBuf)
                    vsc_buffer_use(bufferBuf, bufferPointer, bufferCount)
                    return vscr_ratchet_cipher_decrypt(self.c_ctx, vsc_data(keyPointer, key.count), vsc_data(cipherTextPointer, cipherText.count), bufferBuf)
                })
            })
        })
        buffer.count = vsc_buffer_len(bufferBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return buffer
    }
}
