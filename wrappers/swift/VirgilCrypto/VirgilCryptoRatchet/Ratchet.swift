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

@objc(VSCRRatchet) public class Ratchet: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscr_ratchet_new()
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
        self.c_ctx = vscr_ratchet_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscr_ratchet_delete(self.c_ctx)
    }

    @objc public func setRng(rng: RatchetRng) {
        vscr_ratchet_release_rng(self.c_ctx)
        vscr_ratchet_use_rng(self.c_ctx, rng.c_ctx)
    }

    @objc public func setCipher(cipher: RatchetCipher) {
        vscr_ratchet_release_cipher(self.c_ctx)
        vscr_ratchet_use_cipher(self.c_ctx, cipher.c_ctx)
    }

    @objc public func respond(sharedSecret: Data, ratchetPublicKey: Data, message: RatchetRegularMessage) throws {
        let proxyResult = sharedSecret.withUnsafeBytes({ (sharedSecretPointer: UnsafePointer<byte>) -> vscr_error_t in
            ratchetPublicKey.withUnsafeBytes({ (ratchetPublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                var ratchetPublicKeyBuf = vsc_buffer_new_with_data(vsc_data(ratchetPublicKeyPointer, ratchetPublicKey.count))
                defer {
                    vsc_buffer_delete(ratchetPublicKeyBuf)
                }
                return vscr_ratchet_respond(self.c_ctx, vsc_data(sharedSecretPointer, sharedSecret.count), ratchetPublicKeyBuf, message.c_ctx)
            })
        })

        try RatchetError.handleError(fromC: proxyResult)
    }

    @objc public func initiate(sharedSecret: Data, ratchetPrivateKey: Data) throws {
        let proxyResult = sharedSecret.withUnsafeBytes({ (sharedSecretPointer: UnsafePointer<byte>) -> vscr_error_t in
            ratchetPrivateKey.withUnsafeBytes({ (ratchetPrivateKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                var ratchetPrivateKeyBuf = vsc_buffer_new_with_data(vsc_data(ratchetPrivateKeyPointer, ratchetPrivateKey.count))
                defer {
                    vsc_buffer_delete(ratchetPrivateKeyBuf)
                }
                return vscr_ratchet_initiate(self.c_ctx, vsc_data(sharedSecretPointer, sharedSecret.count), ratchetPrivateKeyBuf)
            })
        })

        try RatchetError.handleError(fromC: proxyResult)
    }

    @objc public func encryptLen(plainTextLen: Int) -> Int {
        let proxyResult = vscr_ratchet_encrypt_len(self.c_ctx, plainTextLen)

        return proxyResult
    }

    @objc public func encrypt(plainText: Data) throws -> Data {
        let cipherTextCount = self.encryptLen(plainTextLen: plainText.count)
        var cipherText = Data(count: cipherTextCount)
        var cipherTextBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(cipherTextBuf)
        }

        let proxyResult = plainText.withUnsafeBytes({ (plainTextPointer: UnsafePointer<byte>) -> vscr_error_t in
            cipherText.withUnsafeMutableBytes({ (cipherTextPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
                vsc_buffer_init(cipherTextBuf)
                vsc_buffer_use(cipherTextBuf, cipherTextPointer, cipherTextCount)
                return vscr_ratchet_encrypt(self.c_ctx, vsc_data(plainTextPointer, plainText.count), cipherTextBuf)
            })
        })
        cipherText.count = vsc_buffer_len(cipherTextBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return cipherText
    }

    @objc public func decryptLen(cipherTextLen: Int) -> Int {
        let proxyResult = vscr_ratchet_decrypt_len(self.c_ctx, cipherTextLen)

        return proxyResult
    }

    @objc public func decrypt(cipherText: Data) throws -> Data {
        let plainTextCount = self.decryptLen(cipherTextLen: cipherText.count)
        var plainText = Data(count: plainTextCount)
        var plainTextBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(plainTextBuf)
        }

        let proxyResult = cipherText.withUnsafeBytes({ (cipherTextPointer: UnsafePointer<byte>) -> vscr_error_t in
            plainText.withUnsafeMutableBytes({ (plainTextPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
                vsc_buffer_init(plainTextBuf)
                vsc_buffer_use(plainTextBuf, plainTextPointer, plainTextCount)
                return vscr_ratchet_decrypt(self.c_ctx, vsc_data(cipherTextPointer, cipherText.count), plainTextBuf)
            })
        })
        plainText.count = vsc_buffer_len(plainTextBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return plainText
    }

    @objc public func serializeLen() -> Int {
        let proxyResult = vscr_ratchet_serialize_len(self.c_ctx)

        return proxyResult
    }

    @objc public func serialize() throws -> Data {
        let outputCount = self.serializeLen()
        var output = Data(count: outputCount)
        var outputBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outputBuf)
        }

        let proxyResult = output.withUnsafeMutableBytes({ (outputPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
            vsc_buffer_init(outputBuf)
            vsc_buffer_use(outputBuf, outputPointer, outputCount)
            return vscr_ratchet_serialize(self.c_ctx, outputBuf)
        })
        output.count = vsc_buffer_len(outputBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return output
    }

    @objc public static func deserialize(input: Data, errCtx: ErrorCtx) -> Ratchet {
        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafePointer<byte>) in
            return vscr_ratchet_deserialize(vsc_data(inputPointer, input.count), errCtx.c_ctx)
        })

        return Ratchet.init(take: proxyResult!)
    }
}
