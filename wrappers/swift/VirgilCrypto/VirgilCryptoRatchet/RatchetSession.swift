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

@objc(VSCRRatchetSession) public class RatchetSession: NSObject {

    /// FIXME
    static let maxRatchetLength = 1024 * 1024;

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscr_ratchet_session_new()
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
        self.c_ctx = vscr_ratchet_session_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscr_ratchet_session_delete(self.c_ctx)
    }

    @objc public func setRng(rng: Random) {
        vscr_ratchet_session_release_rng(self.c_ctx)
        vscr_ratchet_session_use_rng(self.c_ctx, rng.c_ctx)
    }

    @objc public func setupDefaults() {
        vscr_ratchet_session_setup_defaults(self.c_ctx)
    }

    @objc public func initiate(senderIdentityPrivateKey: Data, receiverIdentityPublicKey: Data, receiverLongTermPublicKey: Data, receiverOneTimePublicKey: Data) throws {
        let proxyResult = senderIdentityPrivateKey.withUnsafeBytes({ (senderIdentityPrivateKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
            receiverIdentityPublicKey.withUnsafeBytes({ (receiverIdentityPublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                receiverLongTermPublicKey.withUnsafeBytes({ (receiverLongTermPublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                    receiverOneTimePublicKey.withUnsafeBytes({ (receiverOneTimePublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                        return vscr_ratchet_session_initiate(self.c_ctx, vsc_data(senderIdentityPrivateKeyPointer, senderIdentityPrivateKey.count), vsc_data(receiverIdentityPublicKeyPointer, receiverIdentityPublicKey.count), vsc_data(receiverLongTermPublicKeyPointer, receiverLongTermPublicKey.count), vsc_data(receiverOneTimePublicKeyPointer, receiverOneTimePublicKey.count))
                    })
                })
            })
        })

        try RatchetError.handleError(fromC: proxyResult)
    }

    @objc public func respond(senderIdentityPublicKey: Data, receiverIdentityPrivateKey: Data, receiverLongTermPrivateKey: Data, receiverOneTimePrivateKey: Data, message: RatchetMessage) throws {
        let proxyResult = senderIdentityPublicKey.withUnsafeBytes({ (senderIdentityPublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
            receiverIdentityPrivateKey.withUnsafeBytes({ (receiverIdentityPrivateKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                receiverLongTermPrivateKey.withUnsafeBytes({ (receiverLongTermPrivateKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                    receiverOneTimePrivateKey.withUnsafeBytes({ (receiverOneTimePrivateKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                        return vscr_ratchet_session_respond(self.c_ctx, vsc_data(senderIdentityPublicKeyPointer, senderIdentityPublicKey.count), vsc_data(receiverIdentityPrivateKeyPointer, receiverIdentityPrivateKey.count), vsc_data(receiverLongTermPrivateKeyPointer, receiverLongTermPrivateKey.count), vsc_data(receiverOneTimePrivateKeyPointer, receiverOneTimePrivateKey.count), message.c_ctx)
                    })
                })
            })
        })

        try RatchetError.handleError(fromC: proxyResult)
    }

    @objc public func encrypt(plainText: Data, errCtx: ErrorCtx) -> RatchetMessage {
        let proxyResult = plainText.withUnsafeBytes({ (plainTextPointer: UnsafePointer<byte>) in
            return vscr_ratchet_session_encrypt(self.c_ctx, vsc_data(plainTextPointer, plainText.count), errCtx.c_ctx)
        })

        return RatchetMessage.init(take: proxyResult!)
    }

    @objc public func decryptLen(message: RatchetMessage) -> Int {
        let proxyResult = vscr_ratchet_session_decrypt_len(self.c_ctx, message.c_ctx)

        return proxyResult
    }

    @objc public func decrypt(message: RatchetMessage) throws -> Data {
        let plainTextCount = self.decryptLen(message: message)
        var plainText = Data(count: plainTextCount)
        var plainTextBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(plainTextBuf)
        }

        let proxyResult = plainText.withUnsafeMutableBytes({ (plainTextPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
            vsc_buffer_init(plainTextBuf)
            vsc_buffer_use(plainTextBuf, plainTextPointer, plainTextCount)
            return vscr_ratchet_session_decrypt(self.c_ctx, message.c_ctx, plainTextBuf)
        })
        plainText.count = vsc_buffer_len(plainTextBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return plainText
    }

    @objc public func serializeLen() -> Int {
        let proxyResult = vscr_ratchet_session_serialize_len(self.c_ctx)

        return proxyResult
    }

    @objc public func serialize() -> Data {
        let outputCount = self.serializeLen()
        var output = Data(count: outputCount)
        var outputBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outputBuf)
        }

        output.withUnsafeMutableBytes({ (outputPointer: UnsafeMutablePointer<byte>) -> Void in
            vsc_buffer_init(outputBuf)
            vsc_buffer_use(outputBuf, outputPointer, outputCount)
            vscr_ratchet_session_serialize(self.c_ctx, outputBuf)
        })
        output.count = vsc_buffer_len(outputBuf)

        return output
    }

    @objc public static func deserialize(input: Data, errCtx: ErrorCtx) -> RatchetSession {
        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafePointer<byte>) in
            return vscr_ratchet_session_deserialize(vsc_data(inputPointer, input.count), errCtx.c_ctx)
        })

        return RatchetSession.init(take: proxyResult!)
    }
}
