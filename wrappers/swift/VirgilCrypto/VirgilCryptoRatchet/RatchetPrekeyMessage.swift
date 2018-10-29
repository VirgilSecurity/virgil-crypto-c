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

@objc(VSCRRatchetPrekeyMessage) public class RatchetPrekeyMessage: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: UnsafeMutablePointer<vscr_ratchet_prekey_message_t>

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscr_ratchet_prekey_message_new()
        super.init()
    }

    /// Acquire C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(take c_ctx: UnsafeMutablePointer<vscr_ratchet_prekey_message_t>) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Acquire retained C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(use c_ctx: UnsafeMutablePointer<vscr_ratchet_prekey_message_t>) {
        self.c_ctx = vscr_ratchet_prekey_message_copy(c_ctx)
        super.init()
    }

    public init(protocolVersion: UInt8, senderIdentityKey: Data, senderEphemeralKey: Data, receiverLongTermKey: Data, receiverOneTimeKey: Data, message: Data) {
        let proxyResult = senderIdentityKey.withUnsafeBytes({ (senderIdentityKeyPointer: UnsafePointer<byte>) -> UnsafeMutablePointer<vscr_ratchet_prekey_message_t> in
            senderEphemeralKey.withUnsafeBytes({ (senderEphemeralKeyPointer: UnsafePointer<byte>) -> UnsafeMutablePointer<vscr_ratchet_prekey_message_t> in
                receiverLongTermKey.withUnsafeBytes({ (receiverLongTermKeyPointer: UnsafePointer<byte>) -> UnsafeMutablePointer<vscr_ratchet_prekey_message_t> in
                    receiverOneTimeKey.withUnsafeBytes({ (receiverOneTimeKeyPointer: UnsafePointer<byte>) -> UnsafeMutablePointer<vscr_ratchet_prekey_message_t> in
                        message.withUnsafeBytes({ (messagePointer: UnsafePointer<byte>) -> UnsafeMutablePointer<vscr_ratchet_prekey_message_t> in
                            var senderIdentityKeyBuf = vsc_buffer_new_with_data(vsc_data(senderIdentityKeyPointer, senderIdentityKey.count))
                            defer {
                                vsc_buffer_delete(senderIdentityKeyBuf)
                            }

                            var senderEphemeralKeyBuf = vsc_buffer_new_with_data(vsc_data(senderEphemeralKeyPointer, senderEphemeralKey.count))
                            defer {
                                vsc_buffer_delete(senderEphemeralKeyBuf)
                            }

                            var receiverLongTermKeyBuf = vsc_buffer_new_with_data(vsc_data(receiverLongTermKeyPointer, receiverLongTermKey.count))
                            defer {
                                vsc_buffer_delete(receiverLongTermKeyBuf)
                            }

                            var receiverOneTimeKeyBuf = vsc_buffer_new_with_data(vsc_data(receiverOneTimeKeyPointer, receiverOneTimeKey.count))
                            defer {
                                vsc_buffer_delete(receiverOneTimeKeyBuf)
                            }

                            var messageBuf = vsc_buffer_new_with_data(vsc_data(messagePointer, message.count))
                            defer {
                                vsc_buffer_delete(messageBuf)
                            }
                            return vscr_ratchet_prekey_message_new_with_members(protocolVersion, senderIdentityKeyBuf, senderEphemeralKeyBuf, receiverLongTermKeyBuf, receiverOneTimeKeyBuf, messageBuf)
                        })
                    })
                })
            })
        })

        self.c_ctx = proxyResult
    }

    /// Release underlying C context.
    deinit {
        vscr_ratchet_prekey_message_delete(self.c_ctx)
    }

    @objc public static func serializeLen(messageLen: Int) -> Int {
        let proxyResult = vscr_ratchet_prekey_message_serialize_len(messageLen)

        return proxyResult
    }

    @objc public func serializeLenExt() -> Int {
        let proxyResult = vscr_ratchet_prekey_message_serialize_len_ext(self.c_ctx)

        return proxyResult
    }

    @objc public func serialize() throws -> Data {
        let outputCount = self.serializeLenExt()
        var output = Data(count: outputCount)
        var outputBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outputBuf)
        }

        let proxyResult = output.withUnsafeMutableBytes({ (outputPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
            vsc_buffer_init(outputBuf)
            vsc_buffer_use(outputBuf, outputPointer, outputCount)
            return vscr_ratchet_prekey_message_serialize(self.c_ctx, outputBuf)
        })
        output.count = vsc_buffer_len(outputBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return output
    }

    @objc public static func deserialize(input: Data, errCtx: ErrorCtx) -> RatchetPrekeyMessage {
        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafePointer<byte>) in
            return vscr_ratchet_prekey_message_deserialize(vsc_data(inputPointer, input.count), errCtx.c_ctx)
        })

        return RatchetPrekeyMessage.init(take: proxyResult!)
    }
}
