/// Copyright (C) 2015-2021 Virgil Security, Inc.
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
import VirgilCryptoFoundation

/// Class represents ratchet message
@objc(VSCRRatchetMessage) public class RatchetMessage: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscr_ratchet_message_new()
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
        self.c_ctx = vscr_ratchet_message_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscr_ratchet_message_delete(self.c_ctx)
    }

    /// Returns message type.
    @objc public func getType() -> MsgType {
        let proxyResult = vscr_ratchet_message_get_type(self.c_ctx)

        return MsgType.init(fromC: proxyResult)
    }

    /// Returns message counter in current asymmetric ratchet round.
    @objc public func getCounter() -> UInt32 {
        let proxyResult = vscr_ratchet_message_get_counter(self.c_ctx)

        return proxyResult
    }

    /// Returns long-term public key, if message is prekey message.
    @objc public func getSenderIdentityKeyId() -> Data {
        let proxyResult = vscr_ratchet_message_get_sender_identity_key_id(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Returns long-term public key, if message is prekey message.
    @objc public func getReceiverIdentityKeyId() -> Data {
        let proxyResult = vscr_ratchet_message_get_receiver_identity_key_id(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Returns long-term public key, if message is prekey message.
    @objc public func getReceiverLongTermKeyId() -> Data {
        let proxyResult = vscr_ratchet_message_get_receiver_long_term_key_id(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Returns one-time public key, if message is prekey message and if one-time key is present, empty result otherwise.
    @objc public func getReceiverOneTimeKeyId() -> Data {
        let proxyResult = vscr_ratchet_message_get_receiver_one_time_key_id(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Buffer len to serialize this class.
    @objc public func serializeLen() -> Int {
        let proxyResult = vscr_ratchet_message_serialize_len(self.c_ctx)

        return proxyResult
    }

    /// Serializes instance.
    @objc public func serialize() -> Data {
        let outputCount = self.serializeLen()
        var output = Data(count: outputCount)
        let outputBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outputBuf)
        }

        output.withUnsafeMutableBytes({ (outputPointer: UnsafeMutableRawBufferPointer) -> Void in
            vsc_buffer_use(outputBuf, outputPointer.bindMemory(to: byte.self).baseAddress, outputCount)

            vscr_ratchet_message_serialize(self.c_ctx, outputBuf)
        })
        output.count = vsc_buffer_len(outputBuf)

        return output
    }

    /// Deserializes instance.
    @objc public static func deserialize(input: Data) throws -> RatchetMessage {
        var error: vscr_error_t = vscr_error_t()
        vscr_error_reset(&error)

        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafeRawBufferPointer) in

            return vscr_ratchet_message_deserialize(vsc_data(inputPointer.bindMemory(to: byte.self).baseAddress, input.count), &error)
        })

        try RatchetError.handleStatus(fromC: error.status)

        return RatchetMessage.init(take: proxyResult!)
    }
}
