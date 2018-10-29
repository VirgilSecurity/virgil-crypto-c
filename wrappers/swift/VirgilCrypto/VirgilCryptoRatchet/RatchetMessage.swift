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

@objc(VSCRRatchetMessage) public class RatchetMessage: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: UnsafeMutablePointer<vscr_ratchet_message_t>

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscr_ratchet_message_new()
        super.init()
    }

    /// Acquire C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(take c_ctx: UnsafeMutablePointer<vscr_ratchet_message_t>) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Acquire retained C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(use c_ctx: UnsafeMutablePointer<vscr_ratchet_message_t>) {
        self.c_ctx = vscr_ratchet_message_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscr_ratchet_message_delete(self.c_ctx)
    }

    @objc public static func serializeLen(messageLen: Int) -> Int {
        let proxyResult = vscr_ratchet_message_serialize_len(messageLen)
        return proxyResult
    }

    @objc public func serializeLenExt() -> Int {
        let proxyResult = vscr_ratchet_message_serialize_len_ext(self.c_ctx)
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
            return vscr_ratchet_message_serialize(self.c_ctx, outputBuf)
        })

        try RatchetError.handleError(fromC: proxyResult)

        return output
    }

    @objc public static func deserialize(input: Data, errCtx: ErrorCtx) -> RatchetMessage {
        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafePointer<byte>) in
            return vscr_ratchet_message_deserialize(vsc_data(inputPointer, input.count), errCtx.c_ctx)
        })

        return RatchetMessage.init(take: proxyResult!)
    }
}
