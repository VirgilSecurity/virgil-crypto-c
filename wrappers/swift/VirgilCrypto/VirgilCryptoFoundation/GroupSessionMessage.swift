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
import VSCFoundation

/// Class represents group session message
@objc(VSCFGroupSessionMessage) public class GroupSessionMessage: NSObject {

    /// Max message len
    @objc public static let maxMessageLen: Int = 30188
    /// Message version
    @objc public static let messageVersion: Int = 1

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_group_session_message_new()
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
        self.c_ctx = vscf_group_session_message_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_group_session_message_delete(self.c_ctx)
    }

    /// Returns message type.
    @objc public func getType() -> GroupMsgType {
        let proxyResult = vscf_group_session_message_get_type(self.c_ctx)

        return GroupMsgType.init(fromC: proxyResult)
    }

    /// Returns session id.
    /// This method should be called only for group info type.
    @objc public func getSessionId() -> Data {
        let proxyResult = vscf_group_session_message_get_session_id(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Returns message epoch.
    @objc public func getEpoch() -> UInt32 {
        let proxyResult = vscf_group_session_message_get_epoch(self.c_ctx)

        return proxyResult
    }

    /// Buffer len to serialize this class.
    @objc public func serializeLen() -> Int {
        let proxyResult = vscf_group_session_message_serialize_len(self.c_ctx)

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

            vscf_group_session_message_serialize(self.c_ctx, outputBuf)
        })
        output.count = vsc_buffer_len(outputBuf)

        return output
    }

    /// Deserializes instance.
    @objc public static func deserialize(input: Data) throws -> GroupSessionMessage {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafeRawBufferPointer) in

            return vscf_group_session_message_deserialize(vsc_data(inputPointer.bindMemory(to: byte.self).baseAddress, input.count), &error)
        })

        try FoundationError.handleStatus(fromC: error.status)

        return GroupSessionMessage.init(take: proxyResult!)
    }
}
