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

/// Group chat encryption session.
@objc(VSCFGroupSession) public class GroupSession: NSObject {

    /// Sender id len
    @objc public static let senderIdLen: Int = 32
    /// Max plain text len
    @objc public static let maxPlainTextLen: Int = 30000
    /// Max epochs count
    @objc public static let maxEpochsCount: Int = 50
    /// Salt size
    @objc public static let saltSize: Int = 32

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_group_session_new()
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
        self.c_ctx = vscf_group_session_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_group_session_delete(self.c_ctx)
    }

    /// Random
    @objc public func setRng(rng: Random) {
        vscf_group_session_release_rng(self.c_ctx)
        vscf_group_session_use_rng(self.c_ctx, rng.c_ctx)
    }

    /// Returns current epoch.
    @objc public func getCurrentEpoch() -> UInt32 {
        let proxyResult = vscf_group_session_get_current_epoch(self.c_ctx)

        return proxyResult
    }

    /// Setups default dependencies:
    /// - RNG: CTR DRBG
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_group_session_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Returns session id.
    @objc public func getSessionId() -> Data {
        let proxyResult = vscf_group_session_get_session_id(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
    /// Epoch message should be encrypted and signed by trusted group chat member (admin).
    @objc public func addEpoch(message: GroupSessionMessage) throws {
        let proxyResult = vscf_group_session_add_epoch(self.c_ctx, message.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Encrypts data
    @objc public func encrypt(plainText: Data, privateKey: PrivateKey) throws -> GroupSessionMessage {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = plainText.withUnsafeBytes({ (plainTextPointer: UnsafeRawBufferPointer) in

            return vscf_group_session_encrypt(self.c_ctx, vsc_data(plainTextPointer.bindMemory(to: byte.self).baseAddress, plainText.count), privateKey.c_ctx, &error)
        })

        try FoundationError.handleStatus(fromC: error.status)

        return GroupSessionMessage.init(take: proxyResult!)
    }

    /// Calculates size of buffer sufficient to store decrypted message
    @objc public func decryptLen(message: GroupSessionMessage) -> Int {
        let proxyResult = vscf_group_session_decrypt_len(self.c_ctx, message.c_ctx)

        return proxyResult
    }

    /// Decrypts message
    @objc public func decrypt(message: GroupSessionMessage, publicKey: PublicKey) throws -> Data {
        let plainTextCount = self.decryptLen(message: message)
        var plainText = Data(count: plainTextCount)
        let plainTextBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(plainTextBuf)
        }

        let proxyResult = plainText.withUnsafeMutableBytes({ (plainTextPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(plainTextBuf, plainTextPointer.bindMemory(to: byte.self).baseAddress, plainTextCount)

            return vscf_group_session_decrypt(self.c_ctx, message.c_ctx, publicKey.c_ctx, plainTextBuf)
        })
        plainText.count = vsc_buffer_len(plainTextBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return plainText
    }

    /// Creates ticket with new key for removing participants or proactive to rotate encryption key.
    @objc public func createGroupTicket() throws -> GroupSessionTicket {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_group_session_create_group_ticket(self.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return GroupSessionTicket.init(take: proxyResult!)
    }
}
