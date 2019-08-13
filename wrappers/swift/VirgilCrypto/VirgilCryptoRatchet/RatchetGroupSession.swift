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
import VSCRatchet
import VirgilCryptoFoundation

/// Ratchet group session.
@objc(VSCRRatchetGroupSession) public class RatchetGroupSession: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscr_ratchet_group_session_new()
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
        self.c_ctx = vscr_ratchet_group_session_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscr_ratchet_group_session_delete(self.c_ctx)
    }

    /// Random
    @objc public func setRng(rng: Random) {
        vscr_ratchet_group_session_release_rng(self.c_ctx)
        vscr_ratchet_group_session_use_rng(self.c_ctx, rng.c_ctx)
    }

    /// Shows whether session was initialized.
    @objc public func isInitialized() -> Bool {
        let proxyResult = vscr_ratchet_group_session_is_initialized(self.c_ctx)

        return proxyResult
    }

    /// Shows whether identity private key was set.
    @objc public func isPrivateKeySet() -> Bool {
        let proxyResult = vscr_ratchet_group_session_is_private_key_set(self.c_ctx)

        return proxyResult
    }

    /// Shows whether my id was set.
    @objc public func isMyIdSet() -> Bool {
        let proxyResult = vscr_ratchet_group_session_is_my_id_set(self.c_ctx)

        return proxyResult
    }

    /// Returns current epoch.
    @objc public func getCurrentEpoch() -> UInt32 {
        let proxyResult = vscr_ratchet_group_session_get_current_epoch(self.c_ctx)

        return proxyResult
    }

    /// Setups default dependencies:
    /// - RNG: CTR DRBG
    @objc public func setupDefaults() throws {
        let proxyResult = vscr_ratchet_group_session_setup_defaults(self.c_ctx)

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Sets identity private key.
    @objc public func setPrivateKey(myPrivateKey: Data) throws {
        let proxyResult = myPrivateKey.withUnsafeBytes({ (myPrivateKeyPointer: UnsafeRawBufferPointer) -> vscr_status_t in

            return vscr_ratchet_group_session_set_private_key(self.c_ctx, vsc_data(myPrivateKeyPointer.bindMemory(to: byte.self).baseAddress, myPrivateKey.count))
        })

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Sets my id. Should be 32 byte
    @objc public func setMyId(myId: Data) {
        myId.withUnsafeBytes({ (myIdPointer: UnsafeRawBufferPointer) -> Void in

            vscr_ratchet_group_session_set_my_id(self.c_ctx, vsc_data(myIdPointer.bindMemory(to: byte.self).baseAddress, myId.count))
        })
    }

    /// Returns my id.
    @objc public func getMyId() -> Data {
        let proxyResult = vscr_ratchet_group_session_get_my_id(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Returns session id.
    @objc public func getSessionId() -> Data {
        let proxyResult = vscr_ratchet_group_session_get_session_id(self.c_ctx)

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Returns number of participants.
    @objc public func getParticipantsCount() -> UInt32 {
        let proxyResult = vscr_ratchet_group_session_get_participants_count(self.c_ctx)

        return proxyResult
    }

    /// Sets up session.
    /// Use this method when you have newer epoch message and know all participants info.
    /// NOTE: Identity private key and my id should be set separately.
    @objc public func setupSessionState(message: RatchetGroupMessage, participants: RatchetGroupParticipantsInfo) throws {
        let proxyResult = vscr_ratchet_group_session_setup_session_state(self.c_ctx, message.c_ctx, participants.c_ctx)

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Sets up session.
    /// Use this method when you have message with next epoch, and you know how participants set was changed.
    /// NOTE: Identity private key and my id should be set separately.
    @objc public func updateSessionState(message: RatchetGroupMessage, addParticipants: RatchetGroupParticipantsInfo, removeParticipants: RatchetGroupParticipantsIds) throws {
        let proxyResult = vscr_ratchet_group_session_update_session_state(self.c_ctx, message.c_ctx, addParticipants.c_ctx, removeParticipants.c_ctx)

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Encrypts data
    @objc public func encrypt(plainText: Data) throws -> RatchetGroupMessage {
        var error: vscr_error_t = vscr_error_t()
        vscr_error_reset(&error)

        let proxyResult = plainText.withUnsafeBytes({ (plainTextPointer: UnsafeRawBufferPointer) in

            return vscr_ratchet_group_session_encrypt(self.c_ctx, vsc_data(plainTextPointer.bindMemory(to: byte.self).baseAddress, plainText.count), &error)
        })

        try RatchetError.handleStatus(fromC: error.status)

        return RatchetGroupMessage.init(take: proxyResult!)
    }

    /// Calculates size of buffer sufficient to store decrypted message
    @objc public func decryptLen(message: RatchetGroupMessage) -> Int {
        let proxyResult = vscr_ratchet_group_session_decrypt_len(self.c_ctx, message.c_ctx)

        return proxyResult
    }

    /// Decrypts message
    @objc public func decrypt(message: RatchetGroupMessage, senderId: Data) throws -> Data {
        let plainTextCount = self.decryptLen(message: message)
        var plainText = Data(count: plainTextCount)
        var plainTextBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(plainTextBuf)
        }

        let proxyResult = senderId.withUnsafeBytes({ (senderIdPointer: UnsafeRawBufferPointer) -> vscr_status_t in
            plainText.withUnsafeMutableBytes({ (plainTextPointer: UnsafeMutableRawBufferPointer) -> vscr_status_t in
                vsc_buffer_init(plainTextBuf)
                vsc_buffer_use(plainTextBuf, plainTextPointer.bindMemory(to: byte.self).baseAddress, plainTextCount)

                return vscr_ratchet_group_session_decrypt(self.c_ctx, message.c_ctx, vsc_data(senderIdPointer.bindMemory(to: byte.self).baseAddress, senderId.count), plainTextBuf)
            })
        })
        plainText.count = vsc_buffer_len(plainTextBuf)

        try RatchetError.handleStatus(fromC: proxyResult)

        return plainText
    }

    /// Serializes session to buffer
    /// NOTE: Session changes its state every encrypt/decrypt operations. Be sure to save it.
    @objc public func serialize() -> Data {
        let proxyResult = vscr_ratchet_group_session_serialize(self.c_ctx)

        defer {
            vsc_buffer_delete(proxyResult)
        }

        return Data.init(bytes: vsc_buffer_bytes(proxyResult), count: vsc_buffer_len(proxyResult))
    }

    /// Deserializes session from buffer.
    /// NOTE: Deserialized session needs dependencies to be set.
    /// You should set separately:
    ///     - rng
    ///     - my private key
    @objc public static func deserialize(input: Data) throws -> RatchetGroupSession {
        var error: vscr_error_t = vscr_error_t()
        vscr_error_reset(&error)

        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafeRawBufferPointer) in

            return vscr_ratchet_group_session_deserialize(vsc_data(inputPointer.bindMemory(to: byte.self).baseAddress, input.count), &error)
        })

        try RatchetError.handleStatus(fromC: error.status)

        return RatchetGroupSession.init(take: proxyResult!)
    }

    /// Creates ticket with new key for adding or removing participants.
    @objc public func createGroupTicket() throws -> RatchetGroupTicket {
        var error: vscr_error_t = vscr_error_t()
        vscr_error_reset(&error)

        let proxyResult = vscr_ratchet_group_session_create_group_ticket(self.c_ctx, &error)

        try RatchetError.handleStatus(fromC: error.status)

        return RatchetGroupTicket.init(take: proxyResult!)
    }
}
