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

/// Class for ratchet session between 2 participants
@objc(VSCRRatchetSession) public class RatchetSession: NSObject {

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

    /// Random used to generate keys
    @objc public func setRng(rng: Random) {
        vscr_ratchet_session_release_rng(self.c_ctx)
        vscr_ratchet_session_use_rng(self.c_ctx, rng.c_ctx)
    }

    /// Setups default dependencies:
    ///     - RNG: CTR DRBG
    @objc public func setupDefaults() throws {
        let proxyResult = vscr_ratchet_session_setup_defaults(self.c_ctx)

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Initiates session
    @objc public func initiate(senderIdentityPrivateKey: PrivateKey, senderIdentityKeyId: Data, receiverIdentityPublicKey: PublicKey, receiverIdentityKeyId: Data, receiverLongTermPublicKey: PublicKey, receiverLongTermKeyId: Data, receiverOneTimePublicKey: PublicKey, receiverOneTimeKeyId: Data, enablePostQuantum: Bool) throws {
        let proxyResult = senderIdentityKeyId.withUnsafeBytes({ (senderIdentityKeyIdPointer: UnsafeRawBufferPointer) -> vscr_status_t in
            receiverIdentityKeyId.withUnsafeBytes({ (receiverIdentityKeyIdPointer: UnsafeRawBufferPointer) -> vscr_status_t in
                receiverLongTermKeyId.withUnsafeBytes({ (receiverLongTermKeyIdPointer: UnsafeRawBufferPointer) -> vscr_status_t in
                    receiverOneTimeKeyId.withUnsafeBytes({ (receiverOneTimeKeyIdPointer: UnsafeRawBufferPointer) -> vscr_status_t in

                        return vscr_ratchet_session_initiate(self.c_ctx, senderIdentityPrivateKey.c_ctx, vsc_data(senderIdentityKeyIdPointer.bindMemory(to: byte.self).baseAddress, senderIdentityKeyId.count), receiverIdentityPublicKey.c_ctx, vsc_data(receiverIdentityKeyIdPointer.bindMemory(to: byte.self).baseAddress, receiverIdentityKeyId.count), receiverLongTermPublicKey.c_ctx, vsc_data(receiverLongTermKeyIdPointer.bindMemory(to: byte.self).baseAddress, receiverLongTermKeyId.count), receiverOneTimePublicKey.c_ctx, vsc_data(receiverOneTimeKeyIdPointer.bindMemory(to: byte.self).baseAddress, receiverOneTimeKeyId.count), enablePostQuantum)
                    })
                })
            })
        })

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Initiates session
    @objc public func initiateNoOneTimeKey(senderIdentityPrivateKey: PrivateKey, senderIdentityKeyId: Data, receiverIdentityPublicKey: PublicKey, receiverIdentityKeyId: Data, receiverLongTermPublicKey: PublicKey, receiverLongTermKeyId: Data, enablePostQuantum: Bool) throws {
        let proxyResult = senderIdentityKeyId.withUnsafeBytes({ (senderIdentityKeyIdPointer: UnsafeRawBufferPointer) -> vscr_status_t in
            receiverIdentityKeyId.withUnsafeBytes({ (receiverIdentityKeyIdPointer: UnsafeRawBufferPointer) -> vscr_status_t in
                receiverLongTermKeyId.withUnsafeBytes({ (receiverLongTermKeyIdPointer: UnsafeRawBufferPointer) -> vscr_status_t in

                    return vscr_ratchet_session_initiate_no_one_time_key(self.c_ctx, senderIdentityPrivateKey.c_ctx, vsc_data(senderIdentityKeyIdPointer.bindMemory(to: byte.self).baseAddress, senderIdentityKeyId.count), receiverIdentityPublicKey.c_ctx, vsc_data(receiverIdentityKeyIdPointer.bindMemory(to: byte.self).baseAddress, receiverIdentityKeyId.count), receiverLongTermPublicKey.c_ctx, vsc_data(receiverLongTermKeyIdPointer.bindMemory(to: byte.self).baseAddress, receiverLongTermKeyId.count), enablePostQuantum)
                })
            })
        })

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Responds to session initiation
    @objc public func respond(senderIdentityPublicKey: PublicKey, receiverIdentityPrivateKey: PrivateKey, receiverLongTermPrivateKey: PrivateKey, receiverOneTimePrivateKey: PrivateKey, message: RatchetMessage, enablePostQuantum: Bool) throws {
        let proxyResult = vscr_ratchet_session_respond(self.c_ctx, senderIdentityPublicKey.c_ctx, receiverIdentityPrivateKey.c_ctx, receiverLongTermPrivateKey.c_ctx, receiverOneTimePrivateKey.c_ctx, message.c_ctx, enablePostQuantum)

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Responds to session initiation
    @objc public func respondNoOneTimeKey(senderIdentityPublicKey: PublicKey, receiverIdentityPrivateKey: PrivateKey, receiverLongTermPrivateKey: PrivateKey, message: RatchetMessage, enablePostQuantum: Bool) throws {
        let proxyResult = vscr_ratchet_session_respond_no_one_time_key(self.c_ctx, senderIdentityPublicKey.c_ctx, receiverIdentityPrivateKey.c_ctx, receiverLongTermPrivateKey.c_ctx, message.c_ctx, enablePostQuantum)

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Returns flag that indicates is this session was initiated or responded
    @objc public func isInitiator() -> Bool {
        let proxyResult = vscr_ratchet_session_is_initiator(self.c_ctx)

        return proxyResult
    }

    /// Returns flag that indicates if session is post-quantum
    @objc public func isPqcEnabled() -> Bool {
        let proxyResult = vscr_ratchet_session_is_pqc_enabled(self.c_ctx)

        return proxyResult
    }

    /// Returns true if at least 1 response was successfully decrypted, false - otherwise
    @objc public func receivedFirstResponse() -> Bool {
        let proxyResult = vscr_ratchet_session_received_first_response(self.c_ctx)

        return proxyResult
    }

    /// Returns true if receiver had one time public key
    @objc public func receiverHasOneTimePublicKey() -> Bool {
        let proxyResult = vscr_ratchet_session_receiver_has_one_time_public_key(self.c_ctx)

        return proxyResult
    }

    /// Encrypts data
    @objc public func encrypt(plainText: Data) throws -> RatchetMessage {
        var error: vscr_error_t = vscr_error_t()
        vscr_error_reset(&error)

        let proxyResult = plainText.withUnsafeBytes({ (plainTextPointer: UnsafeRawBufferPointer) in

            return vscr_ratchet_session_encrypt(self.c_ctx, vsc_data(plainTextPointer.bindMemory(to: byte.self).baseAddress, plainText.count), &error)
        })

        try RatchetError.handleStatus(fromC: error.status)

        return RatchetMessage.init(take: proxyResult!)
    }

    /// Calculates size of buffer sufficient to store decrypted message
    @objc public func decryptLen(message: RatchetMessage) -> Int {
        let proxyResult = vscr_ratchet_session_decrypt_len(self.c_ctx, message.c_ctx)

        return proxyResult
    }

    /// Decrypts message
    @objc public func decrypt(message: RatchetMessage) throws -> Data {
        let plainTextCount = self.decryptLen(message: message)
        var plainText = Data(count: plainTextCount)
        let plainTextBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(plainTextBuf)
        }

        let proxyResult = plainText.withUnsafeMutableBytes({ (plainTextPointer: UnsafeMutableRawBufferPointer) -> vscr_status_t in
            vsc_buffer_use(plainTextBuf, plainTextPointer.bindMemory(to: byte.self).baseAddress, plainTextCount)

            return vscr_ratchet_session_decrypt(self.c_ctx, message.c_ctx, plainTextBuf)
        })
        plainText.count = vsc_buffer_len(plainTextBuf)

        try RatchetError.handleStatus(fromC: proxyResult)

        return plainText
    }

    /// Serializes session to buffer
    @objc public func serialize() -> Data {
        let proxyResult = vscr_ratchet_session_serialize(self.c_ctx)

        defer {
            vsc_buffer_delete(proxyResult)
        }

        return Data.init(bytes: vsc_buffer_bytes(proxyResult), count: vsc_buffer_len(proxyResult))
    }

    /// Deserializes session from buffer.
    /// NOTE: Deserialized session needs dependencies to be set. Check setup defaults
    @objc public static func deserialize(input: Data) throws -> RatchetSession {
        var error: vscr_error_t = vscr_error_t()
        vscr_error_reset(&error)

        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafeRawBufferPointer) in

            return vscr_ratchet_session_deserialize(vsc_data(inputPointer.bindMemory(to: byte.self).baseAddress, input.count), &error)
        })

        try RatchetError.handleStatus(fromC: error.status)

        return RatchetSession.init(take: proxyResult!)
    }
}
