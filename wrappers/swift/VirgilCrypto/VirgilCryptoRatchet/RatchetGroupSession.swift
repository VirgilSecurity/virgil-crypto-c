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

    /// Random used to generate keys
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

    /// Sets up session. Identity private key should be set separately.
    @objc public func setupSession(myId: Data, message: RatchetGroupMessage) throws {
        let proxyResult = myId.withUnsafeBytes({ (myIdPointer: UnsafeRawBufferPointer) -> vscr_status_t in

            return vscr_ratchet_group_session_setup_session(self.c_ctx, vsc_data(myIdPointer.bindMemory(to: byte.self).baseAddress, myId.count), message.c_ctx)
        })

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
    @objc public func decrypt(message: RatchetGroupMessage) throws -> Data {
        let plainTextCount = self.decryptLen(message: message)
        var plainText = Data(count: plainTextCount)
        var plainTextBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(plainTextBuf)
        }

        let proxyResult = plainText.withUnsafeMutableBytes({ (plainTextPointer: UnsafeMutableRawBufferPointer) -> vscr_status_t in
            vsc_buffer_init(plainTextBuf)
            vsc_buffer_use(plainTextBuf, plainTextPointer.bindMemory(to: byte.self).baseAddress, plainTextCount)

            return vscr_ratchet_group_session_decrypt(self.c_ctx, message.c_ctx, plainTextBuf)
        })
        plainText.count = vsc_buffer_len(plainTextBuf)

        try RatchetError.handleStatus(fromC: proxyResult)

        return plainText
    }

    /// Calculates size of buffer sufficient to store session
    @objc public func serializeLen() -> Int {
        let proxyResult = vscr_ratchet_group_session_serialize_len(self.c_ctx)

        return proxyResult
    }

    /// Serializes session to buffer
    @objc public func serialize() -> Data {
        let outputCount = self.serializeLen()
        var output = Data(count: outputCount)
        var outputBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outputBuf)
        }

        output.withUnsafeMutableBytes({ (outputPointer: UnsafeMutableRawBufferPointer) -> Void in
            vsc_buffer_init(outputBuf)
            vsc_buffer_use(outputBuf, outputPointer.bindMemory(to: byte.self).baseAddress, outputCount)

            vscr_ratchet_group_session_serialize(self.c_ctx, outputBuf)
        })
        output.count = vsc_buffer_len(outputBuf)

        return output
    }

    /// Deserializes session from buffer.
    /// NOTE: Deserialized session needs dependencies to be set. Check setup defaults
    @objc public static func deserialize(input: Data) throws -> RatchetGroupSession {
        var error: vscr_error_t = vscr_error_t()
        vscr_error_reset(&error)

        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafeRawBufferPointer) in

            return vscr_ratchet_group_session_deserialize(vsc_data(inputPointer.bindMemory(to: byte.self).baseAddress, input.count), &error)
        })

        try RatchetError.handleStatus(fromC: error.status)

        return RatchetGroupSession.init(take: proxyResult!)
    }
}
