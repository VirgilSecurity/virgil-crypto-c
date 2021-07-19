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

/// Add and/or remove recipients and it's parameters within message info.
///
/// Usage:
///   1. Unpack binary message info that was obtained from RecipientCipher.
///   2. Add and/or remove key recipients.
///   3. Pack MessagInfo to the binary data.
@objc(VSCFMessageInfoEditor) public class MessageInfoEditor: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_message_info_editor_new()
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
        self.c_ctx = vscf_message_info_editor_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_message_info_editor_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_message_info_editor_release_random(self.c_ctx)
        vscf_message_info_editor_use_random(self.c_ctx, random.c_ctx)
    }

    /// Set dependencies to it's defaults.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_message_info_editor_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Unpack serialized message info.
    ///
    /// Note that recipients can only be removed but not added.
    /// Note, use "unlock" method to be able to add new recipients as well.
    @objc public func unpack(messageInfoData: Data) throws {
        let proxyResult = messageInfoData.withUnsafeBytes({ (messageInfoDataPointer: UnsafeRawBufferPointer) -> vscf_status_t in

            return vscf_message_info_editor_unpack(self.c_ctx, vsc_data(messageInfoDataPointer.bindMemory(to: byte.self).baseAddress, messageInfoData.count))
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Decrypt encryption key this allows adding new recipients.
    @objc public func unlock(ownerRecipientId: Data, ownerPrivateKey: PrivateKey) throws {
        let proxyResult = ownerRecipientId.withUnsafeBytes({ (ownerRecipientIdPointer: UnsafeRawBufferPointer) -> vscf_status_t in

            return vscf_message_info_editor_unlock(self.c_ctx, vsc_data(ownerRecipientIdPointer.bindMemory(to: byte.self).baseAddress, ownerRecipientId.count), ownerPrivateKey.c_ctx)
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Add recipient defined with id and public key.
    @objc public func addKeyRecipient(recipientId: Data, publicKey: PublicKey) throws {
        let proxyResult = recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafeRawBufferPointer) -> vscf_status_t in

            return vscf_message_info_editor_add_key_recipient(self.c_ctx, vsc_data(recipientIdPointer.bindMemory(to: byte.self).baseAddress, recipientId.count), publicKey.c_ctx)
        })

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Remove recipient with a given id.
    /// Return false if recipient with given id was not found.
    @objc public func removeKeyRecipient(recipientId: Data) -> Bool {
        let proxyResult = recipientId.withUnsafeBytes({ (recipientIdPointer: UnsafeRawBufferPointer) -> Bool in

            return vscf_message_info_editor_remove_key_recipient(self.c_ctx, vsc_data(recipientIdPointer.bindMemory(to: byte.self).baseAddress, recipientId.count))
        })

        return proxyResult
    }

    /// Remove all existent recipients.
    @objc public func removeAll() {
        vscf_message_info_editor_remove_all(self.c_ctx)
    }

    /// Return length of serialized message info.
    /// Actual length can be obtained right after applying changes.
    @objc public func packedLen() -> Int {
        let proxyResult = vscf_message_info_editor_packed_len(self.c_ctx)

        return proxyResult
    }

    /// Return serialized message info.
    /// Precondition: this method can be called after "apply".
    @objc public func pack() -> Data {
        let messageInfoCount = self.packedLen()
        var messageInfo = Data(count: messageInfoCount)
        let messageInfoBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(messageInfoBuf)
        }

        messageInfo.withUnsafeMutableBytes({ (messageInfoPointer: UnsafeMutableRawBufferPointer) -> Void in
            vsc_buffer_use(messageInfoBuf, messageInfoPointer.bindMemory(to: byte.self).baseAddress, messageInfoCount)

            vscf_message_info_editor_pack(self.c_ctx, messageInfoBuf)
        })
        messageInfo.count = vsc_buffer_len(messageInfoBuf)

        return messageInfo
    }
}
