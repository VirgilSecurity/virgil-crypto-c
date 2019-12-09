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
import VSCFoundation

/// Handle information about an encrypted message and algorithms
/// that was used for encryption.
@objc(VSCFMessageInfo) public class MessageInfo: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_message_info_new()
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
        self.c_ctx = vscf_message_info_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_message_info_delete(self.c_ctx)
    }

    /// Return information about algorithm that was used for the data encryption.
    @objc public func dataEncryptionAlgInfo() -> AlgInfo {
        let proxyResult = vscf_message_info_data_encryption_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(use: proxyResult!)
    }

    /// Return list with a "key recipient info" elements.
    @objc public func keyRecipientInfoList() -> KeyRecipientInfoList {
        let proxyResult = vscf_message_info_key_recipient_info_list(self.c_ctx)

        return KeyRecipientInfoList.init(use: proxyResult!)
    }

    /// Return list with a "password recipient info" elements.
    @objc public func passwordRecipientInfoList() -> PasswordRecipientInfoList {
        let proxyResult = vscf_message_info_password_recipient_info_list(self.c_ctx)

        return PasswordRecipientInfoList.init(use: proxyResult!)
    }

    /// Return true if message info contains at least one custom param.
    @objc public func hasCustomParams() -> Bool {
        let proxyResult = vscf_message_info_has_custom_params(self.c_ctx)

        return proxyResult
    }

    /// Provide access to the custom params object.
    /// The returned object can be used to add custom params or read it.
    /// If custom params object was not set then new empty object is created.
    @objc public func customParams() -> MessageInfoCustomParams {
        let proxyResult = vscf_message_info_custom_params(self.c_ctx)

        return MessageInfoCustomParams.init(use: proxyResult!)
    }

    /// Return true if cipher kdf alg info exists.
    @objc public func hasCipherKdfAlgInfo() -> Bool {
        let proxyResult = vscf_message_info_has_cipher_kdf_alg_info(self.c_ctx)

        return proxyResult
    }

    /// Return cipher kdf alg info.
    @objc public func cipherKdfAlgInfo() -> AlgInfo {
        let proxyResult = vscf_message_info_cipher_kdf_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(use: proxyResult!)
    }

    /// Return true if cipher padding alg info exists.
    @objc public func hasCipherPaddingAlgInfo() -> Bool {
        let proxyResult = vscf_message_info_has_cipher_padding_alg_info(self.c_ctx)

        return proxyResult
    }

    /// Return cipher padding alg info.
    @objc public func cipherPaddingAlgInfo() -> AlgInfo {
        let proxyResult = vscf_message_info_cipher_padding_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(use: proxyResult!)
    }

    /// Return true if footer info exists.
    @objc public func hasFooterInfo() -> Bool {
        let proxyResult = vscf_message_info_has_footer_info(self.c_ctx)

        return proxyResult
    }

    /// Return footer info.
    @objc public func footerInfo() -> FooterInfo {
        let proxyResult = vscf_message_info_footer_info(self.c_ctx)

        return FooterInfo.init(use: proxyResult!)
    }

    /// Remove all infos.
    @objc public func clear() {
        vscf_message_info_clear(self.c_ctx)
    }
}
