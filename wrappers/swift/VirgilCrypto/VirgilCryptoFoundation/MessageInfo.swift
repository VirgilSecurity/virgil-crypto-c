/// Copyright (C) 2015-2022 Virgil Security, Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
/// (1) Redistributions of source code must retain the above copyright
/// notice, this list of conditions and the following disclaimer.
///
/// (2) Redistributions in binary form must reproduce the above copyright
/// notice, this list of conditions and the following disclaimer in
/// the documentation and/or other materials provided with the
/// distribution.
///
/// (3) Neither the name of the copyright holder nor the names of its
/// contributors may be used to endorse or promote products derived from
/// this software without specific prior written permission.
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

@objc(VSCFMessageInfo) public class MessageInfo: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    public override init() {
        self.c_ctx = vscf_message_info_new()
        super.init()
    }

    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_message_info_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_message_info_delete(self.c_ctx)
    }

    @objc public func dataEncryptionAlgInfo() -> AlgInfo {
        let proxyResult = vscf_message_info_data_encryption_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(use: proxyResult!)
    }

    @objc public func keyRecipientInfoList() -> KeyRecipientInfoList {
        let proxyResult = vscf_message_info_key_recipient_info_list(self.c_ctx)

        return KeyRecipientInfoList.init(use: proxyResult!)
    }

    @objc public func passwordRecipientInfoList() -> PasswordRecipientInfoList {
        let proxyResult = vscf_message_info_password_recipient_info_list(self.c_ctx)

        return PasswordRecipientInfoList.init(use: proxyResult!)
    }

    @objc public func hasCustomParams() -> Bool {
        let proxyResult = vscf_message_info_has_custom_params(self.c_ctx)

        return proxyResult
    }

    @objc public func customParams() -> MessageInfoCustomParams {
        let proxyResult = vscf_message_info_custom_params(self.c_ctx)

        return MessageInfoCustomParams.init(use: proxyResult!)
    }

    @objc public func hasCipherKdfAlgInfo() -> Bool {
        let proxyResult = vscf_message_info_has_cipher_kdf_alg_info(self.c_ctx)

        return proxyResult
    }

    @objc public func cipherKdfAlgInfo() -> AlgInfo {
        let proxyResult = vscf_message_info_cipher_kdf_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(use: proxyResult!)
    }

    @objc public func hasCipherPaddingAlgInfo() -> Bool {
        let proxyResult = vscf_message_info_has_cipher_padding_alg_info(self.c_ctx)

        return proxyResult
    }

    @objc public func cipherPaddingAlgInfo() -> AlgInfo {
        let proxyResult = vscf_message_info_cipher_padding_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(use: proxyResult!)
    }

    @objc public func hasFooterInfo() -> Bool {
        let proxyResult = vscf_message_info_has_footer_info(self.c_ctx)

        return proxyResult
    }

    @objc public func footerInfo() -> FooterInfo {
        let proxyResult = vscf_message_info_footer_info(self.c_ctx)

        return FooterInfo.init(use: proxyResult!)
    }

    @objc public func clear() {
        vscf_message_info_clear(self.c_ctx)
    }

}
