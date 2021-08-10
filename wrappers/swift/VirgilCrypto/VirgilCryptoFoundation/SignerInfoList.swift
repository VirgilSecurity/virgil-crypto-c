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

/// Handles a list of "signer info" class objects.
@objc(VSCFSignerInfoList) public class SignerInfoList: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_signer_info_list_new()
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
        self.c_ctx = vscf_signer_info_list_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_signer_info_list_delete(self.c_ctx)
    }

    /// Return true if given list has item.
    @objc public func hasItem() -> Bool {
        let proxyResult = vscf_signer_info_list_has_item(self.c_ctx)

        return proxyResult
    }

    /// Return list item.
    @objc public func item() -> SignerInfo {
        let proxyResult = vscf_signer_info_list_item(self.c_ctx)

        return SignerInfo.init(use: proxyResult!)
    }

    /// Return true if list has next item.
    @objc public func hasNext() -> Bool {
        let proxyResult = vscf_signer_info_list_has_next(self.c_ctx)

        return proxyResult
    }

    /// Return next list node if exists, or NULL otherwise.
    @objc public func next() -> SignerInfoList {
        let proxyResult = vscf_signer_info_list_next(self.c_ctx)

        return SignerInfoList.init(take: proxyResult!)
    }

    /// Return true if list has previous item.
    @objc public func hasPrev() -> Bool {
        let proxyResult = vscf_signer_info_list_has_prev(self.c_ctx)

        return proxyResult
    }

    /// Return previous list node if exists, or NULL otherwise.
    @objc public func prev() -> SignerInfoList {
        let proxyResult = vscf_signer_info_list_prev(self.c_ctx)

        return SignerInfoList.init(take: proxyResult!)
    }

    /// Remove all items.
    @objc public func clear() {
        vscf_signer_info_list_clear(self.c_ctx)
    }
}
