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

/// Handle information about signed data.
@objc(VSCFSignedDataInfo) public class SignedDataInfo: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_signed_data_info_new()
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
        self.c_ctx = vscf_signed_data_info_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_signed_data_info_delete(self.c_ctx)
    }

    /// Set information about algorithm that was used to produce data digest.
    @objc public func setHashAlgInfo(hashAlgInfo: AlgInfo) {
        var hashAlgInfoCopy = vscf_impl_shallow_copy(hashAlgInfo.c_ctx)

        vscf_signed_data_info_set_hash_alg_info(self.c_ctx, &hashAlgInfoCopy)
    }

    /// Return information about algorithm that was used to produce data digest.
    @objc public func hashAlgInfo() -> AlgInfo {
        let proxyResult = vscf_signed_data_info_hash_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(take: proxyResult!)
    }

    /// Setup signed custom params.
    @objc public func setCustomParams(customParams: MessageInfoCustomParams) {
        var customParamsCopy = vscf_message_info_custom_params_shallow_copy(customParams.c_ctx)

        vscf_signed_data_info_set_custom_params(self.c_ctx, &customParamsCopy)
    }

    /// Provide access to the signed custom params object.
    /// The returned object can be used to add custom params or read it.
    /// If custom params object was not set then new empty object is created.
    @objc public func customParams() -> MessageInfoCustomParams {
        let proxyResult = vscf_signed_data_info_custom_params(self.c_ctx)

        return MessageInfoCustomParams.init(use: proxyResult!)
    }

    /// Set data size.
    @objc public func setDataSize(dataSize: Int) {
        vscf_signed_data_info_set_data_size(self.c_ctx, dataSize)
    }

    /// Return data size.
    @objc public func dataSize() -> Int {
        let proxyResult = vscf_signed_data_info_data_size(self.c_ctx)

        return proxyResult
    }
}
