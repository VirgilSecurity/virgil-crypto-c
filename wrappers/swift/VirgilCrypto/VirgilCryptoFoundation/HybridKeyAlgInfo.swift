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

/// Handle information about hybrid key algorithm.
@objc(VSCFHybridKeyAlgInfo) public class HybridKeyAlgInfo: NSObject, AlgInfo {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_hybrid_key_alg_info_new()
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
        self.c_ctx = vscf_hybrid_key_alg_info_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_hybrid_key_alg_info_delete(self.c_ctx)
    }

    /// Return algorithm information about the first key.
    @objc public func firstKeyAlgInfo() -> AlgInfo {
        let proxyResult = vscf_hybrid_key_alg_info_first_key_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(use: proxyResult!)
    }

    /// Return algorithm information about the second key.
    @objc public func secondKeyAlgInfo() -> AlgInfo {
        let proxyResult = vscf_hybrid_key_alg_info_second_key_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(use: proxyResult!)
    }

    /// Provide algorithm identificator.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_hybrid_key_alg_info_alg_id(self.c_ctx)

        return AlgId.init(fromC: proxyResult)
    }
}
