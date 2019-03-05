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
import VirgilCryptoCommon

@objc(VSCFMessageInfoCustomParams) public class MessageInfoCustomParams: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_message_info_custom_params_new()
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
        self.c_ctx = vscf_message_info_custom_params_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_message_info_custom_params_delete(self.c_ctx)
    }

    /// Add custom parameter with integer value.
    @objc public func addInt(key: Data, value: Int32) {
        key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> Void in
            vscf_message_info_custom_params_add_int(self.c_ctx, vsc_data(keyPointer, key.count), value)
        })
    }

    /// Add custom parameter with UTF8 string value.
    @objc public func addString(key: Data, value: Data) {
        key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> Void in
            value.withUnsafeBytes({ (valuePointer: UnsafePointer<byte>) -> Void in
                vscf_message_info_custom_params_add_string(self.c_ctx, vsc_data(keyPointer, key.count), vsc_data(valuePointer, value.count))
            })
        })
    }

    /// Add custom parameter with octet string value.
    @objc public func addData(key: Data, value: Data) {
        key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> Void in
            value.withUnsafeBytes({ (valuePointer: UnsafePointer<byte>) -> Void in
                vscf_message_info_custom_params_add_data(self.c_ctx, vsc_data(keyPointer, key.count), vsc_data(valuePointer, value.count))
            })
        })
    }

    /// Remove all parameters.
    @objc public func clear() {
        vscf_message_info_custom_params_clear(self.c_ctx)
    }

    /// Return custom parameter with integer value.
    @objc public func findInt(key: Data, error: ErrorCtx) -> Int32 {
        let proxyResult = key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> Int32 in
            return vscf_message_info_custom_params_find_int(self.c_ctx, vsc_data(keyPointer, key.count), error.c_ctx)
        })

        return proxyResult
    }

    /// Return custom parameter with UTF8 string value.
    @objc public func findString(key: Data, error: ErrorCtx) -> Data {
        let proxyResult = key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) in
            return vscf_message_info_custom_params_find_string(self.c_ctx, vsc_data(keyPointer, key.count), error.c_ctx)
        })

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Return custom parameter with octet string value.
    @objc public func findData(key: Data, error: ErrorCtx) -> Data {
        let proxyResult = key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) in
            return vscf_message_info_custom_params_find_data(self.c_ctx, vsc_data(keyPointer, key.count), error.c_ctx)
        })

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }
}
