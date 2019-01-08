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

/// Virgil Security implementation of the HKDF (RFC 6234) algorithm.
@objc(VSCFHkdf) public class Hkdf: NSObject, SaltedKdf {

    @objc public let hashCounterMax: Int = 255

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_hkdf_new()
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
        self.c_ctx = vscf_hkdf_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_hkdf_delete(self.c_ctx)
    }

    @objc public func setHash(hash: HashStream) {
        vscf_hkdf_release_hash(self.c_ctx)
        vscf_hkdf_use_hash(self.c_ctx, hash.c_ctx)
    }

    /// Derive key of the requested length from the given data, salt and info.
    @objc public func derive(data: Data, salt: Data, info: Data, keyLen: Int) -> Data {
        let keyCount = keyLen
        var key = Data(count: keyCount)
        var keyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(keyBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            salt.withUnsafeBytes({ (saltPointer: UnsafePointer<byte>) -> Void in
                info.withUnsafeBytes({ (infoPointer: UnsafePointer<byte>) -> Void in
                    key.withUnsafeMutableBytes({ (keyPointer: UnsafeMutablePointer<byte>) -> Void in
                        vsc_buffer_init(keyBuf)
                        vsc_buffer_use(keyBuf, keyPointer, keyCount)
                        vscf_hkdf_derive(self.c_ctx, vsc_data(dataPointer, data.count), vsc_data(saltPointer, salt.count), vsc_data(infoPointer, info.count), keyBuf, keyLen)
                    })
                })
            })
        })
        key.count = vsc_buffer_len(keyBuf)

        return key
    }
}
