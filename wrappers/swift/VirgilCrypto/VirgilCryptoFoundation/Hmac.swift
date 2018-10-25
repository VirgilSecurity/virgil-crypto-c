/// Copyright (C) 2015-2018 Virgil Security Inc.
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

/// Virgil Security implementation of HMAC algorithm (RFC 2104) (FIPS PUB 198-1).
@objc(VSCFHmac) public class Hmac: NSObject, MacInfo, Mac, MacStream {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_hmac_new()
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
        self.c_ctx = vscf_hmac_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_hmac_delete(self.c_ctx)
    }

    @objc public func setHash(hash: HashStream) {
        vscf_hmac_use_hash(self.c_ctx, hash.c_ctx)
    }

    /// Size of the digest (mac output) in bytes.
    @objc public func digestLen() -> Int {
        let proxyResult = vscf_hmac_digest_len(self.c_ctx)
        return proxyResult
    }

    /// Calculate MAC over given data.
    @objc public func mac(key: Data, data: Data) -> Data {
        let macCount = self.digestLen()
        var mac = Data(count: macCount)
        var macBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(macBuf)
        }

        key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> Void in
            data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
                mac.withUnsafeMutableBytes({ (macPointer: UnsafeMutablePointer<byte>) -> Void in
                    vsc_buffer_init(macBuf)
                    vsc_buffer_use(macBuf, macPointer, macCount)
                    vscf_hmac_mac(self.c_ctx, vsc_data(keyPointer, key.count), vsc_data(dataPointer, data.count), macBuf)
                })
            })
        })

        return mac
    }

    /// Start a new MAC.
    @objc public func start(key: Data) {
        key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> Void in
            vscf_hmac_start(self.c_ctx, vsc_data(keyPointer, key.count))
        })
    }

    /// Add given data to the MAC.
    @objc public func update(data: Data) {
        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            vscf_hmac_update(self.c_ctx, vsc_data(dataPointer, data.count))
        })
    }

    /// Accomplish MAC and return it's result (a message digest).
    @objc public func finish() -> Data {
        let macCount = self.digestLen()
        var mac = Data(count: macCount)
        var macBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(macBuf)
        }

        mac.withUnsafeMutableBytes({ (macPointer: UnsafeMutablePointer<byte>) -> Void in
            vsc_buffer_init(macBuf)
            vsc_buffer_use(macBuf, macPointer, macCount)
            vscf_hmac_finish(self.c_ctx, macBuf)
        })

        return mac
    }

    /// Prepare to authenticate a new message with the same key
    /// as the previous MAC operation.
    @objc public func reset() {
        vscf_hmac_reset(self.c_ctx)
    }
}
