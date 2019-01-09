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

/// Provides interface to the stateless MAC (message authentication code) algorithms.
@objc(VSCFMac) public protocol Mac : MacInfo {

    /// Calculate MAC over given data.
    @objc func mac(key: Data, data: Data) -> Data
}

/// Implement interface methods
@objc(VSCFMacProxy) internal class MacProxy: NSObject, Mac {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Take C context that implements this interface
    public init(c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_impl_delete(self.c_ctx)
    }

    /// Size of the digest (mac output) in bytes.
    @objc public func digestLen() -> Int {
        let proxyResult = vscf_mac_info_digest_len(self.c_ctx)

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
                    vscf_mac(self.c_ctx, vsc_data(keyPointer, key.count), vsc_data(dataPointer, data.count), macBuf)
                })
            })
        })
        mac.count = vsc_buffer_len(macBuf)

        return mac
    }
}
