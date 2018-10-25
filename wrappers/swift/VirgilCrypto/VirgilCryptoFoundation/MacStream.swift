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

/// Provides interface to the MAC (message authentication code) algorithms.
@objc(VSCFMacStream) public protocol MacStream : MacInfo {

    @objc func start(key: Data)

    @objc func update(data: Data)

    @objc func finish() -> Data

    @objc func reset()
}

/// Implement interface methods
@objc(VSCFMacStreamProxy) internal class MacStreamProxy: NSObject, MacStream {

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

    /// Start a new MAC.
    @objc public func start(key: Data) {
        key.withUnsafeBytes({ (keyPointer: UnsafePointer<byte>) -> Void in
            vscf_mac_stream_start(self.c_ctx, vsc_data(keyPointer, key.count))
        })
    }

    /// Add given data to the MAC.
    @objc public func update(data: Data) {
        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            vscf_mac_stream_update(self.c_ctx, vsc_data(dataPointer, data.count))
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
            vscf_mac_stream_finish(self.c_ctx, macBuf)
        })

        return mac
    }

    /// Prepare to authenticate a new message with the same key
    /// as the previous MAC operation.
    @objc public func reset() {
        vscf_mac_stream_reset(self.c_ctx)
    }
}
