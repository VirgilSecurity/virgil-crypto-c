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

/// Provides interface to the key derivation function (KDF) algorithms
/// that use salt and teration count.
@objc(VSCFSaltedKdf) public protocol SaltedKdf : Kdf {

    /// Prepare algorithm to derive new key.
    @objc func reset(salt: Data, iterationCount: Int)

    /// Setup application specific information (optional).
    /// Can be empty.
    @objc func setInfo(info: Data)
}

/// Implement interface methods
@objc(VSCFSaltedKdfProxy) internal class SaltedKdfProxy: NSObject, SaltedKdf {

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

    /// Derive key of the requested length from the given data.
    @objc public func derive(data: Data, keyLen: Int) -> Data {
        let keyCount = keyLen
        var key = Data(count: keyCount)
        var keyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(keyBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            key.withUnsafeMutableBytes({ (keyPointer: UnsafeMutablePointer<byte>) -> Void in
                vsc_buffer_init(keyBuf)
                vsc_buffer_use(keyBuf, keyPointer, keyCount)

                vscf_kdf_derive(self.c_ctx, vsc_data(dataPointer, data.count), keyLen, keyBuf)
            })
        })
        key.count = vsc_buffer_len(keyBuf)

        return key
    }

    /// Prepare algorithm to derive new key.
    @objc public func reset(salt: Data, iterationCount: Int) {
        salt.withUnsafeBytes({ (saltPointer: UnsafePointer<byte>) -> Void in

            vscf_salted_kdf_reset(self.c_ctx, vsc_data(saltPointer, salt.count), iterationCount)
        })
    }

    /// Setup application specific information (optional).
    /// Can be empty.
    @objc public func setInfo(info: Data) {
        info.withUnsafeBytes({ (infoPointer: UnsafePointer<byte>) -> Void in

            vscf_salted_kdf_set_info(self.c_ctx, vsc_data(infoPointer, info.count))
        })
    }
}
