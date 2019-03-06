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

/// Provide interface for authenticated data encryption.
@objc(VSCFAuthEncrypt) public protocol AuthEncrypt : CipherAuthInfo {

    /// Encrypt given data.
    /// If 'tag' is not give, then it will written to the 'enc'.
    @objc func authEncrypt(data: Data, authData: Data) throws -> AuthEncryptAuthEncryptResult

    /// Calculate required buffer length to hold the authenticated encrypted data.
    @objc func authEncryptedLen(dataLen: Int) -> Int
}

/// Encapsulate result of method AuthEncrypt.authEncrypt()
@objc(VSCFAuthEncryptAuthEncryptResult) public class AuthEncryptAuthEncryptResult: NSObject {

    @objc public let out: Data

    @objc public let tag: Data

    /// Initialize all properties.
    internal init(out: Data, tag: Data) {
        self.out = out
        self.tag = tag
        super.init()
    }
}

/// Implement interface methods
@objc(VSCFAuthEncryptProxy) internal class AuthEncryptProxy: NSObject, AuthEncrypt {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Defines authentication tag length in bytes.
    @objc public var authTagLen: Int {
        return vscf_cipher_auth_info_auth_tag_len(vscf_cipher_auth_info_api(self.c_ctx))
    }

    /// Take C context that implements this interface
    public init(c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_impl_delete(self.c_ctx)
    }

    /// Encrypt given data.
    /// If 'tag' is not give, then it will written to the 'enc'.
    @objc public func authEncrypt(data: Data, authData: Data) throws -> AuthEncryptAuthEncryptResult {
        let outCount = self.authEncryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let tagCount = self.authTagLen
        var tag = Data(count: tagCount)
        var tagBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(tagBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_status_t in
            authData.withUnsafeBytes({ (authDataPointer: UnsafePointer<byte>) -> vscf_status_t in
                out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_status_t in
                    tag.withUnsafeMutableBytes({ (tagPointer: UnsafeMutablePointer<byte>) -> vscf_status_t in
                        vsc_buffer_init(outBuf)
                        vsc_buffer_use(outBuf, outPointer, outCount)

                        vsc_buffer_init(tagBuf)
                        vsc_buffer_use(tagBuf, tagPointer, tagCount)
                        return vscf_auth_encrypt(self.c_ctx, vsc_data(dataPointer, data.count), vsc_data(authDataPointer, authData.count), outBuf, tagBuf)
                    })
                })
            })
        })
        out.count = vsc_buffer_len(outBuf)
        tag.count = vsc_buffer_len(tagBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return AuthEncryptAuthEncryptResult(out: out, tag: tag)
    }

    /// Calculate required buffer length to hold the authenticated encrypted data.
    @objc public func authEncryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_auth_encrypt_auth_encrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }
}
