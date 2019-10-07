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

/// Virgil Security implementation of the PBES2 (RFC 8018) algorithm.
@objc(VSCFPkcs5Pbes2) public class Pkcs5Pbes2: NSObject, Alg, Encrypt, Decrypt {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_pkcs5_pbes2_new()
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
        self.c_ctx = vscf_pkcs5_pbes2_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_pkcs5_pbes2_delete(self.c_ctx)
    }

    @objc public func setKdf(kdf: SaltedKdf) {
        vscf_pkcs5_pbes2_release_kdf(self.c_ctx)
        vscf_pkcs5_pbes2_use_kdf(self.c_ctx, kdf.c_ctx)
    }

    @objc public func setCipher(cipher: Cipher) {
        vscf_pkcs5_pbes2_release_cipher(self.c_ctx)
        vscf_pkcs5_pbes2_use_cipher(self.c_ctx, cipher.c_ctx)
    }

    /// Configure cipher with a new password.
    @objc public func reset(pwd: Data) {
        pwd.withUnsafeBytes({ (pwdPointer: UnsafeRawBufferPointer) -> Void in

            vscf_pkcs5_pbes2_reset(self.c_ctx, vsc_data(pwdPointer.bindMemory(to: byte.self).baseAddress, pwd.count))
        })
    }

    /// Provide algorithm identificator.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_pkcs5_pbes2_alg_id(self.c_ctx)

        return AlgId.init(fromC: proxyResult)
    }

    /// Produce object with algorithm information and configuration parameters.
    @objc public func produceAlgInfo() -> AlgInfo {
        let proxyResult = vscf_pkcs5_pbes2_produce_alg_info(self.c_ctx)

        return FoundationImplementation.wrapAlgInfo(take: proxyResult!)
    }

    /// Restore algorithm configuration from the given object.
    @objc public func restoreAlgInfo(algInfo: AlgInfo) throws {
        let proxyResult = vscf_pkcs5_pbes2_restore_alg_info(self.c_ctx, algInfo.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Encrypt given data.
    @objc public func encrypt(data: Data) throws -> Data {
        let outCount = self.encryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_pkcs5_pbes2_encrypt(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the encrypted data.
    @objc public func encryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_pkcs5_pbes2_encrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Precise length calculation of encrypted data.
    @objc public func preciseEncryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_pkcs5_pbes2_precise_encrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Decrypt given data.
    @objc public func decrypt(data: Data) throws -> Data {
        let outCount = self.decryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_pkcs5_pbes2_decrypt(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the decrypted data.
    @objc public func decryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_pkcs5_pbes2_decrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }
}
