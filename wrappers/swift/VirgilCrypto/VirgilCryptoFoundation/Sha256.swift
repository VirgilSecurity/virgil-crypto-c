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

/// This is MbedTLS implementation of SHA256.
@objc(VSCFSha256) public class Sha256: NSObject, HashInfo, Hash, HashStream, AlgInfoCompatible {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Length of the digest (hashing output) in bytes.
    @objc public let digestLen: Int = 32

    /// Block length of the digest function in bytes.
    @objc public let blockLen: Int = 64

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_sha256_new()
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
        self.c_ctx = vscf_sha256_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_sha256_delete(self.c_ctx)
    }

    /// Return implemented hash algorithm type.
    @objc public func alg() -> HashAlg {
        let proxyResult = vscf_sha256_alg()

        return HashAlg.init(fromC: proxyResult)
    }

    /// Calculate hash over given data.
    @objc public func hash(data: Data) -> Data {
        let digestCount = self.digestLen
        var digest = Data(count: digestCount)
        var digestBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(digestBuf)
        }

        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            digest.withUnsafeMutableBytes({ (digestPointer: UnsafeMutablePointer<byte>) -> Void in
                vsc_buffer_init(digestBuf)
                vsc_buffer_use(digestBuf, digestPointer, digestCount)
                vscf_sha256_hash(vsc_data(dataPointer, data.count), digestBuf)
            })
        })
        digest.count = vsc_buffer_len(digestBuf)

        return digest
    }

    /// Start a new hashing.
    @objc public func start() {
        vscf_sha256_start(self.c_ctx)
    }

    /// Add given data to the hash.
    @objc public func update(data: Data) {
        data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> Void in
            vscf_sha256_update(self.c_ctx, vsc_data(dataPointer, data.count))
        })
    }

    /// Accompilsh hashing and return it's result (a message digest).
    @objc public func finish() -> Data {
        let digestCount = self.digestLen
        var digest = Data(count: digestCount)
        var digestBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(digestBuf)
        }

        digest.withUnsafeMutableBytes({ (digestPointer: UnsafeMutablePointer<byte>) -> Void in
            vsc_buffer_init(digestBuf)
            vsc_buffer_use(digestBuf, digestPointer, digestCount)
            vscf_sha256_finish(self.c_ctx, digestBuf)
        })
        digest.count = vsc_buffer_len(digestBuf)

        return digest
    }

    /// Produce algorithm information structure
    @objc public func produceAlgInfo() -> AlgInfo {
        let proxyResult = vscf_sha256_produce_alg_info(self.c_ctx)

        return AlgInfoProxy.init(c_ctx: proxyResult!)
    }
}
