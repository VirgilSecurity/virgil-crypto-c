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

/// Sign data of any size.
@objc(VSCFSigner) public class Signer: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_signer_new()
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
        self.c_ctx = vscf_signer_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_signer_delete(self.c_ctx)
    }

    @objc public func setHash(hash: Hash) {
        vscf_signer_release_hash(self.c_ctx)
        vscf_signer_use_hash(self.c_ctx, hash.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_signer_release_random(self.c_ctx)
        vscf_signer_use_random(self.c_ctx, random.c_ctx)
    }

    /// Start a processing a new signature.
    @objc public func reset() {
        vscf_signer_reset(self.c_ctx)
    }

    /// Add given data to the signed data.
    @objc public func appendData(data: Data) {
        data.withUnsafeBytes({ (dataPointer: UnsafeRawBufferPointer) -> Void in

            vscf_signer_append_data(self.c_ctx, vsc_data(dataPointer.bindMemory(to: byte.self).baseAddress, data.count))
        })
    }

    /// Return length of the signature.
    @objc public func signatureLen(privateKey: PrivateKey) -> Int {
        let proxyResult = vscf_signer_signature_len(self.c_ctx, privateKey.c_ctx)

        return proxyResult
    }

    /// Accomplish signing and return signature.
    @objc public func sign(privateKey: PrivateKey) throws -> Data {
        let signatureCount = self.signatureLen(privateKey: privateKey)
        var signature = Data(count: signatureCount)
        var signatureBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(signatureBuf)
        }

        let proxyResult = signature.withUnsafeMutableBytes({ (signaturePointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(signatureBuf, signaturePointer.bindMemory(to: byte.self).baseAddress, signatureCount)

            return vscf_signer_sign(self.c_ctx, privateKey.c_ctx, signatureBuf)
        })
        signature.count = vsc_buffer_len(signatureBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return signature
    }
}
