// Copyright (C) 2015-2026 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


import Foundation
import VSCFoundation

@objc(VSCFShamir) public class Shamir: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    public override init() {
        self.c_ctx = vscf_shamir_new()
        super.init()
    }

    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_shamir_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_shamir_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_shamir_release_random(self.c_ctx)
        vscf_shamir_use_random(self.c_ctx, random.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies:
    /// a CTR DRBG random number generator.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_shamir_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    /// Calculate an upper bound on the length in bytes of a single share
    /// produced for a secret of the given length. The buffer given to 'split'
    /// must be at least this size; the actual written length may be a few
    /// bytes smaller.
    @objc public func shareLen(secretLen: Int) -> Int {
        let proxyResult = vscf_shamir_share_len(self.c_ctx, secretLen)

        return proxyResult
    }

    /// Calculate an upper bound on the length in bytes of the buffer needed to
    /// hold all shares produced by 'split' for a secret of the given length and
    /// the given number of shares. The actual written length is reported on the
    /// output buffer by 'split'.
    @objc public func sharesLen(secretLen: Int, shareCount: Int) -> Int {
        let proxyResult = vscf_shamir_shares_len(self.c_ctx, secretLen, shareCount)

        return proxyResult
    }

    /// Calculate an upper bound on the length in bytes of the recovered secret
    /// for the given total shares length and number of provided shares.
    /// The exact length is set on the output buffer by 'combine'.
    @objc public func recoveredSecretLen(sharesLen: Int, shareCount: Int) -> Int {
        let proxyResult = vscf_shamir_recovered_secret_len(self.c_ctx, sharesLen, shareCount)

        return proxyResult
    }

    /// Split the given secret into 'share count' shares with reconstruction
    /// 'threshold'. Requires a configured random number generator (see
    /// 'setup defaults' / 'use random').
    ///
    /// Constraints: 1 <= threshold <= share count <= 255.
    ///
    /// The produced shares are written consecutively to 'out', all of equal
    /// length and each at most 'share len(secret.len)' bytes.
    @objc public func split(secret: Data, threshold: Int, shareCount: Int) throws -> Data {
        let outCount = self.sharesLen(secretLen: secret.count, shareCount: shareCount)
        var out = Data(count: outCount)
        let outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = secret.withUnsafeBytes({ (secretPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return out.withUnsafeMutableBytes({ (outPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(outBuf, outPointer.bindMemory(to: byte.self).baseAddress, outCount)

                return vscf_shamir_split(self.c_ctx, vsc_data(secretPointer.bindMemory(to: byte.self).baseAddress, secret.count), threshold, shareCount, outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return out
    }

    /// Reconstruct the secret from 'share count' shares concatenated in
    /// 'shares'. 'share count' must be at least the threshold used at split
    /// time.
    ///
    /// Returns 'success' and writes the secret to 'secret' on success.
    /// Returns 'error bad arguments' if the shares are structurally invalid
    /// (malformed/short input, inconsistent or duplicated shares, or shares
    /// that do not belong to the same split). Returns 'error shamir recovery
    /// failed' if the shares are structurally valid but cryptographically
    /// wrong, tampered, or insufficient to meet the threshold. On any failure
    /// the output buffer is left empty.
    @objc public func combine(shares: Data, shareCount: Int) throws -> Data {
        let secretCount = self.recoveredSecretLen(sharesLen: shares.count, shareCount: shareCount)
        var secret = Data(count: secretCount)
        let secretBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(secretBuf)
        }

        let proxyResult = shares.withUnsafeBytes({ (sharesPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return secret.withUnsafeMutableBytes({ (secretPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(secretBuf, secretPointer.bindMemory(to: byte.self).baseAddress, secretCount)

                return vscf_shamir_combine(self.c_ctx, vsc_data(sharesPointer.bindMemory(to: byte.self).baseAddress, shares.count), shareCount, secretBuf)
            })
        })
        secret.count = vsc_buffer_len(secretBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return secret
    }

}
