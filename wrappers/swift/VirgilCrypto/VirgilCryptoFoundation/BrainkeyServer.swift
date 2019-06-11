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

@objc(VSCFBrainkeyServer) public class BrainkeyServer: NSObject {

    @objc public static let pointLen: Int = 65
    @objc public static let mpiLen: Int = 32

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_brainkey_server_new()
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
        self.c_ctx = vscf_brainkey_server_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_brainkey_server_delete(self.c_ctx)
    }

    /// Random used for key generation, proofs, etc.
    @objc public func setRandom(random: Random) {
        vscf_brainkey_server_release_random(self.c_ctx)
        vscf_brainkey_server_use_random(self.c_ctx, random.c_ctx)
    }

    /// Random used for crypto operations to make them const-time
    @objc public func setOperationRandom(operationRandom: Random) {
        vscf_brainkey_server_release_operation_random(self.c_ctx)
        vscf_brainkey_server_use_operation_random(self.c_ctx, operationRandom.c_ctx)
    }

    @objc public func setupDefaults() throws {
        let proxyResult = vscf_brainkey_server_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    @objc public func generateIdentitySecret() throws -> Data {
        let identitySecretCount = BrainkeyServer.mpiLen
        var identitySecret = Data(count: identitySecretCount)
        var identitySecretBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(identitySecretBuf)
        }

        let proxyResult = identitySecret.withUnsafeMutableBytes({ (identitySecretPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_init(identitySecretBuf)
            vsc_buffer_use(identitySecretBuf, identitySecretPointer.bindMemory(to: byte.self).baseAddress, identitySecretCount)

            return vscf_brainkey_server_generate_identity_secret(self.c_ctx, identitySecretBuf)
        })
        identitySecret.count = vsc_buffer_len(identitySecretBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return identitySecret
    }

    @objc public func harden(identitySecret: Data, blindedPoint: Data) throws -> Data {
        let hardenedPointCount = BrainkeyServer.pointLen
        var hardenedPoint = Data(count: hardenedPointCount)
        var hardenedPointBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(hardenedPointBuf)
        }

        let proxyResult = identitySecret.withUnsafeBytes({ (identitySecretPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            blindedPoint.withUnsafeBytes({ (blindedPointPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                hardenedPoint.withUnsafeMutableBytes({ (hardenedPointPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                    vsc_buffer_init(hardenedPointBuf)
                    vsc_buffer_use(hardenedPointBuf, hardenedPointPointer.bindMemory(to: byte.self).baseAddress, hardenedPointCount)

                    return vscf_brainkey_server_harden(self.c_ctx, vsc_data(identitySecretPointer.bindMemory(to: byte.self).baseAddress, identitySecret.count), vsc_data(blindedPointPointer.bindMemory(to: byte.self).baseAddress, blindedPoint.count), hardenedPointBuf)
                })
            })
        })
        hardenedPoint.count = vsc_buffer_len(hardenedPointBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return hardenedPoint
    }
}
