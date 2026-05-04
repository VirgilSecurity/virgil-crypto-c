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

@objc(VSCFBrainkeyServer) public class BrainkeyServer: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    @objc public let pointLen: Int = 65

    @objc public let mpiLen: Int = 32

    @objc public let proofValueLen: Int = 32

    public override init() {
        self.c_ctx = vscf_brainkey_server_new()
        super.init()
    }

    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_brainkey_server_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_brainkey_server_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_brainkey_server_release_random(self.c_ctx)
        vscf_brainkey_server_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setOperationRandom(operationRandom: Random) {
        vscf_brainkey_server_release_operation_random(self.c_ctx)
        vscf_brainkey_server_use_operation_random(self.c_ctx, operationRandom.c_ctx)
    }

    @objc public func setupDefaults() throws {
        let proxyResult = vscf_brainkey_server_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    @objc public func generateIdentitySecret() throws -> Data {
        let identitySecretCount = self.mpiLen
        var identitySecret = Data(count: identitySecretCount)
        let identitySecretBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(identitySecretBuf)
        }

        let proxyResult = identitySecret.withUnsafeMutableBytes({ (identitySecretPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(identitySecretBuf, identitySecretPointer.bindMemory(to: byte.self).baseAddress, identitySecretCount)

            return vscf_brainkey_server_generate_identity_secret(self.c_ctx, identitySecretBuf)
        })
        identitySecret.count = vsc_buffer_len(identitySecretBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return identitySecret
    }

    @objc public func harden(identitySecret: Data, blindedPoint: Data) throws -> Data {
        let hardenedPointCount = self.pointLen
        var hardenedPoint = Data(count: hardenedPointCount)
        let hardenedPointBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(hardenedPointBuf)
        }

        let proxyResult = identitySecret.withUnsafeBytes({ (identitySecretPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return blindedPoint.withUnsafeBytes({ (blindedPointPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                return hardenedPoint.withUnsafeMutableBytes({ (hardenedPointPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                    vsc_buffer_use(hardenedPointBuf, hardenedPointPointer.bindMemory(to: byte.self).baseAddress, hardenedPointCount)

                    return vscf_brainkey_server_harden(self.c_ctx, vsc_data(identitySecretPointer.bindMemory(to: byte.self).baseAddress, identitySecret.count), vsc_data(blindedPointPointer.bindMemory(to: byte.self).baseAddress, blindedPoint.count), hardenedPointBuf)
                })
            })
        })
        hardenedPoint.count = vsc_buffer_len(hardenedPointBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return hardenedPoint
    }

    /// Computes the server's public key G_x = x*G from the given identity secret x.
    /// Required by the client to verify DLEQ proofs.
    @objc public func computePublicKey(identitySecret: Data) throws -> Data {
        let publicKeyCount = self.pointLen
        var publicKey = Data(count: publicKeyCount)
        let publicKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(publicKeyBuf)
        }

        let proxyResult = identitySecret.withUnsafeBytes({ (identitySecretPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return publicKey.withUnsafeMutableBytes({ (publicKeyPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(publicKeyBuf, publicKeyPointer.bindMemory(to: byte.self).baseAddress, publicKeyCount)

                return vscf_brainkey_server_compute_public_key(self.c_ctx, vsc_data(identitySecretPointer.bindMemory(to: byte.self).baseAddress, identitySecret.count), publicKeyBuf)
            })
        })
        publicKey.count = vsc_buffer_len(publicKeyBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return publicKey
    }

    /// Generates a DLEQ proof that hardened_point = x * blinded_point using the same
    /// identity secret x as server_public_key = x * G.
    /// Client must call verify() before deblind() to authenticate the server response.
    @objc public func prove(blindedPoint: Data, hardenedPoint: Data, identitySecret: Data, serverPublicKey: Data) throws -> BrainkeyServerProveResult {
        let proofValueCCount = self.proofValueLen
        var proofValueC = Data(count: proofValueCCount)
        let proofValueCBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(proofValueCBuf)
        }

        let proofValueSCount = self.proofValueLen
        var proofValueS = Data(count: proofValueSCount)
        let proofValueSBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(proofValueSBuf)
        }

        let proxyResult = blindedPoint.withUnsafeBytes({ (blindedPointPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return hardenedPoint.withUnsafeBytes({ (hardenedPointPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                return identitySecret.withUnsafeBytes({ (identitySecretPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                    return serverPublicKey.withUnsafeBytes({ (serverPublicKeyPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                        return proofValueC.withUnsafeMutableBytes({ (proofValueCPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                            vsc_buffer_use(proofValueCBuf, proofValueCPointer.bindMemory(to: byte.self).baseAddress, proofValueCCount)

                            return proofValueS.withUnsafeMutableBytes({ (proofValueSPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                                vsc_buffer_use(proofValueSBuf, proofValueSPointer.bindMemory(to: byte.self).baseAddress, proofValueSCount)

                                return vscf_brainkey_server_prove(self.c_ctx, vsc_data(blindedPointPointer.bindMemory(to: byte.self).baseAddress, blindedPoint.count), vsc_data(hardenedPointPointer.bindMemory(to: byte.self).baseAddress, hardenedPoint.count), vsc_data(identitySecretPointer.bindMemory(to: byte.self).baseAddress, identitySecret.count), vsc_data(serverPublicKeyPointer.bindMemory(to: byte.self).baseAddress, serverPublicKey.count), proofValueCBuf, proofValueSBuf)
                            })
                        })
                    })
                })
            })
        })
        proofValueC.count = vsc_buffer_len(proofValueCBuf)
        proofValueS.count = vsc_buffer_len(proofValueSBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return BrainkeyServerProveResult(proofValueC: proofValueC, proofValueS: proofValueS)
    }

}

@objc(VSCFBrainkeyServerProveResult) public class BrainkeyServerProveResult: NSObject {

    @objc public let proofValueC: Data

    @objc public let proofValueS: Data

    internal init(proofValueC: Data, proofValueS: Data) {
        self.proofValueC = proofValueC
        self.proofValueS = proofValueS
        super.init()
    }
}
