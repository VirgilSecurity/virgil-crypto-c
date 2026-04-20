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

@objc(VSCFBrainkeyClient) public class BrainkeyClient: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    @objc public let pointLen: Int = 65

    @objc public let mpiLen: Int = 32

    @objc public let seedLen: Int = 32

    @objc public let maxPasswordLen: Int = 128

    @objc public let maxKeyNameLen: Int = 128

    public override init() {
        self.c_ctx = vscf_brainkey_client_new()
        super.init()
    }

    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_brainkey_client_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_brainkey_client_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_brainkey_client_release_random(self.c_ctx)
        vscf_brainkey_client_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setOperationRandom(operationRandom: Random) {
        vscf_brainkey_client_release_operation_random(self.c_ctx)
        vscf_brainkey_client_use_operation_random(self.c_ctx, operationRandom.c_ctx)
    }

    @objc public func setupDefaults() throws {
        let proxyResult = vscf_brainkey_client_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    @objc public func blind(password: Data) throws -> BrainkeyClientBlindResult {
        let deblindFactorCount = self.mpiLen
        var deblindFactor = Data(count: deblindFactorCount)
        let deblindFactorBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(deblindFactorBuf)
        }

        let blindedPointCount = self.pointLen
        var blindedPoint = Data(count: blindedPointCount)
        let blindedPointBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(blindedPointBuf)
        }

        let proxyResult = password.withUnsafeBytes({ (passwordPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return deblindFactor.withUnsafeMutableBytes({ (deblindFactorPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                vsc_buffer_use(deblindFactorBuf, deblindFactorPointer.bindMemory(to: byte.self).baseAddress, deblindFactorCount)

                return blindedPoint.withUnsafeMutableBytes({ (blindedPointPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                    vsc_buffer_use(blindedPointBuf, blindedPointPointer.bindMemory(to: byte.self).baseAddress, blindedPointCount)

                    return vscf_brainkey_client_blind(self.c_ctx, vsc_data(passwordPointer.bindMemory(to: byte.self).baseAddress, password.count), deblindFactorBuf, blindedPointBuf)
                })
            })
        })
        deblindFactor.count = vsc_buffer_len(deblindFactorBuf)
        blindedPoint.count = vsc_buffer_len(blindedPointBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return BrainkeyClientBlindResult(deblindFactor: deblindFactor, blindedPoint: blindedPoint)
    }

    @objc public func deblind(password: Data, hardenedPoint: Data, deblindFactor: Data, keyName: Data) throws -> Data {
        let seedCount = self.pointLen
        var seed = Data(count: seedCount)
        let seedBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(seedBuf)
        }

        let proxyResult = password.withUnsafeBytes({ (passwordPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            return hardenedPoint.withUnsafeBytes({ (hardenedPointPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                return deblindFactor.withUnsafeBytes({ (deblindFactorPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                    return keyName.withUnsafeBytes({ (keyNamePointer: UnsafeRawBufferPointer) -> vscf_status_t in
                        return seed.withUnsafeMutableBytes({ (seedPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                            vsc_buffer_use(seedBuf, seedPointer.bindMemory(to: byte.self).baseAddress, seedCount)

                            return vscf_brainkey_client_deblind(self.c_ctx, vsc_data(passwordPointer.bindMemory(to: byte.self).baseAddress, password.count), vsc_data(hardenedPointPointer.bindMemory(to: byte.self).baseAddress, hardenedPoint.count), vsc_data(deblindFactorPointer.bindMemory(to: byte.self).baseAddress, deblindFactor.count), vsc_data(keyNamePointer.bindMemory(to: byte.self).baseAddress, keyName.count), seedBuf)
                        })
                    })
                })
            })
        })
        seed.count = vsc_buffer_len(seedBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return seed
    }

}

@objc(VSCFBrainkeyClientBlindResult) public class BrainkeyClientBlindResult: NSObject {

    @objc public let deblindFactor: Data

    @objc public let blindedPoint: Data

    internal init(deblindFactor: Data, blindedPoint: Data) {
        self.deblindFactor = deblindFactor
        self.blindedPoint = blindedPoint
        super.init()
    }
}
