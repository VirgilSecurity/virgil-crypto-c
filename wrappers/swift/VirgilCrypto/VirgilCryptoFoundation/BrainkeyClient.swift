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

@objc(VSCFBrainkeyClient) public class BrainkeyClient: NSObject {

    @objc public static let pointLen: Int = 65
    @objc public static let mpiLen: Int = 32
    @objc public static let seedLen: Int = 32
    @objc public static let maxPasswordLen: Int = 128
    @objc public static let maxKeyNameLen: Int = 128

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_brainkey_client_new()
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
        self.c_ctx = vscf_brainkey_client_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_brainkey_client_delete(self.c_ctx)
    }

    /// Random used for key generation, proofs, etc.
    @objc public func setRandom(random: Random) {
        vscf_brainkey_client_release_random(self.c_ctx)
        vscf_brainkey_client_use_random(self.c_ctx, random.c_ctx)
    }

    /// Random used for crypto operations to make them const-time
    @objc public func setOperationRandom(operationRandom: Random) {
        vscf_brainkey_client_release_operation_random(self.c_ctx)
        vscf_brainkey_client_use_operation_random(self.c_ctx, operationRandom.c_ctx)
    }

    @objc public func setupDefaults() throws {
        let proxyResult = vscf_brainkey_client_setup_defaults(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }

    @objc public func blind(password: Data) throws -> BrainkeyClientBlindResult {
        let deblindFactorCount = BrainkeyClient.mpiLen
        var deblindFactor = Data(count: deblindFactorCount)
        var deblindFactorBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(deblindFactorBuf)
        }

        let blindedPointCount = BrainkeyClient.pointLen
        var blindedPoint = Data(count: blindedPointCount)
        var blindedPointBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(blindedPointBuf)
        }

        let proxyResult = password.withUnsafeBytes({ (passwordPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            deblindFactor.withUnsafeMutableBytes({ (deblindFactorPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                blindedPoint.withUnsafeMutableBytes({ (blindedPointPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                    vsc_buffer_init(deblindFactorBuf)
                    vsc_buffer_use(deblindFactorBuf, deblindFactorPointer.bindMemory(to: byte.self).baseAddress, deblindFactorCount)

                    vsc_buffer_init(blindedPointBuf)
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
        let seedCount = BrainkeyClient.pointLen
        var seed = Data(count: seedCount)
        var seedBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(seedBuf)
        }

        let proxyResult = password.withUnsafeBytes({ (passwordPointer: UnsafeRawBufferPointer) -> vscf_status_t in
            hardenedPoint.withUnsafeBytes({ (hardenedPointPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                deblindFactor.withUnsafeBytes({ (deblindFactorPointer: UnsafeRawBufferPointer) -> vscf_status_t in
                    keyName.withUnsafeBytes({ (keyNamePointer: UnsafeRawBufferPointer) -> vscf_status_t in
                        seed.withUnsafeMutableBytes({ (seedPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
                            vsc_buffer_init(seedBuf)
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

/// Encapsulate result of method BrainkeyClient.blind()
@objc(VSCFBrainkeyClientBlindResult) public class BrainkeyClientBlindResult: NSObject {

    @objc public let deblindFactor: Data

    @objc public let blindedPoint: Data

    /// Initialize all properties.
    internal init(deblindFactor: Data, blindedPoint: Data) {
        self.deblindFactor = deblindFactor
        self.blindedPoint = blindedPoint
        super.init()
    }
}
