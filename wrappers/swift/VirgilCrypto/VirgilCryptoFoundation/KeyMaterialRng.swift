/// Copyright (C) 2015-2020 Virgil Security, Inc.
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

/// Random number generator that generate deterministic sequence based
/// on a given seed.
/// This RNG can be used to transform key material rial to the private key.
@objc(VSCFKeyMaterialRng) public class KeyMaterialRng: NSObject, Random {

    /// Minimum length in bytes for the key material.
    @objc public static let keyMaterialLenMin: Int = 32
    /// Maximum length in bytes for the key material.
    @objc public static let keyMaterialLenMax: Int = 512

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_key_material_rng_new()
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
        self.c_ctx = vscf_key_material_rng_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_key_material_rng_delete(self.c_ctx)
    }

    /// Set a new key material.
    @objc public func resetKeyMaterial(keyMaterial: Data) {
        keyMaterial.withUnsafeBytes({ (keyMaterialPointer: UnsafeRawBufferPointer) -> Void in

            vscf_key_material_rng_reset_key_material(self.c_ctx, vsc_data(keyMaterialPointer.bindMemory(to: byte.self).baseAddress, keyMaterial.count))
        })
    }

    /// Generate random bytes.
    /// All RNG implementations must be thread-safe.
    @objc public func random(dataLen: Int) throws -> Data {
        let dataCount = dataLen
        var data = Data(count: dataCount)
        var dataBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(dataBuf)
        }

        let proxyResult = data.withUnsafeMutableBytes({ (dataPointer: UnsafeMutableRawBufferPointer) -> vscf_status_t in
            vsc_buffer_use(dataBuf, dataPointer.bindMemory(to: byte.self).baseAddress, dataCount)

            return vscf_key_material_rng_random(self.c_ctx, dataLen, dataBuf)
        })
        data.count = vsc_buffer_len(dataBuf)

        try FoundationError.handleStatus(fromC: proxyResult)

        return data
    }

    /// Retrieve new seed data from the entropy sources.
    @objc public func reseed() throws {
        let proxyResult = vscf_key_material_rng_reseed(self.c_ctx)

        try FoundationError.handleStatus(fromC: proxyResult)
    }
}
