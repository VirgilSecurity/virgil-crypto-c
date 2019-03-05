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

/// Provide functionality for private key generation and importing that
/// relies on the software default implementations.
@objc(VSCFKeyProvider) public class KeyProvider: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_key_provider_new()
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
        self.c_ctx = vscf_key_provider_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_key_provider_delete(self.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_key_provider_release_random(self.c_ctx)
        vscf_key_provider_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setEcies(ecies: Ecies) {
        vscf_key_provider_release_ecies(self.c_ctx)
        vscf_key_provider_use_ecies(self.c_ctx, ecies.c_ctx)
    }

    @objc public func setHash(hash: Hash) {
        vscf_key_provider_release_hash(self.c_ctx)
        vscf_key_provider_use_hash(self.c_ctx, hash.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_key_provider_setup_defaults(self.c_ctx)

        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Setup parameters that is used during RSA key generation.
    @objc public func setRsaParams(bitlen: Int, exponent: Int) {
        vscf_key_provider_set_rsa_params(self.c_ctx, bitlen, exponent)
    }

    /// Generate new private key from the given id.
    @objc public func generatePrivateKey(algId: AlgId, error: ErrorCtx) -> PrivateKey {
        let proxyResult = vscf_key_provider_generate_private_key(self.c_ctx, vscf_alg_id_t(rawValue: UInt32(algId.rawValue)), error.c_ctx)

        return PrivateKeyProxy.init(c_ctx: proxyResult!)
    }

    /// Import private key from the PKCS#8 format.
    @objc public func importPrivateKey(pkcs8Data: Data, error: ErrorCtx) -> PrivateKey {
        let proxyResult = pkcs8Data.withUnsafeBytes({ (pkcs8DataPointer: UnsafePointer<byte>) in
            return vscf_key_provider_import_private_key(self.c_ctx, vsc_data(pkcs8DataPointer, pkcs8Data.count), error.c_ctx)
        })

        return PrivateKeyProxy.init(c_ctx: proxyResult!)
    }

    /// Import public key from the PKCS#8 format.
    @objc public func importPublicKey(pkcs8Data: Data, error: ErrorCtx) -> PublicKey {
        let proxyResult = pkcs8Data.withUnsafeBytes({ (pkcs8DataPointer: UnsafePointer<byte>) in
            return vscf_key_provider_import_public_key(self.c_ctx, vsc_data(pkcs8DataPointer, pkcs8Data.count), error.c_ctx)
        })

        return PublicKeyProxy.init(c_ctx: proxyResult!)
    }
}
