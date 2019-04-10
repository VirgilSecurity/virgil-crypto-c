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

/// Create algorithms based on the given information.
@objc(VSCFAlgFactory) public class AlgFactory: NSObject {

    /// Create algorithm that implements "hash stream" interface.
    @objc public static func createHashFromInfo(algInfo: AlgInfo) -> Hash {
        let proxyResult = vscf_alg_factory_create_hash_from_info(algInfo.c_ctx)

        return FoundationImplementation.wrapHash(take: proxyResult!)
    }

    /// Create algorithm that implements "mac stream" interface.
    @objc public static func createMacFromInfo(algInfo: AlgInfo) -> Mac {
        let proxyResult = vscf_alg_factory_create_mac_from_info(algInfo.c_ctx)

        return FoundationImplementation.wrapMac(take: proxyResult!)
    }

    /// Create algorithm that implements "kdf" interface.
    @objc public static func createKdfFromInfo(algInfo: AlgInfo) -> Kdf {
        let proxyResult = vscf_alg_factory_create_kdf_from_info(algInfo.c_ctx)

        return FoundationImplementation.wrapKdf(take: proxyResult!)
    }

    /// Create algorithm that implements "salted kdf" interface.
    @objc public static func createSaltedKdfFromInfo(algInfo: AlgInfo) -> SaltedKdf {
        let proxyResult = vscf_alg_factory_create_salted_kdf_from_info(algInfo.c_ctx)

        return FoundationImplementation.wrapSaltedKdf(take: proxyResult!)
    }

    /// Create algorithm that implements "cipher" interface.
    @objc public static func createCipherFromInfo(algInfo: AlgInfo) -> Cipher {
        let proxyResult = vscf_alg_factory_create_cipher_from_info(algInfo.c_ctx)

        return FoundationImplementation.wrapCipher(take: proxyResult!)
    }

    /// Create algorithm that implements "public key" interface.
    @objc public static func createPublicKeyFromRawKey(rawKey: RawKey) throws -> PublicKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_alg_factory_create_public_key_from_raw_key(rawKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPublicKey(take: proxyResult!)
    }

    /// Create algorithm that implements "private key" interface.
    @objc public static func createPrivateKeyFromRawKey(rawKey: RawKey) throws -> PrivateKey {
        var error: vscf_error_t = vscf_error_t()
        vscf_error_reset(&error)

        let proxyResult = vscf_alg_factory_create_private_key_from_raw_key(rawKey.c_ctx, &error)

        try FoundationError.handleStatus(fromC: error.status)

        return FoundationImplementation.wrapPrivateKey(take: proxyResult!)
    }
}
