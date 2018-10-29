/// Copyright (C) 2015-2018 Virgil Security Inc.
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

/// Provides compile time knownledge about algorithm.
@objc(VSCFCipherInfo) public protocol CipherInfo : CContext {
    /// Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    @objc var nonceLen: Int { get }
    /// Cipher key length in bytes.
    @objc var keyLen: Int { get }
    /// Cipher key length in bits.
    @objc var keyBitlen: Int { get }
    /// Cipher block length in bytes.
    @objc var blockLen: Int { get }
}

/// Implement interface methods
@objc(VSCFCipherInfoProxy) internal class CipherInfoProxy: NSObject, CipherInfo {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    @objc public var nonceLen: Int {
        return vscf_cipher_info_nonce_len(vscf_cipher_info_api(self.c_ctx))
    }

    /// Cipher key length in bytes.
    @objc public var keyLen: Int {
        return vscf_cipher_info_key_len(vscf_cipher_info_api(self.c_ctx))
    }

    /// Cipher key length in bits.
    @objc public var keyBitlen: Int {
        return vscf_cipher_info_key_bitlen(vscf_cipher_info_api(self.c_ctx))
    }

    /// Cipher block length in bytes.
    @objc public var blockLen: Int {
        return vscf_cipher_info_block_len(vscf_cipher_info_api(self.c_ctx))
    }

    /// Take C context that implements this interface
    public init(c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_impl_delete(self.c_ctx)
    }
}
