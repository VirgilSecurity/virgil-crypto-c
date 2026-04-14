// Copyright (C) 2015-2022 Virgil Security, Inc.
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

@objc(VSCFKeyInfo) public class KeyInfo: NSObject {
    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    override public init() {
        c_ctx = vscf_key_info_new()
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
        self.c_ctx = vscf_key_info_shallow_copy(c_ctx)
        super.init()
    }

    /// Build key information based on the generic algorithm information.
    public init(algInfo: AlgInfo) {
        let proxyResult = vscf_key_info_new_with_alg_info(algInfo.c_ctx)

        c_ctx = proxyResult!
    }

    /// Release underlying C context.
    deinit {
        vscf_key_info_delete(self.c_ctx)
    }

    /// Return true if a key is a compound key
    @objc public func isCompound() -> Bool {
        return vscf_key_info_is_compound(c_ctx)
    }

    /// Return true if a key is a hybrid key
    @objc public func isHybrid() -> Bool {
        return vscf_key_info_is_hybrid(c_ctx)
    }

    /// Return true if a key is a compound key and compounds cipher key
    /// and signer key are hybrid keys.
    @objc public func isCompoundHybrid() -> Bool {
        return vscf_key_info_is_compound_hybrid(c_ctx)
    }

    /// Return true if a key is a compound key and compounds cipher key
    /// is a hybrid key.
    @objc public func isCompoundHybridCipher() -> Bool {
        return vscf_key_info_is_compound_hybrid_cipher(c_ctx)
    }

    /// Return true if a key is a compound key and compounds signer key
    /// is a hybrid key.
    @objc public func isCompoundHybridSigner() -> Bool {
        return vscf_key_info_is_compound_hybrid_signer(c_ctx)
    }

    /// Return true if a key is a compound key that contains hybrid keys
    /// for encryption/decryption and signing/verifying that itself
    /// contains a combination of classic keys and post-quantum keys.
    @objc public func isHybridPostQuantum() -> Bool {
        return vscf_key_info_is_hybrid_post_quantum(c_ctx)
    }

    /// Return true if a key is a compound key that contains a hybrid key
    /// for encryption/decryption that contains a classic key and
    /// a post-quantum key.
    @objc public func isHybridPostQuantumCipher() -> Bool {
        return vscf_key_info_is_hybrid_post_quantum_cipher(c_ctx)
    }

    /// Return true if a key is a compound key that contains a hybrid key
    /// for signing/verifying that contains a classic key and
    /// a post-quantum key.
    @objc public func isHybridPostQuantumSigner() -> Bool {
        return vscf_key_info_is_hybrid_post_quantum_signer(c_ctx)
    }

    /// Return common type of the key.
    @objc public func algId() -> AlgId {
        let proxyResult = vscf_key_info_alg_id(c_ctx)

        return AlgId(fromC: proxyResult)
    }

    /// Return compound's cipher key id, if key is compound.
    /// Return None, otherwise.
    @objc public func compoundCipherAlgId() -> AlgId {
        let proxyResult = vscf_key_info_compound_cipher_alg_id(c_ctx)

        return AlgId(fromC: proxyResult)
    }

    /// Return compound's signer key id, if key is compound.
    /// Return None, otherwise.
    @objc public func compoundSignerAlgId() -> AlgId {
        let proxyResult = vscf_key_info_compound_signer_alg_id(c_ctx)

        return AlgId(fromC: proxyResult)
    }

    /// Return hybrid's first key id, if key is hybrid.
    /// Return None, otherwise.
    @objc public func hybridFirstKeyAlgId() -> AlgId {
        let proxyResult = vscf_key_info_hybrid_first_key_alg_id(c_ctx)

        return AlgId(fromC: proxyResult)
    }

    /// Return hybrid's second key id, if key is hybrid.
    /// Return None, otherwise.
    @objc public func hybridSecondKeyAlgId() -> AlgId {
        let proxyResult = vscf_key_info_hybrid_second_key_alg_id(c_ctx)

        return AlgId(fromC: proxyResult)
    }

    /// Return hybrid's first key id of compound's cipher key,
    /// if key is compound(hybrid, ...), None - otherwise.
    @objc public func compoundHybridCipherFirstKeyAlgId() -> AlgId {
        let proxyResult = vscf_key_info_compound_hybrid_cipher_first_key_alg_id(c_ctx)

        return AlgId(fromC: proxyResult)
    }

    /// Return hybrid's second key id of compound's cipher key,
    /// if key is compound(hybrid, ...), None - otherwise.
    @objc public func compoundHybridCipherSecondKeyAlgId() -> AlgId {
        let proxyResult = vscf_key_info_compound_hybrid_cipher_second_key_alg_id(c_ctx)

        return AlgId(fromC: proxyResult)
    }

    /// Return hybrid's first key id of compound's signer key,
    /// if key is compound(..., hybrid), None - otherwise.
    @objc public func compoundHybridSignerFirstKeyAlgId() -> AlgId {
        let proxyResult = vscf_key_info_compound_hybrid_signer_first_key_alg_id(c_ctx)

        return AlgId(fromC: proxyResult)
    }

    /// Return hybrid's second key id of compound's signer key,
    /// if key is compound(..., hybrid), None - otherwise.
    @objc public func compoundHybridSignerSecondKeyAlgId() -> AlgId {
        let proxyResult = vscf_key_info_compound_hybrid_signer_second_key_alg_id(c_ctx)

        return AlgId(fromC: proxyResult)
    }
}
