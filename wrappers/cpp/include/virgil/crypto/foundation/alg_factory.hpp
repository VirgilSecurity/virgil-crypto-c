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

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <tl/expected.hpp>
#include <memory>
#include <virgil/crypto/foundation/vscf_alg_factory.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/kdf.hpp>
#include <virgil/crypto/foundation/mac.hpp>
#include <virgil/crypto/foundation/padding.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/salted_kdf.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Create algorithms based on the given information.
class AlgFactory {
public:
    /// Create algorithm that implements "hash stream" interface.
    static std::unique_ptr<Hash> create_hash_from_info(const AlgInfo& alg_info) {
        auto proxy_result = vscf_alg_factory_create_hash_from_info(alg_info.impl());
        return FoundationImplementation::wrap_hash(proxy_result);
    }

    /// Create algorithm that implements "mac stream" interface.
    static std::unique_ptr<Mac> create_mac_from_info(const AlgInfo& alg_info) {
        auto proxy_result = vscf_alg_factory_create_mac_from_info(alg_info.impl());
        return FoundationImplementation::wrap_mac(proxy_result);
    }

    /// Create algorithm that implements "kdf" interface.
    static std::unique_ptr<Kdf> create_kdf_from_info(const AlgInfo& alg_info) {
        auto proxy_result = vscf_alg_factory_create_kdf_from_info(alg_info.impl());
        return FoundationImplementation::wrap_kdf(proxy_result);
    }

    /// Create algorithm that implements "salted kdf" interface.
    static std::unique_ptr<SaltedKdf> create_salted_kdf_from_info(const AlgInfo& alg_info) {
        auto proxy_result = vscf_alg_factory_create_salted_kdf_from_info(alg_info.impl());
        return FoundationImplementation::wrap_salted_kdf(proxy_result);
    }

    /// Create algorithm that implements "cipher" interface.
    static std::unique_ptr<Cipher> create_cipher_from_info(const AlgInfo& alg_info) {
        auto proxy_result = vscf_alg_factory_create_cipher_from_info(alg_info.impl());
        return FoundationImplementation::wrap_cipher(proxy_result);
    }

    /// Create algorithm that implements "padding" interface.
    static std::unique_ptr<Padding> create_padding_from_info(const AlgInfo& alg_info, const Random& random) {
        auto proxy_result = vscf_alg_factory_create_padding_from_info(alg_info.impl(), random.impl());
        return FoundationImplementation::wrap_padding(proxy_result);
    }

};

}  // namespace virgil::crypto::foundation
