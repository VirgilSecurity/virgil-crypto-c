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
#include <virgil/crypto/foundation/vscf_key_alg_factory.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Create a bridge between "raw keys" and algorithms that can import them.
class KeyAlgFactory {
public:
    /// Create a key algorithm based on an identifier.
    static tl::expected<std::unique_ptr<KeyAlg>, Error> create_from_alg_id(AlgId alg_id, const Random& random) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_alg_factory_create_from_alg_id(static_cast<vscf_alg_id_t>(alg_id), random.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_key_alg(proxy_result);
    }

    /// Create a key algorithm correspond to a specific key.
    static tl::expected<std::unique_ptr<KeyAlg>, Error> create_from_key(const Key& key, const Random& random) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_alg_factory_create_from_key(key.impl(), random.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_key_alg(proxy_result);
    }

    /// Create a key algorithm that can import "raw public key".
    static tl::expected<std::unique_ptr<KeyAlg>, Error> create_from_raw_public_key(const RawPublicKey& public_key, const Random& random) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_alg_factory_create_from_raw_public_key(public_key.c_ctx(), random.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_key_alg(proxy_result);
    }

    /// Create a key algorithm that can import "raw private key".
    static tl::expected<std::unique_ptr<KeyAlg>, Error> create_from_raw_private_key(const RawPrivateKey& private_key, const Random& random) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_alg_factory_create_from_raw_private_key(private_key.c_ctx(), random.impl(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_key_alg(proxy_result);
    }

};

}  // namespace virgil::crypto::foundation
