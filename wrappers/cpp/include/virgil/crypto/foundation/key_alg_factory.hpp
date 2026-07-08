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
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>

namespace virgil::crypto::foundation {

class Key;
class KeyAlg;
class Random;
class RawPrivateKey;
class RawPublicKey;

/// Create a bridge between "raw keys" and algorithms that can import them.
class KeyAlgFactory {
public:
    /// Create a key algorithm based on an identifier.
    static tl::expected<std::unique_ptr<KeyAlg>, Error> create_from_alg_id(AlgId alg_id, const Random& random);

    /// Create a key algorithm correspond to a specific key.
    static tl::expected<std::unique_ptr<KeyAlg>, Error> create_from_key(const Key& key, const Random& random);

    /// Create a key algorithm that can import "raw public key".
    static tl::expected<std::unique_ptr<KeyAlg>, Error> create_from_raw_public_key(const RawPublicKey& public_key, const Random& random);

    /// Create a key algorithm that can import "raw private key".
    static tl::expected<std::unique_ptr<KeyAlg>, Error> create_from_raw_private_key(const RawPrivateKey& private_key, const Random& random);

};

}  // namespace virgil::crypto::foundation
