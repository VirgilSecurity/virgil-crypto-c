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
#include <virgil/crypto/foundation/error.hpp>

struct vscf_brainkey_client_t;

namespace virgil::crypto::foundation {

class Random;

/// Result of BrainkeyClient::blind().
struct BrainkeyClientBlindResult {
    std::vector<uint8_t> deblind_factor;
    std::vector<uint8_t> blinded_point;
};

class BrainkeyClient {
public:
    BrainkeyClient();
    /// Adopt ownership of an existing C handle.
    explicit BrainkeyClient(vscf_brainkey_client_t* c_ctx) noexcept;
    BrainkeyClient(const BrainkeyClient& other);
    BrainkeyClient(BrainkeyClient&& other) noexcept;
    BrainkeyClient& operator=(const BrainkeyClient& other);
    BrainkeyClient& operator=(BrainkeyClient&& other) noexcept;
    ~BrainkeyClient();

    /// The underlying concrete C handle (non-owning).
    vscf_brainkey_client_t* c_ctx() const noexcept;

    static constexpr std::size_t POINT_LEN = 65;

    static constexpr std::size_t MPI_LEN = 32;

    static constexpr std::size_t SEED_LEN = 32;

    static constexpr std::size_t MAX_PASSWORD_LEN = 128;

    static constexpr std::size_t MAX_KEY_NAME_LEN = 128;

    void set_random(const Random& random);

    void set_operation_random(const Random& operation_random);

    tl::expected<void, Error> setup_defaults();

    tl::expected<BrainkeyClientBlindResult, Error> blind(std::span<const uint8_t> password);

    tl::expected<std::vector<uint8_t>, Error> deblind(std::span<const uint8_t> password, std::span<const uint8_t> hardened_point, std::span<const uint8_t> deblind_factor, std::span<const uint8_t> key_name);

    /// Verifies the DLEQ proof that hardened_point = x * blinded_point where x corresponds
    /// to server_public_key = x * G. Must be called before deblind() to authenticate
    /// the server response.
    tl::expected<bool, Error> verify(std::span<const uint8_t> blinded_point, std::span<const uint8_t> hardened_point, std::span<const uint8_t> server_public_key, std::span<const uint8_t> proof_value_c, std::span<const uint8_t> proof_value_s);

private:
    vscf_brainkey_client_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
