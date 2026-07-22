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

struct vscf_brainkey_server_t;

namespace virgil::crypto::foundation {

class Random;

/// Result of BrainkeyServer::prove().
struct BrainkeyServerProveResult {
    bool is_success;
    std::vector<uint8_t> proof_value_c;
    std::vector<uint8_t> proof_value_s;
};

class BrainkeyServer {
public:
    BrainkeyServer();
    /// Adopt ownership of an existing C handle.
    explicit BrainkeyServer(vscf_brainkey_server_t* c_ctx) noexcept;
    BrainkeyServer(const BrainkeyServer& other);
    BrainkeyServer(BrainkeyServer&& other) noexcept;
    BrainkeyServer& operator=(const BrainkeyServer& other);
    BrainkeyServer& operator=(BrainkeyServer&& other) noexcept;
    ~BrainkeyServer();

    /// The underlying concrete C handle (non-owning).
    vscf_brainkey_server_t* c_ctx() const noexcept;

    static constexpr std::size_t POINT_LEN = 65;

    static constexpr std::size_t MPI_LEN = 32;

    static constexpr std::size_t PROOF_VALUE_LEN = 32;

    void set_random(const Random& random);

    void set_operation_random(const Random& operation_random);

    tl::expected<void, Error> setup_defaults();

    tl::expected<std::vector<uint8_t>, Error> generate_identity_secret();

    tl::expected<std::vector<uint8_t>, Error> harden(std::span<const uint8_t> identity_secret, std::span<const uint8_t> blinded_point);

    /// Computes the server's public key G_x = x*G from the given identity secret x.
    /// Required by the client to verify DLEQ proofs.
    tl::expected<std::vector<uint8_t>, Error> compute_public_key(std::span<const uint8_t> identity_secret);

    /// Generates a DLEQ proof that hardened_point = x * blinded_point using the same
    /// identity secret x as server_public_key = x * G.
    /// Client must call verify() before deblind() to authenticate the server response.
    tl::expected<BrainkeyServerProveResult, Error> prove(std::span<const uint8_t> blinded_point, std::span<const uint8_t> hardened_point, std::span<const uint8_t> identity_secret, std::span<const uint8_t> server_public_key);

private:
    vscf_brainkey_server_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
