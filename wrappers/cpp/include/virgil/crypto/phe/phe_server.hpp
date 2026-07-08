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
#include <virgil/crypto/phe/error.hpp>
#include <virgil/crypto/foundation/random.hpp>

struct vsce_phe_server_t;

namespace virgil::crypto::phe {

/// Result of PheServer::generate_server_key_pair().
struct PheServerGenerateServerKeyPairResult {
    std::vector<uint8_t> server_private_key;
    std::vector<uint8_t> server_public_key;
};

/// Result of PheServer::rotate_keys().
struct PheServerRotateKeysResult {
    std::vector<uint8_t> new_server_private_key;
    std::vector<uint8_t> new_server_public_key;
    std::vector<uint8_t> update_token;
};

/// Class for server-side PHE crypto operations.
/// This class is thread-safe in case if .(c_global_macros_multi_threading) defined.
class PheServer {
public:
    PheServer();
    /// Adopt ownership of an existing C handle.
    explicit PheServer(vsce_phe_server_t* c_ctx) noexcept;
    PheServer(const PheServer& other);
    PheServer(PheServer&& other) noexcept;
    PheServer& operator=(const PheServer& other);
    PheServer& operator=(PheServer&& other) noexcept;
    ~PheServer();

    /// The underlying concrete C handle (non-owning).
    vsce_phe_server_t* c_ctx() const noexcept;

    void set_random(const virgil::crypto::foundation::Random& random);

    void set_operation_random(const virgil::crypto::foundation::Random& operation_random);

    /// Setups dependencies with default values.
    tl::expected<void, Error> setup_defaults();

    /// Generates new NIST P-256 server key pair for some client
    tl::expected<PheServerGenerateServerKeyPairResult, Error> generate_server_key_pair();

    /// Buffer size needed to fit EnrollmentResponse
    std::size_t enrollment_response_len();

    /// Generates a new random enrollment and proof for a new user
    tl::expected<std::vector<uint8_t>, Error> get_enrollment(std::span<const uint8_t> server_private_key, std::span<const uint8_t> server_public_key);

    /// Buffer size needed to fit VerifyPasswordResponse
    std::size_t verify_password_response_len();

    /// Verifies existing user's password and generates response with proof
    tl::expected<std::vector<uint8_t>, Error> verify_password(std::span<const uint8_t> server_private_key, std::span<const uint8_t> server_public_key, std::span<const uint8_t> verify_password_request);

    /// Buffer size needed to fit UpdateToken
    std::size_t update_token_len();

    /// Updates server's private and public keys and issues an update token for use on client's side
    tl::expected<PheServerRotateKeysResult, Error> rotate_keys(std::span<const uint8_t> server_private_key);

private:
    vsce_phe_server_t* c_ctx_;
};

}  // namespace virgil::crypto::phe
