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

struct vsce_phe_client_t;

namespace virgil::crypto::phe {

/// Result of PheClient::enroll_account().
struct PheClientEnrollAccountResult {
    std::vector<uint8_t> enrollment_record;
    std::vector<uint8_t> account_key;
};

/// Result of PheClient::rotate_keys().
struct PheClientRotateKeysResult {
    std::vector<uint8_t> new_client_private_key;
    std::vector<uint8_t> new_server_public_key;
};

/// Class for client-side PHE crypto operations.
/// This class is thread-safe in case if .(c_global_macros_multi_threading) defined.
class PheClient {
public:
    PheClient();
    /// Adopt ownership of an existing C handle.
    explicit PheClient(vsce_phe_client_t* c_ctx) noexcept;
    PheClient(const PheClient& other);
    PheClient(PheClient&& other) noexcept;
    PheClient& operator=(const PheClient& other);
    PheClient& operator=(PheClient&& other) noexcept;
    ~PheClient();

    /// The underlying concrete C handle (non-owning).
    vsce_phe_client_t* c_ctx() const noexcept;

    void set_random(const virgil::crypto::foundation::Random& random);

    void set_operation_random(const virgil::crypto::foundation::Random& operation_random);

    /// Setups dependencies with default values.
    tl::expected<void, Error> setup_defaults();

    /// Sets client private and server public key
    /// Call this method before any other methods except `update enrollment record` and `generate client private key`
    /// This function should be called only once
    tl::expected<void, Error> set_keys(std::span<const uint8_t> client_private_key, std::span<const uint8_t> server_public_key);

    /// Generates client private key
    tl::expected<std::vector<uint8_t>, Error> generate_client_private_key();

    /// Buffer size needed to fit EnrollmentRecord
    std::size_t enrollment_record_len();

    /// Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
    /// a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
    /// Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
    tl::expected<PheClientEnrollAccountResult, Error> enroll_account(std::span<const uint8_t> enrollment_response, std::span<const uint8_t> password);

    /// Buffer size needed to fit VerifyPasswordRequest
    std::size_t verify_password_request_len();

    /// Creates a request for further password verification at the PHE server side.
    tl::expected<std::vector<uint8_t>, Error> create_verify_password_request(std::span<const uint8_t> password, std::span<const uint8_t> enrollment_record);

    /// Verifies PHE server's answer
    /// If login succeeded, extracts account key
    /// If login failed account key will be empty
    tl::expected<std::vector<uint8_t>, Error> check_response_and_decrypt(std::span<const uint8_t> password, std::span<const uint8_t> enrollment_record, std::span<const uint8_t> verify_password_response);

    /// Updates client's private key and server's public key using server's update token
    /// Use output values to instantiate new client instance with new keys
    tl::expected<PheClientRotateKeysResult, Error> rotate_keys(std::span<const uint8_t> update_token);

    /// Updates EnrollmentRecord using server's update token
    tl::expected<std::vector<uint8_t>, Error> update_enrollment_record(std::span<const uint8_t> enrollment_record, std::span<const uint8_t> update_token);

private:
    vsce_phe_client_t* c_ctx_;
};

}  // namespace virgil::crypto::phe
