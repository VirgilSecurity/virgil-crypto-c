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

struct vsce_uokms_server_t;

namespace virgil::crypto::phe {

/// Result of UokmsServer::generate_server_key_pair().
struct UokmsServerGenerateServerKeyPairResult {
    std::vector<uint8_t> server_private_key;
    std::vector<uint8_t> server_public_key;
};

/// Result of UokmsServer::rotate_keys().
struct UokmsServerRotateKeysResult {
    std::vector<uint8_t> new_server_private_key;
    std::vector<uint8_t> new_server_public_key;
    std::vector<uint8_t> update_token;
};

/// Class implements UOKMS for server-side.
class UokmsServer {
public:
    UokmsServer();
    /// Adopt ownership of an existing C handle.
    explicit UokmsServer(vsce_uokms_server_t* c_ctx) noexcept;
    UokmsServer(const UokmsServer& other);
    UokmsServer(UokmsServer&& other) noexcept;
    UokmsServer& operator=(const UokmsServer& other);
    UokmsServer& operator=(UokmsServer&& other) noexcept;
    ~UokmsServer();

    /// The underlying concrete C handle (non-owning).
    vsce_uokms_server_t* c_ctx() const noexcept;

    void set_random(const virgil::crypto::foundation::Random& random);

    void set_operation_random(const virgil::crypto::foundation::Random& operation_random);

    /// Setups dependencies with default values.
    tl::expected<void, Error> setup_defaults();

    /// Generates new NIST P-256 server key pair for some client
    tl::expected<UokmsServerGenerateServerKeyPairResult, Error> generate_server_key_pair();

    /// Buffer size needed to fit DecryptResponse
    std::size_t decrypt_response_len();

    /// Processed client's decrypt request
    tl::expected<std::vector<uint8_t>, Error> process_decrypt_request(std::span<const uint8_t> server_private_key, std::span<const uint8_t> decrypt_request);

    /// Updates server's private and public keys and issues an update token for use on client's side
    tl::expected<UokmsServerRotateKeysResult, Error> rotate_keys(std::span<const uint8_t> server_private_key);

private:
    vsce_uokms_server_t* c_ctx_;
};

}  // namespace virgil::crypto::phe
