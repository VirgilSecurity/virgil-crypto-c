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
#include <virgil/crypto/phe/vsce_uokms_server.h>
#include <virgil/crypto/phe/error.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/phe/phe_common.hpp>

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
    UokmsServer() : c_ctx_(vsce_uokms_server_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit UokmsServer(vsce_uokms_server_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    UokmsServer(const UokmsServer& other) : c_ctx_(vsce_uokms_server_shallow_copy(other.c_ctx_)) {}
    UokmsServer(UokmsServer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    UokmsServer& operator=(const UokmsServer& other) {
        if (this != &other) {
            vsce_uokms_server_delete(c_ctx_);
            c_ctx_ = vsce_uokms_server_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    UokmsServer& operator=(UokmsServer&& other) noexcept {
        if (this != &other) {
            vsce_uokms_server_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~UokmsServer() { vsce_uokms_server_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vsce_uokms_server_t* c_ctx() const noexcept { return c_ctx_; }

    void set_random(const virgil::crypto::foundation::Random& random) {
        vsce_uokms_server_release_random(c_ctx_);
        vsce_uokms_server_use_random(c_ctx_, random.impl());
    }

    void set_operation_random(const virgil::crypto::foundation::Random& operation_random) {
        vsce_uokms_server_release_operation_random(c_ctx_);
        vsce_uokms_server_use_operation_random(c_ctx_, operation_random.impl());
    }

    /// Setups dependencies with default values.
    tl::expected<void, Error> setup_defaults() {
        const vsce_status_t status = vsce_uokms_server_setup_defaults(c_ctx_);
        if (status != vsce_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Generates new NIST P-256 server key pair for some client
    tl::expected<UokmsServerGenerateServerKeyPairResult, Error> generate_server_key_pair() {
        std::vector<uint8_t> server_private_key(PheCommon::PHE_PRIVATE_KEY_LENGTH);
        vsc_buffer_t* server_private_key_buf = vsc_buffer_new();
        vsc_buffer_use(server_private_key_buf, server_private_key.data(), server_private_key.size());
        std::vector<uint8_t> server_public_key(PheCommon::PHE_PUBLIC_KEY_LENGTH);
        vsc_buffer_t* server_public_key_buf = vsc_buffer_new();
        vsc_buffer_use(server_public_key_buf, server_public_key.data(), server_public_key.size());
        const vsce_status_t status = vsce_uokms_server_generate_server_key_pair(c_ctx_, server_private_key_buf, server_public_key_buf);
        server_private_key.resize(vsc_buffer_len(server_private_key_buf));
        vsc_buffer_delete(server_private_key_buf);
        server_public_key.resize(vsc_buffer_len(server_public_key_buf));
        vsc_buffer_delete(server_public_key_buf);
        if (status != vsce_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return UokmsServerGenerateServerKeyPairResult{.server_private_key = std::move(server_private_key), .server_public_key = std::move(server_public_key)};
    }

    /// Buffer size needed to fit DecryptResponse
    std::size_t decrypt_response_len() {
        auto proxy_result = vsce_uokms_server_decrypt_response_len(c_ctx_);
        return proxy_result;
    }

    /// Processed client's decrypt request
    tl::expected<std::vector<uint8_t>, Error> process_decrypt_request(std::span<const uint8_t> server_private_key, std::span<const uint8_t> decrypt_request) {
        std::vector<uint8_t> decrypt_response(this->decrypt_response_len());
        vsc_buffer_t* decrypt_response_buf = vsc_buffer_new();
        vsc_buffer_use(decrypt_response_buf, decrypt_response.data(), decrypt_response.size());
        const vsce_status_t status = vsce_uokms_server_process_decrypt_request(c_ctx_, vsc_data(server_private_key.data(), server_private_key.size()), vsc_data(decrypt_request.data(), decrypt_request.size()), decrypt_response_buf);
        decrypt_response.resize(vsc_buffer_len(decrypt_response_buf));
        vsc_buffer_delete(decrypt_response_buf);
        if (status != vsce_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return decrypt_response;
    }

    /// Updates server's private and public keys and issues an update token for use on client's side
    tl::expected<UokmsServerRotateKeysResult, Error> rotate_keys(std::span<const uint8_t> server_private_key) {
        std::vector<uint8_t> new_server_private_key(PheCommon::PHE_PRIVATE_KEY_LENGTH);
        vsc_buffer_t* new_server_private_key_buf = vsc_buffer_new();
        vsc_buffer_use(new_server_private_key_buf, new_server_private_key.data(), new_server_private_key.size());
        std::vector<uint8_t> new_server_public_key(PheCommon::PHE_PUBLIC_KEY_LENGTH);
        vsc_buffer_t* new_server_public_key_buf = vsc_buffer_new();
        vsc_buffer_use(new_server_public_key_buf, new_server_public_key.data(), new_server_public_key.size());
        std::vector<uint8_t> update_token(PheCommon::PHE_PRIVATE_KEY_LENGTH);
        vsc_buffer_t* update_token_buf = vsc_buffer_new();
        vsc_buffer_use(update_token_buf, update_token.data(), update_token.size());
        const vsce_status_t status = vsce_uokms_server_rotate_keys(c_ctx_, vsc_data(server_private_key.data(), server_private_key.size()), new_server_private_key_buf, new_server_public_key_buf, update_token_buf);
        new_server_private_key.resize(vsc_buffer_len(new_server_private_key_buf));
        vsc_buffer_delete(new_server_private_key_buf);
        new_server_public_key.resize(vsc_buffer_len(new_server_public_key_buf));
        vsc_buffer_delete(new_server_public_key_buf);
        update_token.resize(vsc_buffer_len(update_token_buf));
        vsc_buffer_delete(update_token_buf);
        if (status != vsce_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return UokmsServerRotateKeysResult{.new_server_private_key = std::move(new_server_private_key), .new_server_public_key = std::move(new_server_public_key), .update_token = std::move(update_token)};
    }

private:
    vsce_uokms_server_t* c_ctx_;
};

}  // namespace virgil::crypto::phe
