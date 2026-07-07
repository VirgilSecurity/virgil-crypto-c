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
#include <vector>
#include <tl/expected.hpp>
#include <virgil/crypto/foundation/vscf_brainkey_client.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/random.hpp>

namespace virgil::crypto::foundation {

/// Result of BrainkeyClient::blind().
struct BrainkeyClientBlindResult {
    std::vector<uint8_t> deblind_factor;
    std::vector<uint8_t> blinded_point;
};

class BrainkeyClient {
public:
    BrainkeyClient() : c_ctx_(vscf_brainkey_client_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit BrainkeyClient(vscf_brainkey_client_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    BrainkeyClient(const BrainkeyClient& other) : c_ctx_(vscf_brainkey_client_shallow_copy(other.c_ctx_)) {}
    BrainkeyClient(BrainkeyClient&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    BrainkeyClient& operator=(const BrainkeyClient& other) {
        if (this != &other) {
            vscf_brainkey_client_delete(c_ctx_);
            c_ctx_ = vscf_brainkey_client_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    BrainkeyClient& operator=(BrainkeyClient&& other) noexcept {
        if (this != &other) {
            vscf_brainkey_client_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~BrainkeyClient() { vscf_brainkey_client_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_brainkey_client_t* c_ctx() const noexcept { return c_ctx_; }

    static constexpr std::size_t POINT_LEN = 65;

    static constexpr std::size_t MPI_LEN = 32;

    static constexpr std::size_t SEED_LEN = 32;

    static constexpr std::size_t MAX_PASSWORD_LEN = 128;

    static constexpr std::size_t MAX_KEY_NAME_LEN = 128;

    void set_random(const Random& random) {
        vscf_brainkey_client_release_random(c_ctx_);
        vscf_brainkey_client_use_random(c_ctx_, random.impl());
    }

    void set_operation_random(const Random& operation_random) {
        vscf_brainkey_client_release_operation_random(c_ctx_);
        vscf_brainkey_client_use_operation_random(c_ctx_, operation_random.impl());
    }

    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_brainkey_client_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    tl::expected<BrainkeyClientBlindResult, Error> blind(std::span<const uint8_t> password) {
        std::vector<uint8_t> deblind_factor(this->MPI_LEN);
        vsc_buffer_t* deblind_factor_buf = vsc_buffer_new();
        vsc_buffer_use(deblind_factor_buf, deblind_factor.data(), deblind_factor.size());
        std::vector<uint8_t> blinded_point(this->POINT_LEN);
        vsc_buffer_t* blinded_point_buf = vsc_buffer_new();
        vsc_buffer_use(blinded_point_buf, blinded_point.data(), blinded_point.size());
        const vscf_status_t status = vscf_brainkey_client_blind(c_ctx_, vsc_data(password.data(), password.size()), deblind_factor_buf, blinded_point_buf);
        deblind_factor.resize(vsc_buffer_len(deblind_factor_buf));
        vsc_buffer_delete(deblind_factor_buf);
        blinded_point.resize(vsc_buffer_len(blinded_point_buf));
        vsc_buffer_delete(blinded_point_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return BrainkeyClientBlindResult{.deblind_factor = std::move(deblind_factor), .blinded_point = std::move(blinded_point)};
    }

    tl::expected<std::vector<uint8_t>, Error> deblind(std::span<const uint8_t> password, std::span<const uint8_t> hardened_point, std::span<const uint8_t> deblind_factor, std::span<const uint8_t> key_name) {
        std::vector<uint8_t> seed(this->POINT_LEN);
        vsc_buffer_t* seed_buf = vsc_buffer_new();
        vsc_buffer_use(seed_buf, seed.data(), seed.size());
        const vscf_status_t status = vscf_brainkey_client_deblind(c_ctx_, vsc_data(password.data(), password.size()), vsc_data(hardened_point.data(), hardened_point.size()), vsc_data(deblind_factor.data(), deblind_factor.size()), vsc_data(key_name.data(), key_name.size()), seed_buf);
        seed.resize(vsc_buffer_len(seed_buf));
        vsc_buffer_delete(seed_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return seed;
    }

    /// Verifies the DLEQ proof that hardened_point = x * blinded_point where x corresponds
    /// to server_public_key = x * G. Must be called before deblind() to authenticate
    /// the server response.
    tl::expected<bool, Error> verify(std::span<const uint8_t> blinded_point, std::span<const uint8_t> hardened_point, std::span<const uint8_t> server_public_key, std::span<const uint8_t> proof_value_c, std::span<const uint8_t> proof_value_s) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_brainkey_client_verify(c_ctx_, vsc_data(blinded_point.data(), blinded_point.size()), vsc_data(hardened_point.data(), hardened_point.size()), vsc_data(server_public_key.data(), server_public_key.size()), vsc_data(proof_value_c.data(), proof_value_c.size()), vsc_data(proof_value_s.data(), proof_value_s.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return proxy_result;
    }

private:
    vscf_brainkey_client_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
