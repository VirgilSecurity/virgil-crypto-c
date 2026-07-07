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
#include <virgil/crypto/foundation/vscf_brainkey_server.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/random.hpp>

namespace virgil::crypto::foundation {

/// Result of BrainkeyServer::prove().
struct BrainkeyServerProveResult {
    bool is_success;
    std::vector<uint8_t> proof_value_c;
    std::vector<uint8_t> proof_value_s;
};

class BrainkeyServer {
public:
    BrainkeyServer() : c_ctx_(vscf_brainkey_server_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit BrainkeyServer(vscf_brainkey_server_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    BrainkeyServer(const BrainkeyServer& other) : c_ctx_(vscf_brainkey_server_shallow_copy(other.c_ctx_)) {}
    BrainkeyServer(BrainkeyServer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    BrainkeyServer& operator=(const BrainkeyServer& other) {
        if (this != &other) {
            vscf_brainkey_server_delete(c_ctx_);
            c_ctx_ = vscf_brainkey_server_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    BrainkeyServer& operator=(BrainkeyServer&& other) noexcept {
        if (this != &other) {
            vscf_brainkey_server_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~BrainkeyServer() { vscf_brainkey_server_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_brainkey_server_t* c_ctx() const noexcept { return c_ctx_; }

    static constexpr std::size_t POINT_LEN = 65;

    static constexpr std::size_t MPI_LEN = 32;

    static constexpr std::size_t PROOF_VALUE_LEN = 32;

    void set_random(const Random& random) {
        vscf_brainkey_server_release_random(c_ctx_);
        vscf_brainkey_server_use_random(c_ctx_, random.impl());
    }

    void set_operation_random(const Random& operation_random) {
        vscf_brainkey_server_release_operation_random(c_ctx_);
        vscf_brainkey_server_use_operation_random(c_ctx_, operation_random.impl());
    }

    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_brainkey_server_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    tl::expected<std::vector<uint8_t>, Error> generate_identity_secret() {
        std::vector<uint8_t> identity_secret(this->MPI_LEN);
        vsc_buffer_t* identity_secret_buf = vsc_buffer_new();
        vsc_buffer_use(identity_secret_buf, identity_secret.data(), identity_secret.size());
        const vscf_status_t status = vscf_brainkey_server_generate_identity_secret(c_ctx_, identity_secret_buf);
        identity_secret.resize(vsc_buffer_len(identity_secret_buf));
        vsc_buffer_delete(identity_secret_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return identity_secret;
    }

    tl::expected<std::vector<uint8_t>, Error> harden(std::span<const uint8_t> identity_secret, std::span<const uint8_t> blinded_point) {
        std::vector<uint8_t> hardened_point(this->POINT_LEN);
        vsc_buffer_t* hardened_point_buf = vsc_buffer_new();
        vsc_buffer_use(hardened_point_buf, hardened_point.data(), hardened_point.size());
        const vscf_status_t status = vscf_brainkey_server_harden(c_ctx_, vsc_data(identity_secret.data(), identity_secret.size()), vsc_data(blinded_point.data(), blinded_point.size()), hardened_point_buf);
        hardened_point.resize(vsc_buffer_len(hardened_point_buf));
        vsc_buffer_delete(hardened_point_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return hardened_point;
    }

    /// Computes the server's public key G_x = x*G from the given identity secret x.
    /// Required by the client to verify DLEQ proofs.
    tl::expected<std::vector<uint8_t>, Error> compute_public_key(std::span<const uint8_t> identity_secret) {
        std::vector<uint8_t> public_key(this->POINT_LEN);
        vsc_buffer_t* public_key_buf = vsc_buffer_new();
        vsc_buffer_use(public_key_buf, public_key.data(), public_key.size());
        const vscf_status_t status = vscf_brainkey_server_compute_public_key(c_ctx_, vsc_data(identity_secret.data(), identity_secret.size()), public_key_buf);
        public_key.resize(vsc_buffer_len(public_key_buf));
        vsc_buffer_delete(public_key_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return public_key;
    }

    /// Generates a DLEQ proof that hardened_point = x * blinded_point using the same
    /// identity secret x as server_public_key = x * G.
    /// Client must call verify() before deblind() to authenticate the server response.
    tl::expected<BrainkeyServerProveResult, Error> prove(std::span<const uint8_t> blinded_point, std::span<const uint8_t> hardened_point, std::span<const uint8_t> identity_secret, std::span<const uint8_t> server_public_key) {
        vscf_error_t error;
        vscf_error_reset(&error);
        std::vector<uint8_t> proof_value_c(this->PROOF_VALUE_LEN);
        vsc_buffer_t* proof_value_c_buf = vsc_buffer_new();
        vsc_buffer_use(proof_value_c_buf, proof_value_c.data(), proof_value_c.size());
        std::vector<uint8_t> proof_value_s(this->PROOF_VALUE_LEN);
        vsc_buffer_t* proof_value_s_buf = vsc_buffer_new();
        vsc_buffer_use(proof_value_s_buf, proof_value_s.data(), proof_value_s.size());
        auto proxy_result = vscf_brainkey_server_prove(c_ctx_, vsc_data(blinded_point.data(), blinded_point.size()), vsc_data(hardened_point.data(), hardened_point.size()), vsc_data(identity_secret.data(), identity_secret.size()), vsc_data(server_public_key.data(), server_public_key.size()), proof_value_c_buf, proof_value_s_buf, &error);
        proof_value_c.resize(vsc_buffer_len(proof_value_c_buf));
        vsc_buffer_delete(proof_value_c_buf);
        proof_value_s.resize(vsc_buffer_len(proof_value_s_buf));
        vsc_buffer_delete(proof_value_s_buf);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return BrainkeyServerProveResult{.is_success = proxy_result, .proof_value_c = std::move(proof_value_c), .proof_value_s = std::move(proof_value_s)};
    }

private:
    vscf_brainkey_server_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
