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
#include <virgil/crypto/foundation/vscf_shamir.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/random.hpp>

namespace virgil::crypto::foundation {

/// Threshold secret sharing based on Shamir's scheme over GF(256).
///
/// Splits an arbitrary-length secret into 'share count' shares so that any
/// 'threshold' of them reconstruct the secret, while fewer reveal nothing.
///
/// Construction (split-key-encrypt-data): a random 32-byte data key is
/// generated, the secret is encrypted with it using AES-256-GCM, and only the
/// data key is Shamir-split. Each share is self-contained (it embeds the
/// encrypted secret). Recovery combines the shares to rebuild the data key,
/// verifies a commitment to it, and authenticates the decryption with the GCM
/// tag - so wrong, tampered, insufficient, or cross-split shares fail cleanly.
class Shamir {
public:
    Shamir() : c_ctx_(vscf_shamir_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Shamir(vscf_shamir_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Shamir(const Shamir& other) : c_ctx_(vscf_shamir_shallow_copy(other.c_ctx_)) {}
    Shamir(Shamir&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Shamir& operator=(const Shamir& other) {
        if (this != &other) {
            vscf_shamir_delete(c_ctx_);
            c_ctx_ = vscf_shamir_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Shamir& operator=(Shamir&& other) noexcept {
        if (this != &other) {
            vscf_shamir_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Shamir() { vscf_shamir_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_shamir_t* c_ctx() const noexcept { return c_ctx_; }

    void set_random(const Random& random) {
        vscf_shamir_release_random(c_ctx_);
        vscf_shamir_use_random(c_ctx_, random.impl());
    }

    /// Setup predefined values to the uninitialized class dependencies:
    /// a CTR DRBG random number generator.
    tl::expected<void, Error> setup_defaults() {
        const vscf_status_t status = vscf_shamir_setup_defaults(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Calculate an upper bound on the length in bytes of a single share
    /// produced for a secret of the given length. The buffer given to 'split'
    /// must be at least this size; the actual written length may be a few
    /// bytes smaller.
    std::size_t share_len(std::size_t secret_len) {
        auto proxy_result = vscf_shamir_share_len(c_ctx_, secret_len);
        return proxy_result;
    }

    /// Calculate an upper bound on the length in bytes of the buffer needed to
    /// hold all shares produced by 'split' for a secret of the given length and
    /// the given number of shares. The actual written length is reported on the
    /// output buffer by 'split'.
    std::size_t shares_len(std::size_t secret_len, std::size_t share_count) {
        auto proxy_result = vscf_shamir_shares_len(c_ctx_, secret_len, share_count);
        return proxy_result;
    }

    /// Calculate an upper bound on the length in bytes of the recovered secret
    /// for the given total shares length and number of provided shares.
    /// The exact length is set on the output buffer by 'combine'.
    std::size_t recovered_secret_len(std::size_t shares_len, std::size_t share_count) {
        auto proxy_result = vscf_shamir_recovered_secret_len(c_ctx_, shares_len, share_count);
        return proxy_result;
    }

    /// Split the given secret into 'share count' shares with reconstruction
    /// 'threshold'. Requires a configured random number generator (see
    /// 'setup defaults' / 'use random').
    ///
    /// Constraints: 1 <= threshold <= share count <= 255.
    ///
    /// The produced shares are written consecutively to 'out', all of equal
    /// length and each at most 'share len(secret.len)' bytes.
    tl::expected<std::vector<uint8_t>, Error> split(std::span<const uint8_t> secret, std::size_t threshold, std::size_t share_count) {
        std::vector<uint8_t> out(this->shares_len(secret.size(), share_count));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_shamir_split(c_ctx_, vsc_data(secret.data(), secret.size()), threshold, share_count, out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Reconstruct the secret from 'share count' shares concatenated in
    /// 'shares'. 'share count' must be at least the threshold used at split
    /// time.
    ///
    /// Returns 'success' and writes the secret to 'secret' on success.
    /// Returns 'error bad arguments' if the shares are structurally invalid
    /// (malformed/short input, inconsistent or duplicated shares, or shares
    /// that do not belong to the same split). Returns 'error shamir recovery
    /// failed' if the shares are structurally valid but cryptographically
    /// wrong, tampered, or insufficient to meet the threshold. On any failure
    /// the output buffer is left empty.
    tl::expected<std::vector<uint8_t>, Error> combine(std::span<const uint8_t> shares, std::size_t share_count) {
        std::vector<uint8_t> secret(this->recovered_secret_len(shares.size(), share_count));
        vsc_buffer_t* secret_buf = vsc_buffer_new();
        vsc_buffer_use(secret_buf, secret.data(), secret.size());
        const vscf_status_t status = vscf_shamir_combine(c_ctx_, vsc_data(shares.data(), shares.size()), share_count, secret_buf);
        secret.resize(vsc_buffer_len(secret_buf));
        vsc_buffer_delete(secret_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return secret;
    }

private:
    vscf_shamir_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
