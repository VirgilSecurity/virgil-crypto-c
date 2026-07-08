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

struct vscf_shamir_t;

namespace virgil::crypto::foundation {

class Random;

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
    Shamir();
    /// Adopt ownership of an existing C handle.
    explicit Shamir(vscf_shamir_t* c_ctx) noexcept;
    Shamir(const Shamir& other);
    Shamir(Shamir&& other) noexcept;
    Shamir& operator=(const Shamir& other);
    Shamir& operator=(Shamir&& other) noexcept;
    ~Shamir();

    /// The underlying concrete C handle (non-owning).
    vscf_shamir_t* c_ctx() const noexcept;

    void set_random(const Random& random);

    /// Setup predefined values to the uninitialized class dependencies:
    /// a CTR DRBG random number generator.
    tl::expected<void, Error> setup_defaults();

    /// Calculate an upper bound on the length in bytes of a single share
    /// produced for a secret of the given length. The buffer given to 'split'
    /// must be at least this size; the actual written length may be a few
    /// bytes smaller.
    std::size_t share_len(std::size_t secret_len) const;

    /// Calculate an upper bound on the length in bytes of the buffer needed to
    /// hold all shares produced by 'split' for a secret of the given length and
    /// the given number of shares. The actual written length is reported on the
    /// output buffer by 'split'.
    std::size_t shares_len(std::size_t secret_len, std::size_t share_count) const;

    /// Calculate an upper bound on the length in bytes of the recovered secret
    /// for the given total shares length and number of provided shares.
    /// The exact length is set on the output buffer by 'combine'.
    std::size_t recovered_secret_len(std::size_t shares_len, std::size_t share_count) const;

    /// Split the given secret into 'share count' shares with reconstruction
    /// 'threshold'. Requires a configured random number generator (see
    /// 'setup defaults' / 'use random').
    ///
    /// Constraints: 1 <= threshold <= share count <= 255.
    ///
    /// The produced shares are written consecutively to 'out', all of equal
    /// length and each at most 'share len(secret.len)' bytes.
    tl::expected<std::vector<uint8_t>, Error> split(std::span<const uint8_t> secret, std::size_t threshold, std::size_t share_count);

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
    tl::expected<std::vector<uint8_t>, Error> combine(std::span<const uint8_t> shares, std::size_t share_count) const;

private:
    vscf_shamir_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
