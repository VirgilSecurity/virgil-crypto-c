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
#include <memory>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/random.hpp>

struct vscf_key_material_rng_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

/// Random number generator that generate deterministic sequence based
/// on a given seed.
/// This RNG can be used to transform key material rial to the private key.
class KeyMaterialRng : virtual public Random {
public:
    KeyMaterialRng();
    /// Adopt ownership of an existing C handle.
    explicit KeyMaterialRng(vscf_key_material_rng_t* c_ctx) noexcept;
    KeyMaterialRng(const KeyMaterialRng& other);
    KeyMaterialRng(KeyMaterialRng&& other) noexcept;
    KeyMaterialRng& operator=(const KeyMaterialRng& other);
    KeyMaterialRng& operator=(KeyMaterialRng&& other) noexcept;
    ~KeyMaterialRng();

    /// The underlying concrete C handle (non-owning).
    vscf_key_material_rng_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    /// Minimum length in bytes for the key material.
    static constexpr std::size_t KEY_MATERIAL_LEN_MIN = 32;

    /// Maximum length in bytes for the key material.
    static constexpr std::size_t KEY_MATERIAL_LEN_MAX = 512;

    /// Set a new key material.
    void reset_key_material(std::span<const uint8_t> key_material);

    /// Generate random bytes.
    /// All RNG implementations must be thread-safe.
    tl::expected<std::vector<uint8_t>, Error> random(std::size_t data_len) const override;

    /// Retrieve new seed data from the entropy sources.
    tl::expected<void, Error> reseed() override;

private:
    vscf_key_material_rng_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
