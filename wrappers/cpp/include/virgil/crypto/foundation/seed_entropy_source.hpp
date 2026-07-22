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
#include <virgil/crypto/foundation/entropy_source.hpp>

struct vscf_seed_entropy_source_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

/// Deterministic entropy source that is based only on the given seed.
class SeedEntropySource : virtual public EntropySource {
public:
    SeedEntropySource();
    /// Adopt ownership of an existing C handle.
    explicit SeedEntropySource(vscf_seed_entropy_source_t* c_ctx) noexcept;
    SeedEntropySource(const SeedEntropySource& other);
    SeedEntropySource(SeedEntropySource&& other) noexcept;
    SeedEntropySource& operator=(const SeedEntropySource& other);
    SeedEntropySource& operator=(SeedEntropySource&& other) noexcept;
    ~SeedEntropySource();

    /// The underlying concrete C handle (non-owning).
    vscf_seed_entropy_source_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    /// Set a new seed as an entropy source.
    void reset_seed(std::span<const uint8_t> seed);

    /// Defines that implemented source is strong.
    bool is_strong() override;

    /// Gather entropy of the requested length.
    tl::expected<std::vector<uint8_t>, Error> gather(std::size_t len) override;

private:
    vscf_seed_entropy_source_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
