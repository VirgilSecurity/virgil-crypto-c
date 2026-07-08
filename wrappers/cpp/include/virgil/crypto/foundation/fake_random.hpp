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
#include <virgil/crypto/foundation/entropy_source.hpp>

struct vscf_fake_random_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

/// Random number generator that is used for test purposes only.
class FakeRandom : virtual public Random, virtual public EntropySource {
public:
    FakeRandom();
    /// Adopt ownership of an existing C handle.
    explicit FakeRandom(vscf_fake_random_t* c_ctx) noexcept;
    FakeRandom(const FakeRandom& other);
    FakeRandom(FakeRandom&& other) noexcept;
    FakeRandom& operator=(const FakeRandom& other);
    FakeRandom& operator=(FakeRandom&& other) noexcept;
    ~FakeRandom();

    /// The underlying concrete C handle (non-owning).
    vscf_fake_random_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    /// Configure random number generator to generate sequence filled with given byte.
    void setup_source_byte(uint8_t byte_source);

    /// Configure random number generator to generate random sequence from given data.
    /// Note, that given data is used as circular source.
    void setup_source_data(std::span<const uint8_t> data_source);

    /// Generate random bytes.
    /// All RNG implementations must be thread-safe.
    tl::expected<std::vector<uint8_t>, Error> random(std::size_t data_len) const override;

    /// Retrieve new seed data from the entropy sources.
    tl::expected<void, Error> reseed() override;

    /// Defines that implemented source is strong.
    bool is_strong() override;

    /// Gather entropy of the requested length.
    tl::expected<std::vector<uint8_t>, Error> gather(std::size_t len) override;

private:
    vscf_fake_random_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
