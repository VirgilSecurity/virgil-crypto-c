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
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>

struct vscf_sha512_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class AlgInfo;

/// This is MbedTLS implementation of SHA512.
class Sha512 : virtual public Alg, virtual public Hash {
public:
    Sha512();
    /// Adopt ownership of an existing C handle.
    explicit Sha512(vscf_sha512_t* c_ctx) noexcept;
    Sha512(const Sha512& other);
    Sha512(Sha512&& other) noexcept;
    Sha512& operator=(const Sha512& other);
    Sha512& operator=(Sha512&& other) noexcept;
    ~Sha512();

    /// The underlying concrete C handle (non-owning).
    vscf_sha512_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    static constexpr std::size_t DIGEST_LEN = 64;

    static constexpr std::size_t BLOCK_LEN = 128;

    /// Provide algorithm identificator.
    AlgId alg_id() const override;

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() const override;

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override;

    /// Calculate hash over given data.
    std::vector<uint8_t> hash(std::span<const uint8_t> data) override;

    /// Start a new hashing.
    void start() override;

    /// Add given data to the hash.
    void update(std::span<const uint8_t> data) override;

    /// Accompilsh hashing and return it's result (a message digest).
    std::vector<uint8_t> finish() override;

private:
    vscf_sha512_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
