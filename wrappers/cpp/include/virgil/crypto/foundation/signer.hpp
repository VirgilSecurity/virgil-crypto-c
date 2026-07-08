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

struct vscf_signer_t;

namespace virgil::crypto::foundation {

class Hash;
class PrivateKey;
class Random;

/// Sign data of any size.
class Signer {
public:
    Signer();
    /// Adopt ownership of an existing C handle.
    explicit Signer(vscf_signer_t* c_ctx) noexcept;
    Signer(const Signer& other);
    Signer(Signer&& other) noexcept;
    Signer& operator=(const Signer& other);
    Signer& operator=(Signer&& other) noexcept;
    ~Signer();

    /// The underlying concrete C handle (non-owning).
    vscf_signer_t* c_ctx() const noexcept;

    void set_hash(const Hash& hash);

    void set_random(const Random& random);

    /// Start a processing a new signature.
    void reset();

    /// Add given data to the signed data.
    void append_data(std::span<const uint8_t> data);

    /// Return length of the signature.
    std::size_t signature_len(const PrivateKey& private_key) const;

    /// Accomplish signing and return signature.
    tl::expected<std::vector<uint8_t>, Error> sign(const PrivateKey& private_key) const;

private:
    vscf_signer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
