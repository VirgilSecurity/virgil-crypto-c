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
#include <virgil/crypto/phe/error.hpp>
#include <virgil/crypto/foundation/random.hpp>

struct vsce_uokms_wrap_rotation_t;

namespace virgil::crypto::phe {

/// Implements wrap rotation.
class UokmsWrapRotation {
public:
    UokmsWrapRotation();
    /// Adopt ownership of an existing C handle.
    explicit UokmsWrapRotation(vsce_uokms_wrap_rotation_t* c_ctx) noexcept;
    UokmsWrapRotation(const UokmsWrapRotation& other);
    UokmsWrapRotation(UokmsWrapRotation&& other) noexcept;
    UokmsWrapRotation& operator=(const UokmsWrapRotation& other);
    UokmsWrapRotation& operator=(UokmsWrapRotation&& other) noexcept;
    ~UokmsWrapRotation();

    /// The underlying concrete C handle (non-owning).
    vsce_uokms_wrap_rotation_t* c_ctx() const noexcept;

    void set_operation_random(const virgil::crypto::foundation::Random& operation_random);

    /// Setups dependencies with default values.
    tl::expected<void, Error> setup_defaults();

    /// Sets update token. Should be called only once and before any other function
    tl::expected<void, Error> set_update_token(std::span<const uint8_t> update_token);

    /// Updates EnrollmentRecord using server's update token
    tl::expected<std::vector<uint8_t>, Error> update_wrap(std::span<const uint8_t> wrap);

private:
    vsce_uokms_wrap_rotation_t* c_ctx_;
};

}  // namespace virgil::crypto::phe
