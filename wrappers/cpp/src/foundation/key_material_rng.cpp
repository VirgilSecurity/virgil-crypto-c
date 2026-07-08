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

#include <virgil/crypto/foundation/key_material_rng.hpp>
#include <virgil/crypto/foundation/vscf_key_material_rng.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

KeyMaterialRng::KeyMaterialRng() : c_ctx_(vscf_key_material_rng_new()) {}

KeyMaterialRng::KeyMaterialRng(vscf_key_material_rng_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

KeyMaterialRng::KeyMaterialRng(const KeyMaterialRng& other) : c_ctx_(vscf_key_material_rng_shallow_copy(other.c_ctx_)) {}

KeyMaterialRng::KeyMaterialRng(KeyMaterialRng&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

KeyMaterialRng& KeyMaterialRng::operator=(const KeyMaterialRng& other) {
    if (this != &other) {
        vscf_key_material_rng_delete(c_ctx_);
        c_ctx_ = vscf_key_material_rng_shallow_copy(other.c_ctx_);
    }
    return *this;
}

KeyMaterialRng& KeyMaterialRng::operator=(KeyMaterialRng&& other) noexcept {
    if (this != &other) {
        vscf_key_material_rng_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

KeyMaterialRng::~KeyMaterialRng() { vscf_key_material_rng_delete(c_ctx_); }

vscf_key_material_rng_t* KeyMaterialRng::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* KeyMaterialRng::impl() const noexcept { return vscf_key_material_rng_impl(c_ctx_); }

void KeyMaterialRng::reset_key_material(std::span<const uint8_t> key_material) {
    vscf_key_material_rng_reset_key_material(c_ctx_, key_material.empty() ? vsc_data_empty() : vsc_data(key_material.data(), key_material.size()));
}

tl::expected<std::vector<uint8_t>, Error> KeyMaterialRng::random(std::size_t data_len) const {
    std::vector<uint8_t> data(data_len);
    vsc_buffer_t data_buf;
    vsc_buffer_init(&data_buf);
    vsc_buffer_use(&data_buf, data.data(), data.size());
    const vscf_status_t status = vscf_key_material_rng_random(c_ctx_, data_len, &data_buf);
    data.resize(vsc_buffer_len(&data_buf));
    vsc_buffer_cleanup(&data_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return data;
}

tl::expected<void, Error> KeyMaterialRng::reseed() {
    const vscf_status_t status = vscf_key_material_rng_reseed(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

}  // namespace virgil::crypto::foundation
