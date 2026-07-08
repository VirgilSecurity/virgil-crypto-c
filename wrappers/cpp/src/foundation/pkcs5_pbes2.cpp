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

#include <virgil/crypto/foundation/pkcs5_pbes2.hpp>
#include <virgil/crypto/foundation/vscf_pkcs5_pbes2.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/encrypt.hpp>
#include <virgil/crypto/foundation/decrypt.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/salted_kdf.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

Pkcs5Pbes2::Pkcs5Pbes2() : c_ctx_(vscf_pkcs5_pbes2_new()) {}

Pkcs5Pbes2::Pkcs5Pbes2(vscf_pkcs5_pbes2_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Pkcs5Pbes2::Pkcs5Pbes2(const Pkcs5Pbes2& other) : c_ctx_(vscf_pkcs5_pbes2_shallow_copy(other.c_ctx_)) {}

Pkcs5Pbes2::Pkcs5Pbes2(Pkcs5Pbes2&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Pkcs5Pbes2& Pkcs5Pbes2::operator=(const Pkcs5Pbes2& other) {
    if (this != &other) {
        vscf_pkcs5_pbes2_delete(c_ctx_);
        c_ctx_ = vscf_pkcs5_pbes2_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Pkcs5Pbes2& Pkcs5Pbes2::operator=(Pkcs5Pbes2&& other) noexcept {
    if (this != &other) {
        vscf_pkcs5_pbes2_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Pkcs5Pbes2::~Pkcs5Pbes2() { vscf_pkcs5_pbes2_delete(c_ctx_); }

vscf_pkcs5_pbes2_t* Pkcs5Pbes2::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Pkcs5Pbes2::impl() const noexcept { return vscf_pkcs5_pbes2_impl(c_ctx_); }

void Pkcs5Pbes2::set_kdf(const SaltedKdf& kdf) {
    vscf_pkcs5_pbes2_release_kdf(c_ctx_);
    vscf_pkcs5_pbes2_use_kdf(c_ctx_, kdf.impl());
}

void Pkcs5Pbes2::set_cipher(const Cipher& cipher) {
    vscf_pkcs5_pbes2_release_cipher(c_ctx_);
    vscf_pkcs5_pbes2_use_cipher(c_ctx_, cipher.impl());
}

void Pkcs5Pbes2::reset(std::span<const uint8_t> pwd) {
    vscf_pkcs5_pbes2_reset(c_ctx_, vsc_data(pwd.data(), pwd.size()));
}

AlgId Pkcs5Pbes2::alg_id() const {
    auto proxy_result = vscf_pkcs5_pbes2_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

std::unique_ptr<AlgInfo> Pkcs5Pbes2::produce_alg_info() const {
    auto proxy_result = vscf_pkcs5_pbes2_produce_alg_info(c_ctx_);
    return FoundationImplementation::wrap_alg_info(proxy_result);
}

tl::expected<void, Error> Pkcs5Pbes2::restore_alg_info(const AlgInfo& alg_info) {
    const vscf_status_t status = vscf_pkcs5_pbes2_restore_alg_info(c_ctx_, alg_info.impl());
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

tl::expected<std::vector<uint8_t>, Error> Pkcs5Pbes2::encrypt(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->encrypted_len(data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_pkcs5_pbes2_encrypt(c_ctx_, vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t Pkcs5Pbes2::encrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_pkcs5_pbes2_encrypted_len(c_ctx_, data_len);
    return proxy_result;
}

std::size_t Pkcs5Pbes2::precise_encrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_pkcs5_pbes2_precise_encrypted_len(c_ctx_, data_len);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> Pkcs5Pbes2::decrypt(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(this->decrypted_len(data.size()));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_pkcs5_pbes2_decrypt(c_ctx_, vsc_data(data.data(), data.size()), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

std::size_t Pkcs5Pbes2::decrypted_len(std::size_t data_len) const {
    auto proxy_result = vscf_pkcs5_pbes2_decrypted_len(c_ctx_, data_len);
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
