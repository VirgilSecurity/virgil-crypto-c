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

#include <virgil/crypto/foundation/key_asn1_deserializer.hpp>
#include <virgil/crypto/foundation/vscf_key_asn1_deserializer.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/key_deserializer.hpp>
#include <virgil/crypto/foundation/asn1_reader.hpp>
#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>

namespace virgil::crypto::foundation {

KeyAsn1Deserializer::KeyAsn1Deserializer() : c_ctx_(vscf_key_asn1_deserializer_new()) {}

KeyAsn1Deserializer::KeyAsn1Deserializer(vscf_key_asn1_deserializer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

KeyAsn1Deserializer::KeyAsn1Deserializer(const KeyAsn1Deserializer& other) : c_ctx_(vscf_key_asn1_deserializer_shallow_copy(other.c_ctx_)) {}

KeyAsn1Deserializer::KeyAsn1Deserializer(KeyAsn1Deserializer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

KeyAsn1Deserializer& KeyAsn1Deserializer::operator=(const KeyAsn1Deserializer& other) {
    if (this != &other) {
        vscf_key_asn1_deserializer_delete(c_ctx_);
        c_ctx_ = vscf_key_asn1_deserializer_shallow_copy(other.c_ctx_);
    }
    return *this;
}

KeyAsn1Deserializer& KeyAsn1Deserializer::operator=(KeyAsn1Deserializer&& other) noexcept {
    if (this != &other) {
        vscf_key_asn1_deserializer_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

KeyAsn1Deserializer::~KeyAsn1Deserializer() { vscf_key_asn1_deserializer_delete(c_ctx_); }

vscf_key_asn1_deserializer_t* KeyAsn1Deserializer::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* KeyAsn1Deserializer::impl() const noexcept { return vscf_key_asn1_deserializer_impl(c_ctx_); }

void KeyAsn1Deserializer::set_asn1_reader(const Asn1Reader& asn1_reader) {
    vscf_key_asn1_deserializer_release_asn1_reader(c_ctx_);
    vscf_key_asn1_deserializer_use_asn1_reader(c_ctx_, asn1_reader.impl());
}

void KeyAsn1Deserializer::setup_defaults() {
    vscf_key_asn1_deserializer_setup_defaults(c_ctx_);
}

tl::expected<RawPublicKey, Error> KeyAsn1Deserializer::deserialize_public_key_inplace() {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_key_asn1_deserializer_deserialize_public_key_inplace(c_ctx_, &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPublicKey(proxy_result);
}

tl::expected<RawPrivateKey, Error> KeyAsn1Deserializer::deserialize_private_key_inplace() {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_key_asn1_deserializer_deserialize_private_key_inplace(c_ctx_, &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPrivateKey(proxy_result);
}

tl::expected<RawPublicKey, Error> KeyAsn1Deserializer::deserialize_public_key(std::span<const uint8_t> public_key_data) {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_key_asn1_deserializer_deserialize_public_key(c_ctx_, public_key_data.empty() ? vsc_data_empty() : vsc_data(public_key_data.data(), public_key_data.size()), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPublicKey(proxy_result);
}

tl::expected<RawPrivateKey, Error> KeyAsn1Deserializer::deserialize_private_key(std::span<const uint8_t> private_key_data) {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_key_asn1_deserializer_deserialize_private_key(c_ctx_, private_key_data.empty() ? vsc_data_empty() : vsc_data(private_key_data.data(), private_key_data.size()), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return RawPrivateKey(proxy_result);
}

}  // namespace virgil::crypto::foundation
