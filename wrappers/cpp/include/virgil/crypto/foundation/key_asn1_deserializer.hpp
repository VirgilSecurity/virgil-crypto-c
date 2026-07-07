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
#include <virgil/crypto/foundation/vscf_key_asn1_deserializer.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/key_deserializer.hpp>
#include <virgil/crypto/foundation/asn1_reader.hpp>
#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>

namespace virgil::crypto::foundation {

/// Implements PKCS#8 and SEC1 key deserialization from DER / PEM format.
class KeyAsn1Deserializer : virtual public KeyDeserializer {
public:
    KeyAsn1Deserializer() : c_ctx_(vscf_key_asn1_deserializer_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit KeyAsn1Deserializer(vscf_key_asn1_deserializer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    KeyAsn1Deserializer(const KeyAsn1Deserializer& other) : c_ctx_(vscf_key_asn1_deserializer_shallow_copy(other.c_ctx_)) {}
    KeyAsn1Deserializer(KeyAsn1Deserializer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    KeyAsn1Deserializer& operator=(const KeyAsn1Deserializer& other) {
        if (this != &other) {
            vscf_key_asn1_deserializer_delete(c_ctx_);
            c_ctx_ = vscf_key_asn1_deserializer_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    KeyAsn1Deserializer& operator=(KeyAsn1Deserializer&& other) noexcept {
        if (this != &other) {
            vscf_key_asn1_deserializer_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~KeyAsn1Deserializer() { vscf_key_asn1_deserializer_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_key_asn1_deserializer_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_key_asn1_deserializer_impl(c_ctx_); }

    void set_asn1_reader(const Asn1Reader& asn1_reader) {
        vscf_key_asn1_deserializer_release_asn1_reader(c_ctx_);
        vscf_key_asn1_deserializer_use_asn1_reader(c_ctx_, asn1_reader.impl());
    }

    /// Setup predefined values to the uninitialized class dependencies.
    void setup_defaults() {
        vscf_key_asn1_deserializer_setup_defaults(c_ctx_);
    }

    /// Deserialize Public Key by using internal ASN.1 reader.
    /// Note, that caller code is responsible to reset ASN.1 reader with
    /// an input buffer.
    tl::expected<RawPublicKey, Error> deserialize_public_key_inplace() {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_asn1_deserializer_deserialize_public_key_inplace(c_ctx_, &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return RawPublicKey(proxy_result);
    }

    /// Deserialize Private Key by using internal ASN.1 reader.
    /// Note, that caller code is responsible to reset ASN.1 reader with
    /// an input buffer.
    tl::expected<RawPrivateKey, Error> deserialize_private_key_inplace() {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_asn1_deserializer_deserialize_private_key_inplace(c_ctx_, &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return RawPrivateKey(proxy_result);
    }

    /// Deserialize given public key as an interchangeable format to the object.
    tl::expected<RawPublicKey, Error> deserialize_public_key(std::span<const uint8_t> public_key_data) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_asn1_deserializer_deserialize_public_key(c_ctx_, vsc_data(public_key_data.data(), public_key_data.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return RawPublicKey(proxy_result);
    }

    /// Deserialize given private key as an interchangeable format to the object.
    tl::expected<RawPrivateKey, Error> deserialize_private_key(std::span<const uint8_t> private_key_data) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_key_asn1_deserializer_deserialize_private_key(c_ctx_, vsc_data(private_key_data.data(), private_key_data.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return RawPrivateKey(proxy_result);
    }

private:
    vscf_key_asn1_deserializer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
