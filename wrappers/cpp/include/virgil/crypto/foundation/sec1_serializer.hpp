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
#include <virgil/crypto/foundation/vscf_sec1_serializer.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/key_serializer.hpp>
#include <virgil/crypto/foundation/asn1_writer.hpp>
#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>

namespace virgil::crypto::foundation {

/// Implements SEC 1 key serialization to DER format.
/// See also RFC 5480 and RFC 5915.
class Sec1Serializer : virtual public KeySerializer {
public:
    Sec1Serializer() : c_ctx_(vscf_sec1_serializer_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Sec1Serializer(vscf_sec1_serializer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Sec1Serializer(const Sec1Serializer& other) : c_ctx_(vscf_sec1_serializer_shallow_copy(other.c_ctx_)) {}
    Sec1Serializer(Sec1Serializer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Sec1Serializer& operator=(const Sec1Serializer& other) {
        if (this != &other) {
            vscf_sec1_serializer_delete(c_ctx_);
            c_ctx_ = vscf_sec1_serializer_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Sec1Serializer& operator=(Sec1Serializer&& other) noexcept {
        if (this != &other) {
            vscf_sec1_serializer_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Sec1Serializer() { vscf_sec1_serializer_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_sec1_serializer_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_sec1_serializer_impl(c_ctx_); }

    void set_asn1_writer(const Asn1Writer& asn1_writer) {
        vscf_sec1_serializer_release_asn1_writer(c_ctx_);
        vscf_sec1_serializer_use_asn1_writer(c_ctx_, asn1_writer.impl());
    }

    /// Setup predefined values to the uninitialized class dependencies.
    void setup_defaults() {
        vscf_sec1_serializer_setup_defaults(c_ctx_);
    }

    /// Serialize Public Key by using internal ASN.1 writer.
    /// Note, that caller code is responsible to reset ASN.1 writer with
    /// an output buffer.
    tl::expected<std::size_t, Error> serialize_public_key_inplace(const RawPublicKey& public_key) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_sec1_serializer_serialize_public_key_inplace(c_ctx_, public_key.c_ctx(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return proxy_result;
    }

    /// Serialize Private Key by using internal ASN.1 writer.
    /// Note, that caller code is responsible to reset ASN.1 writer with
    /// an output buffer.
    tl::expected<std::size_t, Error> serialize_private_key_inplace(const RawPrivateKey& private_key) {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_sec1_serializer_serialize_private_key_inplace(c_ctx_, private_key.c_ctx(), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return proxy_result;
    }

    /// Calculate buffer size enough to hold serialized public key.
    ///
    /// Precondition: public key must be exportable.
    std::size_t serialized_public_key_len(const RawPublicKey& public_key) override {
        auto proxy_result = vscf_sec1_serializer_serialized_public_key_len(c_ctx_, public_key.c_ctx());
        return proxy_result;
    }

    /// Serialize given public key to an interchangeable format.
    ///
    /// Precondition: public key must be exportable.
    tl::expected<std::vector<uint8_t>, Error> serialize_public_key(const RawPublicKey& public_key) override {
        std::vector<uint8_t> out(this->serialized_public_key_len(public_key));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_sec1_serializer_serialize_public_key(c_ctx_, public_key.c_ctx(), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Calculate buffer size enough to hold serialized private key.
    ///
    /// Precondition: private key must be exportable.
    std::size_t serialized_private_key_len(const RawPrivateKey& private_key) override {
        auto proxy_result = vscf_sec1_serializer_serialized_private_key_len(c_ctx_, private_key.c_ctx());
        return proxy_result;
    }

    /// Serialize given private key to an interchangeable format.
    ///
    /// Precondition: private key must be exportable.
    tl::expected<std::vector<uint8_t>, Error> serialize_private_key(const RawPrivateKey& private_key) override {
        std::vector<uint8_t> out(this->serialized_private_key_len(private_key));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_sec1_serializer_serialize_private_key(c_ctx_, private_key.c_ctx(), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

private:
    vscf_sec1_serializer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
