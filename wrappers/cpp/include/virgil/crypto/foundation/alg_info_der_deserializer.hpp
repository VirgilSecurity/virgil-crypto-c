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
#include <vector>
#include <tl/expected.hpp>
#include <memory>
#include <virgil/crypto/foundation/vscf_alg_info_der_deserializer.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_info_deserializer.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/asn1_reader.hpp>
#include <virgil/crypto/foundation/foundation_implementation.hpp>

namespace virgil::crypto::foundation {

/// Provide DER deserializer of algorithm information.
class AlgInfoDerDeserializer : virtual public AlgInfoDeserializer {
public:
    AlgInfoDerDeserializer() : c_ctx_(vscf_alg_info_der_deserializer_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit AlgInfoDerDeserializer(vscf_alg_info_der_deserializer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    AlgInfoDerDeserializer(const AlgInfoDerDeserializer& other) : c_ctx_(vscf_alg_info_der_deserializer_shallow_copy(other.c_ctx_)) {}
    AlgInfoDerDeserializer(AlgInfoDerDeserializer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    AlgInfoDerDeserializer& operator=(const AlgInfoDerDeserializer& other) {
        if (this != &other) {
            vscf_alg_info_der_deserializer_delete(c_ctx_);
            c_ctx_ = vscf_alg_info_der_deserializer_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    AlgInfoDerDeserializer& operator=(AlgInfoDerDeserializer&& other) noexcept {
        if (this != &other) {
            vscf_alg_info_der_deserializer_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~AlgInfoDerDeserializer() { vscf_alg_info_der_deserializer_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_alg_info_der_deserializer_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_alg_info_der_deserializer_impl(c_ctx_); }

    void set_asn1_reader(const Asn1Reader& asn1_reader) {
        vscf_alg_info_der_deserializer_release_asn1_reader(c_ctx_);
        vscf_alg_info_der_deserializer_use_asn1_reader(c_ctx_, asn1_reader.impl());
    }

    /// Setup predefined values to the uninitialized class dependencies.
    void setup_defaults() {
        vscf_alg_info_der_deserializer_setup_defaults(c_ctx_);
    }

    /// Deserialize by using internal ASN.1 reader.
    /// Note, that caller code is responsible to reset ASN.1 reader with
    /// an input buffer.
    tl::expected<std::unique_ptr<AlgInfo>, Error> deserialize_inplace() {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_alg_info_der_deserializer_deserialize_inplace(c_ctx_, &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_alg_info(proxy_result);
    }

    /// Deserialize algorithm from the data.
    tl::expected<std::unique_ptr<AlgInfo>, Error> deserialize(std::span<const uint8_t> data) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_alg_info_der_deserializer_deserialize(c_ctx_, vsc_data(data.data(), data.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return FoundationImplementation::wrap_alg_info(proxy_result);
    }

private:
    vscf_alg_info_der_deserializer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
