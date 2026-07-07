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
#include <virgil/crypto/foundation/vscf_alg_info_der_serializer.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/alg_info_serializer.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/asn1_writer.hpp>

namespace virgil::crypto::foundation {

/// Provide DER serializer of algorithm information.
class AlgInfoDerSerializer : virtual public AlgInfoSerializer {
public:
    AlgInfoDerSerializer() : c_ctx_(vscf_alg_info_der_serializer_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit AlgInfoDerSerializer(vscf_alg_info_der_serializer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    AlgInfoDerSerializer(const AlgInfoDerSerializer& other) : c_ctx_(vscf_alg_info_der_serializer_shallow_copy(other.c_ctx_)) {}
    AlgInfoDerSerializer(AlgInfoDerSerializer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    AlgInfoDerSerializer& operator=(const AlgInfoDerSerializer& other) {
        if (this != &other) {
            vscf_alg_info_der_serializer_delete(c_ctx_);
            c_ctx_ = vscf_alg_info_der_serializer_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    AlgInfoDerSerializer& operator=(AlgInfoDerSerializer&& other) noexcept {
        if (this != &other) {
            vscf_alg_info_der_serializer_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~AlgInfoDerSerializer() { vscf_alg_info_der_serializer_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_alg_info_der_serializer_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_alg_info_der_serializer_impl(c_ctx_); }

    void set_asn1_writer(const Asn1Writer& asn1_writer) {
        vscf_alg_info_der_serializer_release_asn1_writer(c_ctx_);
        vscf_alg_info_der_serializer_use_asn1_writer(c_ctx_, asn1_writer.impl());
    }

    /// Setup predefined values to the uninitialized class dependencies.
    void setup_defaults() {
        vscf_alg_info_der_serializer_setup_defaults(c_ctx_);
    }

    /// Serialize by using internal ASN.1 writer.
    /// Note, that caller code is responsible to reset ASN.1 writer with
    /// an output buffer.
    std::size_t serialize_inplace(const AlgInfo& alg_info) {
        auto proxy_result = vscf_alg_info_der_serializer_serialize_inplace(c_ctx_, alg_info.impl());
        return proxy_result;
    }

    /// Return buffer size enough to hold serialized algorithm.
    std::size_t serialized_len(const AlgInfo& alg_info) override {
        auto proxy_result = vscf_alg_info_der_serializer_serialized_len(c_ctx_, alg_info.impl());
        return proxy_result;
    }

    /// Serialize algorithm info to buffer class.
    std::vector<uint8_t> serialize(const AlgInfo& alg_info) override {
        std::vector<uint8_t> out(this->serialized_len(alg_info));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        vscf_alg_info_der_serializer_serialize(c_ctx_, alg_info.impl(), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        return out;
    }

private:
    vscf_alg_info_der_serializer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
