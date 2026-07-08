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

#include <virgil/crypto/foundation/entropy_accumulator.hpp>
#include <virgil/crypto/foundation/vscf_entropy_accumulator.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/entropy_source.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

EntropyAccumulator::EntropyAccumulator() : c_ctx_(vscf_entropy_accumulator_new()) {}

EntropyAccumulator::EntropyAccumulator(vscf_entropy_accumulator_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

EntropyAccumulator::EntropyAccumulator(const EntropyAccumulator& other) : c_ctx_(vscf_entropy_accumulator_shallow_copy(other.c_ctx_)) {}

EntropyAccumulator::EntropyAccumulator(EntropyAccumulator&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

EntropyAccumulator& EntropyAccumulator::operator=(const EntropyAccumulator& other) {
    if (this != &other) {
        vscf_entropy_accumulator_delete(c_ctx_);
        c_ctx_ = vscf_entropy_accumulator_shallow_copy(other.c_ctx_);
    }
    return *this;
}

EntropyAccumulator& EntropyAccumulator::operator=(EntropyAccumulator&& other) noexcept {
    if (this != &other) {
        vscf_entropy_accumulator_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

EntropyAccumulator::~EntropyAccumulator() { vscf_entropy_accumulator_delete(c_ctx_); }

vscf_entropy_accumulator_t* EntropyAccumulator::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* EntropyAccumulator::impl() const noexcept { return vscf_entropy_accumulator_impl(c_ctx_); }

void EntropyAccumulator::setup_defaults() {
    vscf_entropy_accumulator_setup_defaults(c_ctx_);
}

void EntropyAccumulator::add_source(const EntropySource& source, std::size_t threshold) {
    vscf_entropy_accumulator_add_source(c_ctx_, source.impl(), threshold);
}

bool EntropyAccumulator::is_strong() {
    auto proxy_result = vscf_entropy_accumulator_is_strong(c_ctx_);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> EntropyAccumulator::gather(std::size_t len) {
    std::vector<uint8_t> out(len);
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_entropy_accumulator_gather(c_ctx_, len, &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
