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

#include <virgil/crypto/foundation/seed_entropy_source.hpp>
#include <virgil/crypto/foundation/vscf_seed_entropy_source.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/entropy_source.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

SeedEntropySource::SeedEntropySource() : c_ctx_(vscf_seed_entropy_source_new()) {}

SeedEntropySource::SeedEntropySource(vscf_seed_entropy_source_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

SeedEntropySource::SeedEntropySource(const SeedEntropySource& other) : c_ctx_(vscf_seed_entropy_source_shallow_copy(other.c_ctx_)) {}

SeedEntropySource::SeedEntropySource(SeedEntropySource&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

SeedEntropySource& SeedEntropySource::operator=(const SeedEntropySource& other) {
    if (this != &other) {
        vscf_seed_entropy_source_delete(c_ctx_);
        c_ctx_ = vscf_seed_entropy_source_shallow_copy(other.c_ctx_);
    }
    return *this;
}

SeedEntropySource& SeedEntropySource::operator=(SeedEntropySource&& other) noexcept {
    if (this != &other) {
        vscf_seed_entropy_source_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

SeedEntropySource::~SeedEntropySource() { vscf_seed_entropy_source_delete(c_ctx_); }

vscf_seed_entropy_source_t* SeedEntropySource::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* SeedEntropySource::impl() const noexcept { return vscf_seed_entropy_source_impl(c_ctx_); }

void SeedEntropySource::reset_seed(std::span<const uint8_t> seed) {
    vscf_seed_entropy_source_reset_seed(c_ctx_, seed.empty() ? vsc_data_empty() : vsc_data(seed.data(), seed.size()));
}

bool SeedEntropySource::is_strong() {
    auto proxy_result = vscf_seed_entropy_source_is_strong(c_ctx_);
    return proxy_result;
}

tl::expected<std::vector<uint8_t>, Error> SeedEntropySource::gather(std::size_t len) {
    std::vector<uint8_t> out(len);
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    const vscf_status_t status = vscf_seed_entropy_source_gather(c_ctx_, len, &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return out;
}

}  // namespace virgil::crypto::foundation
