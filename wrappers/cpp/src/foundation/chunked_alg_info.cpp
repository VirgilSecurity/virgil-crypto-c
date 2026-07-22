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

#include <virgil/crypto/foundation/chunked_alg_info.hpp>
#include <virgil/crypto/foundation/vscf_chunked_alg_info.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>

namespace virgil::crypto::foundation {

ChunkedAlgInfo::ChunkedAlgInfo() : c_ctx_(vscf_chunked_alg_info_new()) {}

ChunkedAlgInfo::ChunkedAlgInfo(vscf_chunked_alg_info_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

ChunkedAlgInfo::ChunkedAlgInfo(const ChunkedAlgInfo& other) : c_ctx_(vscf_chunked_alg_info_shallow_copy(other.c_ctx_)) {}

ChunkedAlgInfo::ChunkedAlgInfo(ChunkedAlgInfo&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

ChunkedAlgInfo& ChunkedAlgInfo::operator=(const ChunkedAlgInfo& other) {
    if (this != &other) {
        vscf_chunked_alg_info_delete(c_ctx_);
        c_ctx_ = vscf_chunked_alg_info_shallow_copy(other.c_ctx_);
    }
    return *this;
}

ChunkedAlgInfo& ChunkedAlgInfo::operator=(ChunkedAlgInfo&& other) noexcept {
    if (this != &other) {
        vscf_chunked_alg_info_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

ChunkedAlgInfo::~ChunkedAlgInfo() { vscf_chunked_alg_info_delete(c_ctx_); }

vscf_chunked_alg_info_t* ChunkedAlgInfo::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* ChunkedAlgInfo::impl() const noexcept { return vscf_chunked_alg_info_impl(c_ctx_); }

std::size_t ChunkedAlgInfo::version() const {
    auto proxy_result = vscf_chunked_alg_info_version(c_ctx_);
    return proxy_result;
}

std::size_t ChunkedAlgInfo::chunk_size() const {
    auto proxy_result = vscf_chunked_alg_info_chunk_size(c_ctx_);
    return proxy_result;
}

std::vector<uint8_t> ChunkedAlgInfo::nonce() const {
    auto proxy_result = vscf_chunked_alg_info_nonce(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

AlgId ChunkedAlgInfo::alg_id() const {
    auto proxy_result = vscf_chunked_alg_info_alg_id(c_ctx_);
    return static_cast<AlgId>(proxy_result);
}

}  // namespace virgil::crypto::foundation
