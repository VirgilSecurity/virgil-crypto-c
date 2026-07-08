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

#include <virgil/crypto/foundation/asn1rd.hpp>
#include <virgil/crypto/foundation/vscf_asn1rd.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/asn1_reader.hpp>

namespace virgil::crypto::foundation {

Asn1rd::Asn1rd() : c_ctx_(vscf_asn1rd_new()) {}

Asn1rd::Asn1rd(vscf_asn1rd_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Asn1rd::Asn1rd(const Asn1rd& other) : c_ctx_(vscf_asn1rd_shallow_copy(other.c_ctx_)) {}

Asn1rd::Asn1rd(Asn1rd&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Asn1rd& Asn1rd::operator=(const Asn1rd& other) {
    if (this != &other) {
        vscf_asn1rd_delete(c_ctx_);
        c_ctx_ = vscf_asn1rd_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Asn1rd& Asn1rd::operator=(Asn1rd&& other) noexcept {
    if (this != &other) {
        vscf_asn1rd_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Asn1rd::~Asn1rd() { vscf_asn1rd_delete(c_ctx_); }

vscf_asn1rd_t* Asn1rd::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Asn1rd::impl() const noexcept { return vscf_asn1rd_impl(c_ctx_); }

void Asn1rd::reset(std::span<const uint8_t> data) {
    vscf_asn1rd_reset(c_ctx_, vsc_data(data.data(), data.size()));
}

std::size_t Asn1rd::left_len() {
    auto proxy_result = vscf_asn1rd_left_len(c_ctx_);
    return proxy_result;
}

bool Asn1rd::has_error() const {
    auto proxy_result = vscf_asn1rd_has_error(c_ctx_);
    return proxy_result;
}

tl::expected<void, Error> Asn1rd::status() const {
    const vscf_status_t status = vscf_asn1rd_status(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

int32_t Asn1rd::get_tag() {
    auto proxy_result = vscf_asn1rd_get_tag(c_ctx_);
    return proxy_result;
}

std::size_t Asn1rd::get_len() {
    auto proxy_result = vscf_asn1rd_get_len(c_ctx_);
    return proxy_result;
}

std::size_t Asn1rd::get_data_len() {
    auto proxy_result = vscf_asn1rd_get_data_len(c_ctx_);
    return proxy_result;
}

std::size_t Asn1rd::read_tag(int32_t tag) {
    auto proxy_result = vscf_asn1rd_read_tag(c_ctx_, tag);
    return proxy_result;
}

std::size_t Asn1rd::read_context_tag(int32_t tag) {
    auto proxy_result = vscf_asn1rd_read_context_tag(c_ctx_, tag);
    return proxy_result;
}

int32_t Asn1rd::read_int() {
    auto proxy_result = vscf_asn1rd_read_int(c_ctx_);
    return proxy_result;
}

int8_t Asn1rd::read_int8() {
    auto proxy_result = vscf_asn1rd_read_int8(c_ctx_);
    return proxy_result;
}

int16_t Asn1rd::read_int16() {
    auto proxy_result = vscf_asn1rd_read_int16(c_ctx_);
    return proxy_result;
}

int32_t Asn1rd::read_int32() {
    auto proxy_result = vscf_asn1rd_read_int32(c_ctx_);
    return proxy_result;
}

int64_t Asn1rd::read_int64() {
    auto proxy_result = vscf_asn1rd_read_int64(c_ctx_);
    return proxy_result;
}

uint32_t Asn1rd::read_uint() {
    auto proxy_result = vscf_asn1rd_read_uint(c_ctx_);
    return proxy_result;
}

uint8_t Asn1rd::read_uint8() {
    auto proxy_result = vscf_asn1rd_read_uint8(c_ctx_);
    return proxy_result;
}

uint16_t Asn1rd::read_uint16() {
    auto proxy_result = vscf_asn1rd_read_uint16(c_ctx_);
    return proxy_result;
}

uint32_t Asn1rd::read_uint32() {
    auto proxy_result = vscf_asn1rd_read_uint32(c_ctx_);
    return proxy_result;
}

uint64_t Asn1rd::read_uint64() {
    auto proxy_result = vscf_asn1rd_read_uint64(c_ctx_);
    return proxy_result;
}

bool Asn1rd::read_bool() {
    auto proxy_result = vscf_asn1rd_read_bool(c_ctx_);
    return proxy_result;
}

void Asn1rd::read_null() {
    vscf_asn1rd_read_null(c_ctx_);
}

void Asn1rd::read_null_optional() {
    vscf_asn1rd_read_null_optional(c_ctx_);
}

std::vector<uint8_t> Asn1rd::read_octet_str() {
    auto proxy_result = vscf_asn1rd_read_octet_str(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::vector<uint8_t> Asn1rd::read_bitstring_as_octet_str() {
    auto proxy_result = vscf_asn1rd_read_bitstring_as_octet_str(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::vector<uint8_t> Asn1rd::read_utf8_str() {
    auto proxy_result = vscf_asn1rd_read_utf8_str(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::vector<uint8_t> Asn1rd::read_oid() {
    auto proxy_result = vscf_asn1rd_read_oid(c_ctx_);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::vector<uint8_t> Asn1rd::read_data(std::size_t len) {
    auto proxy_result = vscf_asn1rd_read_data(c_ctx_, len);
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

std::size_t Asn1rd::read_sequence() {
    auto proxy_result = vscf_asn1rd_read_sequence(c_ctx_);
    return proxy_result;
}

std::size_t Asn1rd::read_set() {
    auto proxy_result = vscf_asn1rd_read_set(c_ctx_);
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
