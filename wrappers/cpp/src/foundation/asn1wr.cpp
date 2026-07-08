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

#include <virgil/crypto/foundation/asn1wr.hpp>
#include <virgil/crypto/foundation/vscf_asn1wr.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/asn1_writer.hpp>

namespace virgil::crypto::foundation {

Asn1wr::Asn1wr() : c_ctx_(vscf_asn1wr_new()) {}

Asn1wr::Asn1wr(vscf_asn1wr_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

Asn1wr::Asn1wr(const Asn1wr& other) : c_ctx_(vscf_asn1wr_shallow_copy(other.c_ctx_)) {}

Asn1wr::Asn1wr(Asn1wr&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

Asn1wr& Asn1wr::operator=(const Asn1wr& other) {
    if (this != &other) {
        vscf_asn1wr_delete(c_ctx_);
        c_ctx_ = vscf_asn1wr_shallow_copy(other.c_ctx_);
    }
    return *this;
}

Asn1wr& Asn1wr::operator=(Asn1wr&& other) noexcept {
    if (this != &other) {
        vscf_asn1wr_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

Asn1wr::~Asn1wr() { vscf_asn1wr_delete(c_ctx_); }

vscf_asn1wr_t* Asn1wr::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* Asn1wr::impl() const noexcept { return vscf_asn1wr_impl(c_ctx_); }

void Asn1wr::reset(uint8_t* out, std::size_t out_len) {
    vscf_asn1wr_reset(c_ctx_, out, out_len);
}

std::size_t Asn1wr::finish(bool do_not_adjust) {
    auto proxy_result = vscf_asn1wr_finish(c_ctx_, do_not_adjust);
    return proxy_result;
}

uint8_t* Asn1wr::bytes() {
    auto proxy_result = vscf_asn1wr_bytes(c_ctx_);
    return proxy_result;
}

std::size_t Asn1wr::len() const {
    auto proxy_result = vscf_asn1wr_len(c_ctx_);
    return proxy_result;
}

std::size_t Asn1wr::written_len() const {
    auto proxy_result = vscf_asn1wr_written_len(c_ctx_);
    return proxy_result;
}

std::size_t Asn1wr::unwritten_len() const {
    auto proxy_result = vscf_asn1wr_unwritten_len(c_ctx_);
    return proxy_result;
}

bool Asn1wr::has_error() const {
    auto proxy_result = vscf_asn1wr_has_error(c_ctx_);
    return proxy_result;
}

tl::expected<void, Error> Asn1wr::status() const {
    const vscf_status_t status = vscf_asn1wr_status(c_ctx_);
    if (status != vscf_status_SUCCESS) {
        return tl::unexpected(static_cast<Error>(status));
    }
    return {};
}

uint8_t* Asn1wr::reserve(std::size_t len) {
    auto proxy_result = vscf_asn1wr_reserve(c_ctx_, len);
    return proxy_result;
}

std::size_t Asn1wr::write_tag(int32_t tag) {
    auto proxy_result = vscf_asn1wr_write_tag(c_ctx_, tag);
    return proxy_result;
}

std::size_t Asn1wr::write_context_tag(int32_t tag, std::size_t len) {
    auto proxy_result = vscf_asn1wr_write_context_tag(c_ctx_, tag, len);
    return proxy_result;
}

std::size_t Asn1wr::write_len(std::size_t len) {
    auto proxy_result = vscf_asn1wr_write_len(c_ctx_, len);
    return proxy_result;
}

std::size_t Asn1wr::write_int(int32_t value) {
    auto proxy_result = vscf_asn1wr_write_int(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_int8(int8_t value) {
    auto proxy_result = vscf_asn1wr_write_int8(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_int16(int16_t value) {
    auto proxy_result = vscf_asn1wr_write_int16(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_int32(int32_t value) {
    auto proxy_result = vscf_asn1wr_write_int32(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_int64(int64_t value) {
    auto proxy_result = vscf_asn1wr_write_int64(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_uint(uint32_t value) {
    auto proxy_result = vscf_asn1wr_write_uint(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_uint8(uint8_t value) {
    auto proxy_result = vscf_asn1wr_write_uint8(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_uint16(uint16_t value) {
    auto proxy_result = vscf_asn1wr_write_uint16(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_uint32(uint32_t value) {
    auto proxy_result = vscf_asn1wr_write_uint32(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_uint64(uint64_t value) {
    auto proxy_result = vscf_asn1wr_write_uint64(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_bool(bool value) {
    auto proxy_result = vscf_asn1wr_write_bool(c_ctx_, value);
    return proxy_result;
}

std::size_t Asn1wr::write_null() {
    auto proxy_result = vscf_asn1wr_write_null(c_ctx_);
    return proxy_result;
}

std::size_t Asn1wr::write_octet_str(std::span<const uint8_t> value) {
    auto proxy_result = vscf_asn1wr_write_octet_str(c_ctx_, vsc_data(value.data(), value.size()));
    return proxy_result;
}

std::size_t Asn1wr::write_octet_str_as_bitstring(std::span<const uint8_t> value) {
    auto proxy_result = vscf_asn1wr_write_octet_str_as_bitstring(c_ctx_, vsc_data(value.data(), value.size()));
    return proxy_result;
}

std::size_t Asn1wr::write_data(std::span<const uint8_t> data) {
    auto proxy_result = vscf_asn1wr_write_data(c_ctx_, vsc_data(data.data(), data.size()));
    return proxy_result;
}

std::size_t Asn1wr::write_utf8_str(std::span<const uint8_t> value) {
    auto proxy_result = vscf_asn1wr_write_utf8_str(c_ctx_, vsc_data(value.data(), value.size()));
    return proxy_result;
}

std::size_t Asn1wr::write_oid(std::span<const uint8_t> value) {
    auto proxy_result = vscf_asn1wr_write_oid(c_ctx_, vsc_data(value.data(), value.size()));
    return proxy_result;
}

std::size_t Asn1wr::write_sequence(std::size_t len) {
    auto proxy_result = vscf_asn1wr_write_sequence(c_ctx_, len);
    return proxy_result;
}

std::size_t Asn1wr::write_set(std::size_t len) {
    auto proxy_result = vscf_asn1wr_write_set(c_ctx_, len);
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
