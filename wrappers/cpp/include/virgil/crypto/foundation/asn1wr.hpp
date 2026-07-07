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
#include <virgil/crypto/foundation/vscf_asn1wr.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/asn1_writer.hpp>

namespace virgil::crypto::foundation {

/// This is MbedTLS implementation of ASN.1 writer.
class Asn1wr : virtual public Asn1Writer {
public:
    Asn1wr() : c_ctx_(vscf_asn1wr_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit Asn1wr(vscf_asn1wr_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    Asn1wr(const Asn1wr& other) : c_ctx_(vscf_asn1wr_shallow_copy(other.c_ctx_)) {}
    Asn1wr(Asn1wr&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    Asn1wr& operator=(const Asn1wr& other) {
        if (this != &other) {
            vscf_asn1wr_delete(c_ctx_);
            c_ctx_ = vscf_asn1wr_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    Asn1wr& operator=(Asn1wr&& other) noexcept {
        if (this != &other) {
            vscf_asn1wr_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~Asn1wr() { vscf_asn1wr_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_asn1wr_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_asn1wr_impl(c_ctx_); }

    /// Reset all internal states and prepare to new ASN.1 writing operations.
    void reset(uint8_t* out, std::size_t out_len) override {
        vscf_asn1wr_reset(c_ctx_, out, out_len);
    }

    /// Finalize writing and forbid further operations.
    ///
    /// Note, that ASN.1 structure is always written to the buffer end, and
    /// if argument "do not adjust" is false, then data is moved to the
    /// beginning, otherwise - data is left at the buffer end.
    ///
    /// Returns length of the written bytes.
    std::size_t finish(bool do_not_adjust) override {
        auto proxy_result = vscf_asn1wr_finish(c_ctx_, do_not_adjust);
        return proxy_result;
    }

    /// Returns pointer to the inner buffer.
    uint8_t* bytes() override {
        auto proxy_result = vscf_asn1wr_bytes(c_ctx_);
        return proxy_result;
    }

    /// Returns total inner buffer length.
    std::size_t len() override {
        auto proxy_result = vscf_asn1wr_len(c_ctx_);
        return proxy_result;
    }

    /// Returns how many bytes were already written to the ASN.1 structure.
    std::size_t written_len() override {
        auto proxy_result = vscf_asn1wr_written_len(c_ctx_);
        return proxy_result;
    }

    /// Returns how many bytes are available for writing.
    std::size_t unwritten_len() override {
        auto proxy_result = vscf_asn1wr_unwritten_len(c_ctx_);
        return proxy_result;
    }

    /// Return true if status is not "success".
    bool has_error() override {
        auto proxy_result = vscf_asn1wr_has_error(c_ctx_);
        return proxy_result;
    }

    /// Return error code.
    tl::expected<void, Error> status() override {
        const vscf_status_t status = vscf_asn1wr_status(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Move writing position backward for the given length.
    /// Return current writing position.
    uint8_t* reserve(std::size_t len) override {
        auto proxy_result = vscf_asn1wr_reserve(c_ctx_, len);
        return proxy_result;
    }

    /// Write ASN.1 tag.
    /// Return count of written bytes.
    std::size_t write_tag(int32_t tag) override {
        auto proxy_result = vscf_asn1wr_write_tag(c_ctx_, tag);
        return proxy_result;
    }

    /// Write context-specific ASN.1 tag.
    /// Return count of written bytes.
    std::size_t write_context_tag(int32_t tag, std::size_t len) override {
        auto proxy_result = vscf_asn1wr_write_context_tag(c_ctx_, tag, len);
        return proxy_result;
    }

    /// Write length of the following data.
    /// Return count of written bytes.
    std::size_t write_len(std::size_t len) override {
        auto proxy_result = vscf_asn1wr_write_len(c_ctx_, len);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_int(int32_t value) override {
        auto proxy_result = vscf_asn1wr_write_int(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_int8(int8_t value) override {
        auto proxy_result = vscf_asn1wr_write_int8(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_int16(int16_t value) override {
        auto proxy_result = vscf_asn1wr_write_int16(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_int32(int32_t value) override {
        auto proxy_result = vscf_asn1wr_write_int32(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_int64(int64_t value) override {
        auto proxy_result = vscf_asn1wr_write_int64(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_uint(uint32_t value) override {
        auto proxy_result = vscf_asn1wr_write_uint(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_uint8(uint8_t value) override {
        auto proxy_result = vscf_asn1wr_write_uint8(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_uint16(uint16_t value) override {
        auto proxy_result = vscf_asn1wr_write_uint16(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_uint32(uint32_t value) override {
        auto proxy_result = vscf_asn1wr_write_uint32(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: INTEGER.
    /// Return count of written bytes.
    std::size_t write_uint64(uint64_t value) override {
        auto proxy_result = vscf_asn1wr_write_uint64(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: BOOLEAN.
    /// Return count of written bytes.
    std::size_t write_bool(bool value) override {
        auto proxy_result = vscf_asn1wr_write_bool(c_ctx_, value);
        return proxy_result;
    }

    /// Write ASN.1 type: NULL.
    std::size_t write_null() override {
        auto proxy_result = vscf_asn1wr_write_null(c_ctx_);
        return proxy_result;
    }

    /// Write ASN.1 type: OCTET STRING.
    /// Return count of written bytes.
    std::size_t write_octet_str(std::span<const uint8_t> value) override {
        auto proxy_result = vscf_asn1wr_write_octet_str(c_ctx_, vsc_data(value.data(), value.size()));
        return proxy_result;
    }

    /// Write ASN.1 type: BIT STRING with all zero unused bits.
    ///
    /// Return count of written bytes.
    std::size_t write_octet_str_as_bitstring(std::span<const uint8_t> value) override {
        auto proxy_result = vscf_asn1wr_write_octet_str_as_bitstring(c_ctx_, vsc_data(value.data(), value.size()));
        return proxy_result;
    }

    /// Write raw data directly to the ASN.1 structure.
    /// Return count of written bytes.
    /// Note, use this method carefully.
    std::size_t write_data(std::span<const uint8_t> data) override {
        auto proxy_result = vscf_asn1wr_write_data(c_ctx_, vsc_data(data.data(), data.size()));
        return proxy_result;
    }

    /// Write ASN.1 type: UTF8String.
    /// Return count of written bytes.
    std::size_t write_utf8_str(std::span<const uint8_t> value) override {
        auto proxy_result = vscf_asn1wr_write_utf8_str(c_ctx_, vsc_data(value.data(), value.size()));
        return proxy_result;
    }

    /// Write ASN.1 type: OID.
    /// Return count of written bytes.
    std::size_t write_oid(std::span<const uint8_t> value) override {
        auto proxy_result = vscf_asn1wr_write_oid(c_ctx_, vsc_data(value.data(), value.size()));
        return proxy_result;
    }

    /// Mark previously written data of given length as ASN.1 type: SEQUENCE.
    /// Return count of written bytes.
    std::size_t write_sequence(std::size_t len) override {
        auto proxy_result = vscf_asn1wr_write_sequence(c_ctx_, len);
        return proxy_result;
    }

    /// Mark previously written data of given length as ASN.1 type: SET.
    /// Return count of written bytes.
    std::size_t write_set(std::size_t len) override {
        auto proxy_result = vscf_asn1wr_write_set(c_ctx_, len);
        return proxy_result;
    }

private:
    vscf_asn1wr_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
