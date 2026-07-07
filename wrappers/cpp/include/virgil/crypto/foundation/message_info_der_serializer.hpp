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
#include <virgil/crypto/foundation/vscf_message_info_der_serializer.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/message_info_serializer.hpp>
#include <virgil/crypto/foundation/message_info_footer_serializer.hpp>
#include <virgil/crypto/foundation/asn1_reader.hpp>
#include <virgil/crypto/foundation/asn1_writer.hpp>
#include <virgil/crypto/foundation/message_info.hpp>
#include <virgil/crypto/foundation/message_info_footer.hpp>

namespace virgil::crypto::foundation {

/// CMS based serialization of the class "message info".
class MessageInfoDerSerializer : virtual public MessageInfoSerializer, virtual public MessageInfoFooterSerializer {
public:
    MessageInfoDerSerializer() : c_ctx_(vscf_message_info_der_serializer_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit MessageInfoDerSerializer(vscf_message_info_der_serializer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    MessageInfoDerSerializer(const MessageInfoDerSerializer& other) : c_ctx_(vscf_message_info_der_serializer_shallow_copy(other.c_ctx_)) {}
    MessageInfoDerSerializer(MessageInfoDerSerializer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    MessageInfoDerSerializer& operator=(const MessageInfoDerSerializer& other) {
        if (this != &other) {
            vscf_message_info_der_serializer_delete(c_ctx_);
            c_ctx_ = vscf_message_info_der_serializer_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    MessageInfoDerSerializer& operator=(MessageInfoDerSerializer&& other) noexcept {
        if (this != &other) {
            vscf_message_info_der_serializer_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~MessageInfoDerSerializer() { vscf_message_info_der_serializer_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_message_info_der_serializer_t* c_ctx() const noexcept { return c_ctx_; }

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override { return vscf_message_info_der_serializer_impl(c_ctx_); }

    static constexpr std::size_t PREFIX_LEN = 32;

    void set_asn1_reader(const Asn1Reader& asn1_reader) {
        vscf_message_info_der_serializer_release_asn1_reader(c_ctx_);
        vscf_message_info_der_serializer_use_asn1_reader(c_ctx_, asn1_reader.impl());
    }

    void set_asn1_writer(const Asn1Writer& asn1_writer) {
        vscf_message_info_der_serializer_release_asn1_writer(c_ctx_);
        vscf_message_info_der_serializer_use_asn1_writer(c_ctx_, asn1_writer.impl());
    }

    /// Setup predefined values to the uninitialized class dependencies.
    void setup_defaults() {
        vscf_message_info_der_serializer_setup_defaults(c_ctx_);
    }

    /// Return buffer size enough to hold serialized message info.
    std::size_t serialized_len(const MessageInfo& message_info) override {
        auto proxy_result = vscf_message_info_der_serializer_serialized_len(c_ctx_, message_info.c_ctx());
        return proxy_result;
    }

    /// Serialize class "message info".
    std::vector<uint8_t> serialize(const MessageInfo& message_info) override {
        std::vector<uint8_t> out(this->serialized_len(message_info));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        vscf_message_info_der_serializer_serialize(c_ctx_, message_info.c_ctx(), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        return out;
    }

    /// Read message info prefix from the given data, and if it is valid,
    /// return a length of bytes of the whole message info.
    ///
    /// Zero returned if length can not be determined from the given data,
    /// and this means that there is no message info at the data beginning.
    std::size_t read_prefix(std::span<const uint8_t> data) override {
        auto proxy_result = vscf_message_info_der_serializer_read_prefix(c_ctx_, vsc_data(data.data(), data.size()));
        return proxy_result;
    }

    /// Deserialize class "message info".
    tl::expected<MessageInfo, Error> deserialize(std::span<const uint8_t> data) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_message_info_der_serializer_deserialize(c_ctx_, vsc_data(data.data(), data.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return MessageInfo(proxy_result);
    }

    /// Return buffer size enough to hold serialized message info footer.
    std::size_t serialized_footer_len(const MessageInfoFooter& message_info_footer) override {
        auto proxy_result = vscf_message_info_der_serializer_serialized_footer_len(c_ctx_, message_info_footer.c_ctx());
        return proxy_result;
    }

    /// Serialize class "message info footer".
    std::vector<uint8_t> serialize_footer(const MessageInfoFooter& message_info_footer) override {
        std::vector<uint8_t> out(this->serialized_footer_len(message_info_footer));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        vscf_message_info_der_serializer_serialize_footer(c_ctx_, message_info_footer.c_ctx(), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        return out;
    }

    /// Deserialize class "message info footer".
    tl::expected<MessageInfoFooter, Error> deserialize_footer(std::span<const uint8_t> data) override {
        vscf_error_t error;
        vscf_error_reset(&error);
        auto proxy_result = vscf_message_info_der_serializer_deserialize_footer(c_ctx_, vsc_data(data.data(), data.size()), &error);
        if (vscf_error_has_error(&error)) {
            return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
        }
        return MessageInfoFooter(proxy_result);
    }

private:
    vscf_message_info_der_serializer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
