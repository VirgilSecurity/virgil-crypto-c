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

#include <virgil/crypto/foundation/message_info_der_serializer.hpp>
#include <virgil/crypto/foundation/vscf_message_info_der_serializer.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/message_info_serializer.hpp>
#include <virgil/crypto/foundation/message_info_footer_serializer.hpp>
#include <virgil/crypto/foundation/asn1_reader.hpp>
#include <virgil/crypto/foundation/asn1_writer.hpp>
#include <virgil/crypto/foundation/message_info.hpp>
#include <virgil/crypto/foundation/message_info_footer.hpp>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

namespace virgil::crypto::foundation {

MessageInfoDerSerializer::MessageInfoDerSerializer() : c_ctx_(vscf_message_info_der_serializer_new()) {}

MessageInfoDerSerializer::MessageInfoDerSerializer(vscf_message_info_der_serializer_t* c_ctx) noexcept : c_ctx_(c_ctx) {}

MessageInfoDerSerializer::MessageInfoDerSerializer(const MessageInfoDerSerializer& other) : c_ctx_(vscf_message_info_der_serializer_shallow_copy(other.c_ctx_)) {}

MessageInfoDerSerializer::MessageInfoDerSerializer(MessageInfoDerSerializer&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }

MessageInfoDerSerializer& MessageInfoDerSerializer::operator=(const MessageInfoDerSerializer& other) {
    if (this != &other) {
        vscf_message_info_der_serializer_delete(c_ctx_);
        c_ctx_ = vscf_message_info_der_serializer_shallow_copy(other.c_ctx_);
    }
    return *this;
}

MessageInfoDerSerializer& MessageInfoDerSerializer::operator=(MessageInfoDerSerializer&& other) noexcept {
    if (this != &other) {
        vscf_message_info_der_serializer_delete(c_ctx_);
        c_ctx_ = other.c_ctx_;
        other.c_ctx_ = nullptr;
    }
    return *this;
}

MessageInfoDerSerializer::~MessageInfoDerSerializer() { vscf_message_info_der_serializer_delete(c_ctx_); }

vscf_message_info_der_serializer_t* MessageInfoDerSerializer::c_ctx() const noexcept { return c_ctx_; }

vscf_impl_t* MessageInfoDerSerializer::impl() const noexcept { return vscf_message_info_der_serializer_impl(c_ctx_); }

void MessageInfoDerSerializer::set_asn1_reader(const Asn1Reader& asn1_reader) {
    vscf_message_info_der_serializer_release_asn1_reader(c_ctx_);
    vscf_message_info_der_serializer_use_asn1_reader(c_ctx_, asn1_reader.impl());
}

void MessageInfoDerSerializer::set_asn1_writer(const Asn1Writer& asn1_writer) {
    vscf_message_info_der_serializer_release_asn1_writer(c_ctx_);
    vscf_message_info_der_serializer_use_asn1_writer(c_ctx_, asn1_writer.impl());
}

void MessageInfoDerSerializer::setup_defaults() {
    vscf_message_info_der_serializer_setup_defaults(c_ctx_);
}

std::size_t MessageInfoDerSerializer::serialized_len(const MessageInfo& message_info) {
    auto proxy_result = vscf_message_info_der_serializer_serialized_len(c_ctx_, message_info.c_ctx());
    return proxy_result;
}

std::vector<uint8_t> MessageInfoDerSerializer::serialize(const MessageInfo& message_info) {
    std::vector<uint8_t> out(this->serialized_len(message_info));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    vscf_message_info_der_serializer_serialize(c_ctx_, message_info.c_ctx(), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    return out;
}

std::size_t MessageInfoDerSerializer::read_prefix(std::span<const uint8_t> data) {
    auto proxy_result = vscf_message_info_der_serializer_read_prefix(c_ctx_, vsc_data(data.data(), data.size()));
    return proxy_result;
}

tl::expected<MessageInfo, Error> MessageInfoDerSerializer::deserialize(std::span<const uint8_t> data) {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_message_info_der_serializer_deserialize(c_ctx_, vsc_data(data.data(), data.size()), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return MessageInfo(proxy_result);
}

std::size_t MessageInfoDerSerializer::serialized_footer_len(const MessageInfoFooter& message_info_footer) {
    auto proxy_result = vscf_message_info_der_serializer_serialized_footer_len(c_ctx_, message_info_footer.c_ctx());
    return proxy_result;
}

std::vector<uint8_t> MessageInfoDerSerializer::serialize_footer(const MessageInfoFooter& message_info_footer) {
    std::vector<uint8_t> out(this->serialized_footer_len(message_info_footer));
    vsc_buffer_t out_buf;
    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, out.data(), out.size());
    vscf_message_info_der_serializer_serialize_footer(c_ctx_, message_info_footer.c_ctx(), &out_buf);
    out.resize(vsc_buffer_len(&out_buf));
    vsc_buffer_cleanup(&out_buf);
    return out;
}

tl::expected<MessageInfoFooter, Error> MessageInfoDerSerializer::deserialize_footer(std::span<const uint8_t> data) {
    vscf_error_t error;
    vscf_error_reset(&error);
    auto proxy_result = vscf_message_info_der_serializer_deserialize_footer(c_ctx_, vsc_data(data.data(), data.size()), &error);
    if (vscf_error_has_error(&error)) {
        return tl::unexpected(static_cast<Error>(vscf_error_status(&error)));
    }
    return MessageInfoFooter(proxy_result);
}

}  // namespace virgil::crypto::foundation
