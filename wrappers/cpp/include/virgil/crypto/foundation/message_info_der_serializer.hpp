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
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/message_info_serializer.hpp>
#include <virgil/crypto/foundation/message_info_footer_serializer.hpp>

struct vscf_message_info_der_serializer_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class Asn1Reader;
class Asn1Writer;
class MessageInfo;
class MessageInfoFooter;

/// CMS based serialization of the class "message info".
class MessageInfoDerSerializer : virtual public MessageInfoSerializer, virtual public MessageInfoFooterSerializer {
public:
    MessageInfoDerSerializer();
    /// Adopt ownership of an existing C handle.
    explicit MessageInfoDerSerializer(vscf_message_info_der_serializer_t* c_ctx) noexcept;
    MessageInfoDerSerializer(const MessageInfoDerSerializer& other);
    MessageInfoDerSerializer(MessageInfoDerSerializer&& other) noexcept;
    MessageInfoDerSerializer& operator=(const MessageInfoDerSerializer& other);
    MessageInfoDerSerializer& operator=(MessageInfoDerSerializer&& other) noexcept;
    ~MessageInfoDerSerializer();

    /// The underlying concrete C handle (non-owning).
    vscf_message_info_der_serializer_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    static constexpr std::size_t PREFIX_LEN = 32;

    void set_asn1_reader(const Asn1Reader& asn1_reader);

    void set_asn1_writer(const Asn1Writer& asn1_writer);

    /// Setup predefined values to the uninitialized class dependencies.
    void setup_defaults();

    /// Return buffer size enough to hold serialized message info.
    std::size_t serialized_len(const MessageInfo& message_info) override;

    /// Serialize class "message info".
    std::vector<uint8_t> serialize(const MessageInfo& message_info) override;

    /// Read message info prefix from the given data, and if it is valid,
    /// return a length of bytes of the whole message info.
    ///
    /// Zero returned if length can not be determined from the given data,
    /// and this means that there is no message info at the data beginning.
    std::size_t read_prefix(std::span<const uint8_t> data) override;

    /// Deserialize class "message info".
    tl::expected<MessageInfo, Error> deserialize(std::span<const uint8_t> data) override;

    /// Return buffer size enough to hold serialized message info footer.
    std::size_t serialized_footer_len(const MessageInfoFooter& message_info_footer) override;

    /// Serialize class "message info footer".
    std::vector<uint8_t> serialize_footer(const MessageInfoFooter& message_info_footer) override;

    /// Deserialize class "message info footer".
    tl::expected<MessageInfoFooter, Error> deserialize_footer(std::span<const uint8_t> data) override;

private:
    vscf_message_info_der_serializer_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
