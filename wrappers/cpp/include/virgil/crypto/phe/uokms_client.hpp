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
#include <virgil/crypto/phe/error.hpp>
#include <virgil/crypto/foundation/random.hpp>

struct vsce_uokms_client_t;

namespace virgil::crypto::phe {

/// Result of UokmsClient::generate_encrypt_wrap().
struct UokmsClientGenerateEncryptWrapResult {
    std::vector<uint8_t> wrap;
    std::vector<uint8_t> encryption_key;
};

/// Result of UokmsClient::generate_decrypt_request().
struct UokmsClientGenerateDecryptRequestResult {
    std::vector<uint8_t> deblind_factor;
    std::vector<uint8_t> decrypt_request;
};

/// Result of UokmsClient::rotate_keys().
struct UokmsClientRotateKeysResult {
    std::vector<uint8_t> new_client_private_key;
    std::vector<uint8_t> new_server_public_key;
};

/// Class implements UOKMS for client-side.
class UokmsClient {
public:
    UokmsClient();
    /// Adopt ownership of an existing C handle.
    explicit UokmsClient(vsce_uokms_client_t* c_ctx) noexcept;
    UokmsClient(const UokmsClient& other);
    UokmsClient(UokmsClient&& other) noexcept;
    UokmsClient& operator=(const UokmsClient& other);
    UokmsClient& operator=(UokmsClient&& other) noexcept;
    ~UokmsClient();

    /// The underlying concrete C handle (non-owning).
    vsce_uokms_client_t* c_ctx() const noexcept;

    void set_random(const virgil::crypto::foundation::Random& random);

    void set_operation_random(const virgil::crypto::foundation::Random& operation_random);

    /// Setups dependencies with default values.
    tl::expected<void, Error> setup_defaults();

    /// Sets client private
    /// Call this method before any other methods
    /// This function should be called only once
    tl::expected<void, Error> set_keys_oneparty(std::span<const uint8_t> client_private_key);

    /// Sets client private and server public key
    /// Call this method before any other methods
    /// This function should be called only once
    tl::expected<void, Error> set_keys(std::span<const uint8_t> client_private_key, std::span<const uint8_t> server_public_key);

    /// Generates client private key
    tl::expected<std::vector<uint8_t>, Error> generate_client_private_key();

    /// Generates new encrypt wrap (which should be stored and then used for decryption) + encryption key
    /// of "encryption key len" that can be used for symmetric encryption
    tl::expected<UokmsClientGenerateEncryptWrapResult, Error> generate_encrypt_wrap(std::size_t encryption_key_len);

    /// Decrypt
    tl::expected<std::vector<uint8_t>, Error> decrypt_oneparty(std::span<const uint8_t> wrap, std::size_t encryption_key_len);

    /// Generates request to decrypt data, this request should be sent to the server.
    /// Server response is then passed to "process decrypt response" where encryption key can be decapsulated
    tl::expected<UokmsClientGenerateDecryptRequestResult, Error> generate_decrypt_request(std::span<const uint8_t> wrap);

    /// Processed server response, checks server proof and decapsulates encryption key
    tl::expected<std::vector<uint8_t>, Error> process_decrypt_response(std::span<const uint8_t> wrap, std::span<const uint8_t> decrypt_request, std::span<const uint8_t> decrypt_response, std::span<const uint8_t> deblind_factor, std::size_t encryption_key_len);

    /// Rotates client key using given update token obtained from server
    tl::expected<std::vector<uint8_t>, Error> rotate_keys_oneparty(std::span<const uint8_t> update_token);

    /// Generates update token for one-party mode
    tl::expected<std::vector<uint8_t>, Error> generate_update_token_oneparty();

    /// Rotates client and server keys using given update token obtained from server
    tl::expected<UokmsClientRotateKeysResult, Error> rotate_keys(std::span<const uint8_t> update_token);

private:
    vsce_uokms_client_t* c_ctx_;
};

}  // namespace virgil::crypto::phe
