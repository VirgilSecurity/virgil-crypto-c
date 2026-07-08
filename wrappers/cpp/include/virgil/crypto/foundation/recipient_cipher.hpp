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
#include <virgil/crypto/foundation/vscf_recipient_cipher.h>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/key_wrap.hpp>
#include <virgil/crypto/foundation/message_info_custom_params.hpp>
#include <virgil/crypto/foundation/padding.hpp>
#include <virgil/crypto/foundation/padding_params.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/signer_info.hpp>
#include <virgil/crypto/foundation/signer_info_list.hpp>

namespace virgil::crypto::foundation {

/// This class provides hybrid encryption algorithm that combines symmetric
/// cipher for data encryption and asymmetric cipher and password based
/// cipher for symmetric key encryption.
class RecipientCipher {
public:
    RecipientCipher() : c_ctx_(vscf_recipient_cipher_new()) {}
    /// Adopt ownership of an existing C handle.
    explicit RecipientCipher(vscf_recipient_cipher_t* c_ctx) noexcept : c_ctx_(c_ctx) {}
    RecipientCipher(const RecipientCipher& other) : c_ctx_(vscf_recipient_cipher_shallow_copy(other.c_ctx_)) {}
    RecipientCipher(RecipientCipher&& other) noexcept : c_ctx_(other.c_ctx_) { other.c_ctx_ = nullptr; }
    RecipientCipher& operator=(const RecipientCipher& other) {
        if (this != &other) {
            vscf_recipient_cipher_delete(c_ctx_);
            c_ctx_ = vscf_recipient_cipher_shallow_copy(other.c_ctx_);
        }
        return *this;
    }
    RecipientCipher& operator=(RecipientCipher&& other) noexcept {
        if (this != &other) {
            vscf_recipient_cipher_delete(c_ctx_);
            c_ctx_ = other.c_ctx_;
            other.c_ctx_ = nullptr;
        }
        return *this;
    }
    ~RecipientCipher() { vscf_recipient_cipher_delete(c_ctx_); }

    /// The underlying concrete C handle (non-owning).
    vscf_recipient_cipher_t* c_ctx() const noexcept { return c_ctx_; }

    void set_random(const Random& random) {
        vscf_recipient_cipher_release_random(c_ctx_);
        vscf_recipient_cipher_use_random(c_ctx_, random.impl());
    }

    void set_encryption_cipher(const Cipher& encryption_cipher) {
        vscf_recipient_cipher_release_encryption_cipher(c_ctx_);
        vscf_recipient_cipher_use_encryption_cipher(c_ctx_, encryption_cipher.impl());
    }

    void set_encryption_padding(const Padding& encryption_padding) {
        vscf_recipient_cipher_release_encryption_padding(c_ctx_);
        vscf_recipient_cipher_use_encryption_padding(c_ctx_, encryption_padding.impl());
    }

    void set_padding_params(const PaddingParams& padding_params) {
        vscf_recipient_cipher_release_padding_params(c_ctx_);
        vscf_recipient_cipher_use_padding_params(c_ctx_, padding_params.c_ctx());
    }

    void set_signer_hash(const Hash& signer_hash) {
        vscf_recipient_cipher_release_signer_hash(c_ctx_);
        vscf_recipient_cipher_use_signer_hash(c_ctx_, signer_hash.impl());
    }

    /// Return true if a key recipient with a given id has been added.
    /// Note, operation has O(N) time complexity.
    bool has_key_recipient(std::span<const uint8_t> recipient_id) const {
        auto proxy_result = vscf_recipient_cipher_has_key_recipient(c_ctx_, vsc_data(recipient_id.data(), recipient_id.size()));
        return proxy_result;
    }

    /// Add recipient defined with id and public key.
    void add_key_recipient(std::span<const uint8_t> recipient_id, const PublicKey& public_key) {
        vscf_recipient_cipher_add_key_recipient(c_ctx_, vsc_data(recipient_id.data(), recipient_id.size()), public_key.impl());
    }

    /// Add recipient defined with a KEK identifier and key wrap algorithm.
    void add_kek_recipient(std::span<const uint8_t> kek_id, std::span<const uint8_t> kek, const KeyWrap& key_wrap) {
        vscf_recipient_cipher_add_kek_recipient(c_ctx_, vsc_data(kek_id.data(), kek_id.size()), vsc_data(kek.data(), kek.size()), key_wrap.impl());
    }

    /// Remove all recipients.
    void clear_recipients() {
        vscf_recipient_cipher_clear_recipients(c_ctx_);
    }

    /// Add identifier and private key to sign initial plain text.
    /// Return error if the private key can not sign.
    tl::expected<void, Error> add_signer(std::span<const uint8_t> signer_id, const PrivateKey& private_key) {
        const vscf_status_t status = vscf_recipient_cipher_add_signer(c_ctx_, vsc_data(signer_id.data(), signer_id.size()), private_key.impl());
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Remove all signers.
    void clear_signers() {
        vscf_recipient_cipher_clear_signers(c_ctx_);
    }

    /// Provide access to the custom params object.
    /// The returned object can be used to add custom params or read it.
    MessageInfoCustomParams custom_params() {
        auto proxy_result = vscf_recipient_cipher_custom_params(c_ctx_);
        return MessageInfoCustomParams(vscf_message_info_custom_params_shallow_copy(const_cast<vscf_message_info_custom_params_t*>(proxy_result)));
    }

    /// Start encryption process.
    tl::expected<void, Error> start_encryption() {
        const vscf_status_t status = vscf_recipient_cipher_start_encryption(c_ctx_);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Start encryption process with known plain text size.
    ///
    /// Precondition: At least one signer should be added.
    /// Note, store message info footer as well.
    tl::expected<void, Error> start_signed_encryption(std::size_t data_size) {
        const vscf_status_t status = vscf_recipient_cipher_start_signed_encryption(c_ctx_, data_size);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Return buffer length required to hold message info returned by the
    /// "pack message info" method.
    /// Precondition: all recipients and custom parameters should be set.
    std::size_t message_info_len() const {
        auto proxy_result = vscf_recipient_cipher_message_info_len(c_ctx_);
        return proxy_result;
    }

    /// Return serialized message info to the buffer.
    ///
    /// Precondition: this method should be called after "start encryption".
    /// Precondition: this method should be called before "finish encryption".
    ///
    /// Note, store message info to use it for decryption process,
    /// or place it at the encrypted data beginning (embedding).
    ///
    /// Return message info - recipients public information,
    /// algorithm information, etc.
    std::vector<uint8_t> pack_message_info() {
        std::vector<uint8_t> message_info(this->message_info_len());
        vsc_buffer_t* message_info_buf = vsc_buffer_new();
        vsc_buffer_use(message_info_buf, message_info.data(), message_info.size());
        vscf_recipient_cipher_pack_message_info(c_ctx_, message_info_buf);
        message_info.resize(vsc_buffer_len(message_info_buf));
        vsc_buffer_delete(message_info_buf);
        return message_info;
    }

    /// Return buffer length required to hold output of the method
    /// "process encryption" and method "finish" during encryption.
    std::size_t encryption_out_len(std::size_t data_len) {
        auto proxy_result = vscf_recipient_cipher_encryption_out_len(c_ctx_, data_len);
        return proxy_result;
    }

    /// Process encryption of a new portion of data.
    tl::expected<std::vector<uint8_t>, Error> process_encryption(std::span<const uint8_t> data) {
        std::vector<uint8_t> out(this->encryption_out_len(data.size()));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_recipient_cipher_process_encryption(c_ctx_, vsc_data(data.data(), data.size()), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Accomplish encryption.
    tl::expected<std::vector<uint8_t>, Error> finish_encryption() {
        std::vector<uint8_t> out(this->encryption_out_len(0));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_recipient_cipher_finish_encryption(c_ctx_, out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Initiate decryption process with a pre-shared symmetric key (KEK).
    /// Message Info can be empty if it was embedded to encrypted data.
    tl::expected<void, Error> start_decryption_with_kek(std::span<const uint8_t> kek_id, std::span<const uint8_t> kek, const KeyWrap& key_wrap, std::span<const uint8_t> message_info) {
        const vscf_status_t status = vscf_recipient_cipher_start_decryption_with_kek(c_ctx_, vsc_data(kek_id.data(), kek_id.size()), vsc_data(kek.data(), kek.size()), key_wrap.impl(), vsc_data(message_info.data(), message_info.size()));
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Initiate decryption process with a recipient private key.
    /// Message Info can be empty if it was embedded to encrypted data.
    tl::expected<void, Error> start_decryption_with_key(std::span<const uint8_t> recipient_id, const PrivateKey& private_key, std::span<const uint8_t> message_info) {
        const vscf_status_t status = vscf_recipient_cipher_start_decryption_with_key(c_ctx_, vsc_data(recipient_id.data(), recipient_id.size()), private_key.impl(), vsc_data(message_info.data(), message_info.size()));
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Initiate decryption process with a recipient private key.
    /// Message Info can be empty if it was embedded to encrypted data.
    /// Message Info footer can be empty if it was embedded to encrypted data.
    /// If footer was embedded, method "start decryption with key" can be used.
    tl::expected<void, Error> start_verified_decryption_with_key(std::span<const uint8_t> recipient_id, const PrivateKey& private_key, std::span<const uint8_t> message_info, std::span<const uint8_t> message_info_footer) {
        const vscf_status_t status = vscf_recipient_cipher_start_verified_decryption_with_key(c_ctx_, vsc_data(recipient_id.data(), recipient_id.size()), private_key.impl(), vsc_data(message_info.data(), message_info.size()), vsc_data(message_info_footer.data(), message_info_footer.size()));
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return {};
    }

    /// Return buffer length required to hold output of the method
    /// "process decryption" and method "finish" during decryption.
    std::size_t decryption_out_len(std::size_t data_len) {
        auto proxy_result = vscf_recipient_cipher_decryption_out_len(c_ctx_, data_len);
        return proxy_result;
    }

    /// Process with a new portion of data.
    /// Return error if data can not be encrypted or decrypted.
    tl::expected<std::vector<uint8_t>, Error> process_decryption(std::span<const uint8_t> data) {
        std::vector<uint8_t> out(this->decryption_out_len(data.size()));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_recipient_cipher_process_decryption(c_ctx_, vsc_data(data.data(), data.size()), out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Accomplish decryption.
    tl::expected<std::vector<uint8_t>, Error> finish_decryption() {
        std::vector<uint8_t> out(this->decryption_out_len(0));
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_recipient_cipher_finish_decryption(c_ctx_, out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

    /// Return true if data was signed by a sender.
    ///
    /// Precondition: this method should be called after "finish decryption".
    bool is_data_signed() const {
        auto proxy_result = vscf_recipient_cipher_is_data_signed(c_ctx_);
        return proxy_result;
    }

    /// Return information about signers that sign data.
    ///
    /// Precondition: this method should be called after "finish decryption".
    /// Precondition: method "is data signed" returns true.
    SignerInfoList signer_infos() const {
        auto proxy_result = vscf_recipient_cipher_signer_infos(c_ctx_);
        return SignerInfoList(vscf_signer_info_list_shallow_copy(const_cast<vscf_signer_info_list_t*>(proxy_result)));
    }

    /// Verify given cipher info.
    bool verify_signer_info(const SignerInfo& signer_info, const PublicKey& public_key) {
        auto proxy_result = vscf_recipient_cipher_verify_signer_info(c_ctx_, signer_info.c_ctx(), public_key.impl());
        return proxy_result;
    }

    /// Return buffer length required to hold message footer returned by the
    /// "pack message footer" method.
    ///
    /// Precondition: this method should be called after "finish encryption".
    std::size_t message_info_footer_len() const {
        auto proxy_result = vscf_recipient_cipher_message_info_footer_len(c_ctx_);
        return proxy_result;
    }

    /// Return serialized message info footer to the buffer.
    ///
    /// Precondition: this method should be called after "finish encryption".
    ///
    /// Note, store message info to use it for verified decryption process,
    /// or place it at the encrypted data ending (embedding).
    ///
    /// Return message info footer - signers public information, etc.
    tl::expected<std::vector<uint8_t>, Error> pack_message_info_footer() {
        std::vector<uint8_t> out(this->message_info_footer_len());
        vsc_buffer_t* out_buf = vsc_buffer_new();
        vsc_buffer_use(out_buf, out.data(), out.size());
        const vscf_status_t status = vscf_recipient_cipher_pack_message_info_footer(c_ctx_, out_buf);
        out.resize(vsc_buffer_len(out_buf));
        vsc_buffer_delete(out_buf);
        if (status != vscf_status_SUCCESS) {
            return tl::unexpected(static_cast<Error>(status));
        }
        return out;
    }

private:
    vscf_recipient_cipher_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
