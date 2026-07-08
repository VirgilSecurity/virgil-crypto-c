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
#include <virgil/crypto/foundation/error.hpp>

struct vscf_recipient_cipher_t;

namespace virgil::crypto::foundation {

class Cipher;
class Hash;
class KeyWrap;
class MessageInfoCustomParams;
class Padding;
class PaddingParams;
class PrivateKey;
class PublicKey;
class Random;
class SignerInfo;
class SignerInfoList;

/// This class provides hybrid encryption algorithm that combines symmetric
/// cipher for data encryption and asymmetric cipher and password based
/// cipher for symmetric key encryption.
class RecipientCipher {
public:
    RecipientCipher();
    /// Adopt ownership of an existing C handle.
    explicit RecipientCipher(vscf_recipient_cipher_t* c_ctx) noexcept;
    RecipientCipher(const RecipientCipher& other);
    RecipientCipher(RecipientCipher&& other) noexcept;
    RecipientCipher& operator=(const RecipientCipher& other);
    RecipientCipher& operator=(RecipientCipher&& other) noexcept;
    ~RecipientCipher();

    /// The underlying concrete C handle (non-owning).
    vscf_recipient_cipher_t* c_ctx() const noexcept;

    void set_random(const Random& random);

    void set_encryption_cipher(const Cipher& encryption_cipher);

    void set_encryption_padding(const Padding& encryption_padding);

    void set_padding_params(const PaddingParams& padding_params);

    void set_signer_hash(const Hash& signer_hash);

    /// Return true if a key recipient with a given id has been added.
    /// Note, operation has O(N) time complexity.
    bool has_key_recipient(std::span<const uint8_t> recipient_id) const;

    /// Add recipient defined with id and public key.
    void add_key_recipient(std::span<const uint8_t> recipient_id, const PublicKey& public_key);

    /// Add recipient defined with a KEK identifier and key wrap algorithm.
    void add_kek_recipient(std::span<const uint8_t> kek_id, std::span<const uint8_t> kek, const KeyWrap& key_wrap);

    /// Remove all recipients.
    void clear_recipients();

    /// Add identifier and private key to sign initial plain text.
    /// Return error if the private key can not sign.
    tl::expected<void, Error> add_signer(std::span<const uint8_t> signer_id, const PrivateKey& private_key);

    /// Remove all signers.
    void clear_signers();

    /// Provide access to the custom params object.
    /// The returned object can be used to add custom params or read it.
    MessageInfoCustomParams custom_params();

    /// Start encryption process.
    tl::expected<void, Error> start_encryption();

    /// Start encryption process with known plain text size.
    ///
    /// Precondition: At least one signer should be added.
    /// Note, store message info footer as well.
    tl::expected<void, Error> start_signed_encryption(std::size_t data_size);

    /// Return buffer length required to hold message info returned by the
    /// "pack message info" method.
    /// Precondition: all recipients and custom parameters should be set.
    std::size_t message_info_len() const;

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
    std::vector<uint8_t> pack_message_info();

    /// Return buffer length required to hold output of the method
    /// "process encryption" and method "finish" during encryption.
    std::size_t encryption_out_len(std::size_t data_len);

    /// Process encryption of a new portion of data.
    tl::expected<std::vector<uint8_t>, Error> process_encryption(std::span<const uint8_t> data);

    /// Accomplish encryption.
    tl::expected<std::vector<uint8_t>, Error> finish_encryption();

    /// Initiate decryption process with a pre-shared symmetric key (KEK).
    /// Message Info can be empty if it was embedded to encrypted data.
    tl::expected<void, Error> start_decryption_with_kek(std::span<const uint8_t> kek_id, std::span<const uint8_t> kek, const KeyWrap& key_wrap, std::span<const uint8_t> message_info);

    /// Initiate decryption process with a recipient private key.
    /// Message Info can be empty if it was embedded to encrypted data.
    tl::expected<void, Error> start_decryption_with_key(std::span<const uint8_t> recipient_id, const PrivateKey& private_key, std::span<const uint8_t> message_info);

    /// Initiate decryption process with a recipient private key.
    /// Message Info can be empty if it was embedded to encrypted data.
    /// Message Info footer can be empty if it was embedded to encrypted data.
    /// If footer was embedded, method "start decryption with key" can be used.
    tl::expected<void, Error> start_verified_decryption_with_key(std::span<const uint8_t> recipient_id, const PrivateKey& private_key, std::span<const uint8_t> message_info, std::span<const uint8_t> message_info_footer);

    /// Return buffer length required to hold output of the method
    /// "process decryption" and method "finish" during decryption.
    std::size_t decryption_out_len(std::size_t data_len);

    /// Process with a new portion of data.
    /// Return error if data can not be encrypted or decrypted.
    tl::expected<std::vector<uint8_t>, Error> process_decryption(std::span<const uint8_t> data);

    /// Accomplish decryption.
    tl::expected<std::vector<uint8_t>, Error> finish_decryption();

    /// Return true if data was signed by a sender.
    ///
    /// Precondition: this method should be called after "finish decryption".
    bool is_data_signed() const;

    /// Return information about signers that sign data.
    ///
    /// Precondition: this method should be called after "finish decryption".
    /// Precondition: method "is data signed" returns true.
    SignerInfoList signer_infos() const;

    /// Verify given cipher info.
    bool verify_signer_info(const SignerInfo& signer_info, const PublicKey& public_key);

    /// Return buffer length required to hold message footer returned by the
    /// "pack message footer" method.
    ///
    /// Precondition: this method should be called after "finish encryption".
    std::size_t message_info_footer_len() const;

    /// Return serialized message info footer to the buffer.
    ///
    /// Precondition: this method should be called after "finish encryption".
    ///
    /// Note, store message info to use it for verified decryption process,
    /// or place it at the encrypted data ending (embedding).
    ///
    /// Return message info footer - signers public information, etc.
    tl::expected<std::vector<uint8_t>, Error> pack_message_info_footer();

private:
    vscf_recipient_cipher_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
