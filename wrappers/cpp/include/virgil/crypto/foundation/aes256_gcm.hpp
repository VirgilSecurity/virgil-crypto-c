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
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/encrypt.hpp>
#include <virgil/crypto/foundation/decrypt.hpp>
#include <virgil/crypto/foundation/cipher_info.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/cipher_auth_info.hpp>
#include <virgil/crypto/foundation/auth_encrypt.hpp>
#include <virgil/crypto/foundation/auth_decrypt.hpp>
#include <virgil/crypto/foundation/cipher_auth.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>

struct vscf_aes256_gcm_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class AlgInfo;

/// Implementation of the symmetric cipher AES-256 bit in a GCM mode.
/// Note, this implementation contains dynamic memory allocations,
/// this should be improved in the future releases.
class Aes256Gcm : virtual public Alg, virtual public Encrypt, virtual public Decrypt, virtual public CipherInfo, virtual public Cipher, virtual public CipherAuthInfo, virtual public AuthEncrypt, virtual public AuthDecrypt, virtual public CipherAuth {
public:
    Aes256Gcm();
    /// Adopt ownership of an existing C handle.
    explicit Aes256Gcm(vscf_aes256_gcm_t* c_ctx) noexcept;
    Aes256Gcm(const Aes256Gcm& other);
    Aes256Gcm(Aes256Gcm&& other) noexcept;
    Aes256Gcm& operator=(const Aes256Gcm& other);
    Aes256Gcm& operator=(Aes256Gcm&& other) noexcept;
    ~Aes256Gcm();

    /// The underlying concrete C handle (non-owning).
    vscf_aes256_gcm_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    static constexpr std::size_t NONCE_LEN = 12;

    static constexpr std::size_t KEY_LEN = 32;

    static constexpr std::size_t KEY_BITLEN = 256;

    static constexpr std::size_t BLOCK_LEN = 16;

    static constexpr std::size_t AUTH_TAG_LEN = 16;

    /// Provide algorithm identificator.
    AlgId alg_id() const override;

    /// Produce object with algorithm information and configuration parameters.
    std::unique_ptr<AlgInfo> produce_alg_info() const override;

    /// Restore algorithm configuration from the given object.
    tl::expected<void, Error> restore_alg_info(const AlgInfo& alg_info) override;

    /// Encrypt given data.
    tl::expected<std::vector<uint8_t>, Error> encrypt(std::span<const uint8_t> data) override;

    /// Calculate required buffer length to hold the encrypted data.
    std::size_t encrypted_len(std::size_t data_len) const override;

    /// Precise length calculation of encrypted data.
    std::size_t precise_encrypted_len(std::size_t data_len) const override;

    /// Decrypt given data.
    tl::expected<std::vector<uint8_t>, Error> decrypt(std::span<const uint8_t> data) override;

    /// Calculate required buffer length to hold the decrypted data.
    std::size_t decrypted_len(std::size_t data_len) const override;

    /// Setup IV or nonce.
    void set_nonce(std::span<const uint8_t> nonce) override;

    /// Set cipher encryption / decryption key.
    void set_key(std::span<const uint8_t> key) override;

    /// Start sequential encryption.
    void start_encryption() override;

    /// Start sequential decryption.
    void start_decryption() override;

    /// Process encryption or decryption of the given data chunk.
    std::vector<uint8_t> update(std::span<const uint8_t> data) override;

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an current mode.
    /// Pass zero length to define buffer length of the method "finish".
    std::size_t out_len(std::size_t data_len) override;

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an encryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    std::size_t encrypted_out_len(std::size_t data_len) const override;

    /// Return buffer length required to hold an output of the methods
    /// "update" or "finish" in an decryption mode.
    /// Pass zero length to define buffer length of the method "finish".
    std::size_t decrypted_out_len(std::size_t data_len) const override;

    /// Accomplish encryption or decryption process.
    tl::expected<std::vector<uint8_t>, Error> finish() override;

    /// Encrypt given data.
    /// If 'tag' is not given, then it will written to the 'enc'.
    tl::expected<AuthEncryptAuthEncryptResult, Error> auth_encrypt(std::span<const uint8_t> data, std::span<const uint8_t> auth_data) override;

    /// Calculate required buffer length to hold the authenticated encrypted data.
    std::size_t auth_encrypted_len(std::size_t data_len) const override;

    /// Decrypt given data.
    /// If 'tag' is not given, then it will be taken from the 'enc'.
    tl::expected<std::vector<uint8_t>, Error> auth_decrypt(std::span<const uint8_t> data, std::span<const uint8_t> auth_data, std::span<const uint8_t> tag) override;

    /// Calculate required buffer length to hold the authenticated decrypted data.
    std::size_t auth_decrypted_len(std::size_t data_len) const override;

    /// Set additional data for for AEAD ciphers.
    void set_auth_data(std::span<const uint8_t> auth_data) override;

    /// Accomplish an authenticated encryption and place tag separately.
    ///
    /// Note, if authentication tag should be added to an encrypted data,
    /// method "finish" can be used.
    tl::expected<CipherAuthFinishAuthEncryptionResult, Error> finish_auth_encryption() override;

    /// Accomplish an authenticated decryption with explicitly given tag.
    ///
    /// Note, if authentication tag is a part of an encrypted data then,
    /// method "finish" can be used for simplicity.
    tl::expected<std::vector<uint8_t>, Error> finish_auth_decryption(std::span<const uint8_t> tag) override;

private:
    vscf_aes256_gcm_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
