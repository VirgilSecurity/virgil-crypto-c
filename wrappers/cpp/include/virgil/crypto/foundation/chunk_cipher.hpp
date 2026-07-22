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
#include <virgil/crypto/foundation/alg_id.hpp>

struct vscf_chunk_cipher_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class AlgInfo;
class Random;

/// Provides stream encryption in fixed-size chunks, where each encrypted
/// chunk carries its own AES-256-GCM authentication tag.
///
/// Nonce derivation follows the TLS 1.3 construction:
/// nonce_i = initial_nonce XOR (0x00000000 || uint64_be(i))
///
/// Each encrypted frame layout:
/// counter_le64[8] | ciphertext[N] | tag[16]
///
/// The construction is self-describing: it produces and restores a
/// 'chunked alg info' (algorithm id 'aes256 gcm chunked' carrying version,
/// chunk size, and the initial nonce) via the 'alg' interface, so the
/// generic decryptor (recipient cipher / alg factory) can reconstruct and
/// drive it through the 'cipher' interface without out-of-band parameters.
class ChunkCipher : virtual public Alg, virtual public Encrypt, virtual public Decrypt, virtual public CipherInfo, virtual public Cipher {
public:
    ChunkCipher();
    /// Adopt ownership of an existing C handle.
    explicit ChunkCipher(vscf_chunk_cipher_t* c_ctx) noexcept;
    ChunkCipher(const ChunkCipher& other);
    ChunkCipher(ChunkCipher&& other) noexcept;
    ChunkCipher& operator=(const ChunkCipher& other);
    ChunkCipher& operator=(ChunkCipher&& other) noexcept;
    ~ChunkCipher();

    /// The underlying concrete C handle (non-owning).
    vscf_chunk_cipher_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    static constexpr std::size_t NONCE_LEN = 12;

    static constexpr std::size_t KEY_LEN = 32;

    static constexpr std::size_t KEY_BITLEN = 256;

    static constexpr std::size_t BLOCK_LEN = 16;

    void set_random(const Random& random);

    /// Set the plaintext chunk size in bytes. Default is 65536.
    void set_chunk_size(std::size_t chunk_size);

    /// Return the 12-byte initial nonce.
    /// Valid after calling start_encryption. On the generic CMS path the
    /// nonce is carried in the produced 'chunked alg info' (self-describing),
    /// so no out-of-band custom params are needed.
    std::vector<uint8_t> nonce() const;

    /// Return buffer length required to hold output of process_encryption and finish_encryption.
    std::size_t encryption_out_len(std::size_t data_len) const;

    /// Process encryption of a new portion of data.
    tl::expected<std::vector<uint8_t>, Error> process_encryption(std::span<const uint8_t> data);

    /// Encrypt any remaining pending data and finalize the stream.
    tl::expected<std::vector<uint8_t>, Error> finish_encryption();

    /// Return buffer length required to hold output of process_decryption and finish_decryption.
    std::size_t decryption_out_len(std::size_t data_len) const;

    /// Process decryption of a new portion of data.
    tl::expected<std::vector<uint8_t>, Error> process_decryption(std::span<const uint8_t> data);

    /// Decrypt any remaining pending data and finalize the stream.
    tl::expected<std::vector<uint8_t>, Error> finish_decryption();

    /// Return the number of frames the sequential encryption path emits for a plaintext of the
    /// given length: floor(data_len / chunk_size) + 1. The trailing frame (the one with is_last=true)
    /// is empty when data_len is an exact multiple of chunk_size. Use this to drive random-access /
    /// parallel encryption via encrypt_at over indices 0 .. chunk_count-1, placing is_last on the
    /// highest index. Requires chunk_size to be set (> 0).
    std::size_t chunk_count(std::size_t data_len) const;

    /// Encrypt a single chunk at an explicit index for random-access / parallel encryption, writing
    /// the frame counter_le64[8] | ciphertext | tag[16]. Independent of the start/process/finish
    /// state machine; requires key, initial nonce, and chunk_size to be set, and the instance to be
    /// in the INITIAL state (call before, or instead of, start_encryption).
    ///
    /// WARNING (nonce safety): each chunk_index must be encrypted at most ONCE per (key, initial_nonce);
    /// AES-GCM nonce reuse is catastrophic. This API is per-call and does NOT track or enforce
    /// uniqueness — the caller owns it. Thread-safe: each call uses a per-call local cipher context and
    /// only reads the instance's key/nonce/chunk_size, so a single configured instance may be used
    /// concurrently from multiple threads for parallel encryption (no shared mutable cipher state, no
    /// lock). Whole-file only: the caller must know the total chunk count (see chunk_count) to place
    /// exactly one is_last frame.
    tl::expected<std::vector<uint8_t>, Error> encrypt_at(uint64_t chunk_index, bool is_last, std::span<const uint8_t> plaintext);

    /// Authenticate and decrypt a single frame as an explicit chunk index for random-access reads.
    /// The frame's embedded counter is validated against the passed-in chunk_index (a mismatch returns
    /// ERROR_BAD_ENCRYPTED_DATA), so callers must pass the true positional index and never trust the
    /// frame's own counter. Independent of the streaming state machine; requires key, initial nonce,
    /// and chunk_size to be set, and the instance to be in the INITIAL state.
    ///
    /// Thread-safe: uses a per-call local cipher context and only reads the instance's
    /// key/nonce/chunk_size, so a single configured instance may be used concurrently from multiple
    /// threads for parallel/random-access decryption (no shared mutable cipher state, no lock). Note:
    /// this authenticates which frame is last (is_last) and each frame's position, but not the total
    /// number of frames — protect against truncation by authenticating the chunk count out of band
    /// (or deriving it from the ciphertext length).
    tl::expected<std::vector<uint8_t>, Error> decrypt_at(uint64_t chunk_index, bool is_last, std::span<const uint8_t> frame);

    /// Set associated data bound into the stream authentication.
    /// The generic encryptor/decryptor (recipient cipher) sets this to the
    /// serialized CMS 'data encryption alg info' so metadata tampering
    /// (OID swap, chunk_size/initial_nonce change) fails closed. Must be
    /// set before start_encryption/start_decryption (and before
    /// encrypt_at/decrypt_at). Empty auth_data preserves the shipped raw
    /// frame format.
    void set_auth_data(std::span<const uint8_t> auth_data);

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

private:
    vscf_chunk_cipher_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
