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
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/alg_id.hpp>

struct vscf_compound_private_key_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class AlgInfo;
class PrivateKey;
class PublicKey;

/// Handles compound private key.
///
/// Compound private key contains 2 private keys and signature:
/// - cipher key - is used for decryption;
/// - signer key - is used for signing.
class CompoundPrivateKey : virtual public Key, virtual public PrivateKey {
public:
    CompoundPrivateKey();
    /// Adopt ownership of an existing C handle.
    explicit CompoundPrivateKey(vscf_compound_private_key_t* c_ctx) noexcept;
    CompoundPrivateKey(const CompoundPrivateKey& other);
    CompoundPrivateKey(CompoundPrivateKey&& other) noexcept;
    CompoundPrivateKey& operator=(const CompoundPrivateKey& other);
    CompoundPrivateKey& operator=(CompoundPrivateKey&& other) noexcept;
    ~CompoundPrivateKey();

    /// The underlying concrete C handle (non-owning).
    vscf_compound_private_key_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    /// Return primary private key suitable for a final decryption.
    std::unique_ptr<PrivateKey> cipher_key() const;

    /// Return private key suitable for signing.
    std::unique_ptr<PrivateKey> signer_key() const;

    /// Algorithm identifier the key belongs to.
    AlgId alg_id() const override;

    /// Return algorithm information that can be used for serialization.
    std::unique_ptr<AlgInfo> alg_info() const override;

    /// Length of the key in bytes.
    std::size_t len() const override;

    /// Length of the key in bits.
    std::size_t bitlen() const override;

    /// Check that key is valid.
    /// Note, this operation can be slow.
    bool is_valid() const override;

    /// Extract public key from the private key.
    std::unique_ptr<PublicKey> extract_public_key() const override;

private:
    vscf_compound_private_key_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
