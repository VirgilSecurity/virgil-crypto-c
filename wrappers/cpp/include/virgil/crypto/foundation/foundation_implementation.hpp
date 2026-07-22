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

#include <memory>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg.hpp>
#include <virgil/crypto/foundation/hash.hpp>
#include <virgil/crypto/foundation/encrypt.hpp>
#include <virgil/crypto/foundation/decrypt.hpp>
#include <virgil/crypto/foundation/cipher_info.hpp>
#include <virgil/crypto/foundation/cipher.hpp>
#include <virgil/crypto/foundation/cipher_auth_info.hpp>
#include <virgil/crypto/foundation/auth_encrypt.hpp>
#include <virgil/crypto/foundation/auth_decrypt.hpp>
#include <virgil/crypto/foundation/cipher_auth.hpp>
#include <virgil/crypto/foundation/key_wrap.hpp>
#include <virgil/crypto/foundation/asn1_reader.hpp>
#include <virgil/crypto/foundation/asn1_writer.hpp>
#include <virgil/crypto/foundation/key.hpp>
#include <virgil/crypto/foundation/public_key.hpp>
#include <virgil/crypto/foundation/private_key.hpp>
#include <virgil/crypto/foundation/key_alg.hpp>
#include <virgil/crypto/foundation/key_cipher.hpp>
#include <virgil/crypto/foundation/key_signer.hpp>
#include <virgil/crypto/foundation/compute_shared_key.hpp>
#include <virgil/crypto/foundation/kem.hpp>
#include <virgil/crypto/foundation/entropy_source.hpp>
#include <virgil/crypto/foundation/random.hpp>
#include <virgil/crypto/foundation/mac.hpp>
#include <virgil/crypto/foundation/kdf.hpp>
#include <virgil/crypto/foundation/salted_kdf.hpp>
#include <virgil/crypto/foundation/key_serializer.hpp>
#include <virgil/crypto/foundation/key_deserializer.hpp>
#include <virgil/crypto/foundation/alg_info.hpp>
#include <virgil/crypto/foundation/alg_info_serializer.hpp>
#include <virgil/crypto/foundation/alg_info_deserializer.hpp>
#include <virgil/crypto/foundation/message_info_serializer.hpp>
#include <virgil/crypto/foundation/message_info_footer_serializer.hpp>
#include <virgil/crypto/foundation/padding.hpp>

namespace virgil::crypto::foundation {

/// Wraps a C implementation handle into its concrete C++ type by tag.
class FoundationImplementation {
public:
    /// Adopt a returned C alg implementation.
    static std::unique_ptr<Alg> wrap_alg(vscf_impl_t* impl);
    /// Adopt a returned C hash implementation.
    static std::unique_ptr<Hash> wrap_hash(vscf_impl_t* impl);
    /// Adopt a returned C encrypt implementation.
    static std::unique_ptr<Encrypt> wrap_encrypt(vscf_impl_t* impl);
    /// Adopt a returned C decrypt implementation.
    static std::unique_ptr<Decrypt> wrap_decrypt(vscf_impl_t* impl);
    /// Adopt a returned C cipher info implementation.
    static std::unique_ptr<CipherInfo> wrap_cipher_info(vscf_impl_t* impl);
    /// Adopt a returned C cipher implementation.
    static std::unique_ptr<Cipher> wrap_cipher(vscf_impl_t* impl);
    /// Adopt a returned C cipher auth info implementation.
    static std::unique_ptr<CipherAuthInfo> wrap_cipher_auth_info(vscf_impl_t* impl);
    /// Adopt a returned C auth encrypt implementation.
    static std::unique_ptr<AuthEncrypt> wrap_auth_encrypt(vscf_impl_t* impl);
    /// Adopt a returned C auth decrypt implementation.
    static std::unique_ptr<AuthDecrypt> wrap_auth_decrypt(vscf_impl_t* impl);
    /// Adopt a returned C cipher auth implementation.
    static std::unique_ptr<CipherAuth> wrap_cipher_auth(vscf_impl_t* impl);
    /// Adopt a returned C key wrap implementation.
    static std::unique_ptr<KeyWrap> wrap_key_wrap(vscf_impl_t* impl);
    /// Adopt a returned C asn1 reader implementation.
    static std::unique_ptr<Asn1Reader> wrap_asn1_reader(vscf_impl_t* impl);
    /// Adopt a returned C asn1 writer implementation.
    static std::unique_ptr<Asn1Writer> wrap_asn1_writer(vscf_impl_t* impl);
    /// Adopt a returned C key implementation.
    static std::unique_ptr<Key> wrap_key(vscf_impl_t* impl);
    /// Adopt a returned C public key implementation.
    static std::unique_ptr<PublicKey> wrap_public_key(vscf_impl_t* impl);
    /// Adopt a returned C private key implementation.
    static std::unique_ptr<PrivateKey> wrap_private_key(vscf_impl_t* impl);
    /// Adopt a returned C key alg implementation.
    static std::unique_ptr<KeyAlg> wrap_key_alg(vscf_impl_t* impl);
    /// Adopt a returned C key cipher implementation.
    static std::unique_ptr<KeyCipher> wrap_key_cipher(vscf_impl_t* impl);
    /// Adopt a returned C key signer implementation.
    static std::unique_ptr<KeySigner> wrap_key_signer(vscf_impl_t* impl);
    /// Adopt a returned C compute shared key implementation.
    static std::unique_ptr<ComputeSharedKey> wrap_compute_shared_key(vscf_impl_t* impl);
    /// Adopt a returned C kem implementation.
    static std::unique_ptr<Kem> wrap_kem(vscf_impl_t* impl);
    /// Adopt a returned C entropy source implementation.
    static std::unique_ptr<EntropySource> wrap_entropy_source(vscf_impl_t* impl);
    /// Adopt a returned C random implementation.
    static std::unique_ptr<Random> wrap_random(vscf_impl_t* impl);
    /// Adopt a returned C mac implementation.
    static std::unique_ptr<Mac> wrap_mac(vscf_impl_t* impl);
    /// Adopt a returned C kdf implementation.
    static std::unique_ptr<Kdf> wrap_kdf(vscf_impl_t* impl);
    /// Adopt a returned C salted kdf implementation.
    static std::unique_ptr<SaltedKdf> wrap_salted_kdf(vscf_impl_t* impl);
    /// Adopt a returned C key serializer implementation.
    static std::unique_ptr<KeySerializer> wrap_key_serializer(vscf_impl_t* impl);
    /// Adopt a returned C key deserializer implementation.
    static std::unique_ptr<KeyDeserializer> wrap_key_deserializer(vscf_impl_t* impl);
    /// Adopt a returned C alg info implementation.
    static std::unique_ptr<AlgInfo> wrap_alg_info(vscf_impl_t* impl);
    /// Adopt a returned C alg info serializer implementation.
    static std::unique_ptr<AlgInfoSerializer> wrap_alg_info_serializer(vscf_impl_t* impl);
    /// Adopt a returned C alg info deserializer implementation.
    static std::unique_ptr<AlgInfoDeserializer> wrap_alg_info_deserializer(vscf_impl_t* impl);
    /// Adopt a returned C message info serializer implementation.
    static std::unique_ptr<MessageInfoSerializer> wrap_message_info_serializer(vscf_impl_t* impl);
    /// Adopt a returned C message info footer serializer implementation.
    static std::unique_ptr<MessageInfoFooterSerializer> wrap_message_info_footer_serializer(vscf_impl_t* impl);
    /// Adopt a returned C padding implementation.
    static std::unique_ptr<Padding> wrap_padding(vscf_impl_t* impl);
};

}  // namespace virgil::crypto::foundation
