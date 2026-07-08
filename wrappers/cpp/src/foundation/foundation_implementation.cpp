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

#include <virgil/crypto/foundation/foundation_implementation.hpp>

#include <virgil/crypto/foundation/aes128_kw.hpp>
#include <virgil/crypto/foundation/aes256_cbc.hpp>
#include <virgil/crypto/foundation/aes256_gcm.hpp>
#include <virgil/crypto/foundation/aes256_kw.hpp>
#include <virgil/crypto/foundation/alg_info_der_deserializer.hpp>
#include <virgil/crypto/foundation/alg_info_der_serializer.hpp>
#include <virgil/crypto/foundation/asn1rd.hpp>
#include <virgil/crypto/foundation/asn1wr.hpp>
#include <virgil/crypto/foundation/chunk_cipher.hpp>
#include <virgil/crypto/foundation/chunked_alg_info.hpp>
#include <virgil/crypto/foundation/cipher_alg_info.hpp>
#include <virgil/crypto/foundation/compound_key_alg.hpp>
#include <virgil/crypto/foundation/compound_key_alg_info.hpp>
#include <virgil/crypto/foundation/compound_private_key.hpp>
#include <virgil/crypto/foundation/compound_public_key.hpp>
#include <virgil/crypto/foundation/ctr_drbg.hpp>
#include <virgil/crypto/foundation/curve25519.hpp>
#include <virgil/crypto/foundation/ecc.hpp>
#include <virgil/crypto/foundation/ecc_alg_info.hpp>
#include <virgil/crypto/foundation/ecc_private_key.hpp>
#include <virgil/crypto/foundation/ecc_public_key.hpp>
#include <virgil/crypto/foundation/ed25519.hpp>
#include <virgil/crypto/foundation/entropy_accumulator.hpp>
#include <virgil/crypto/foundation/fake_random.hpp>
#include <virgil/crypto/foundation/falcon.hpp>
#include <virgil/crypto/foundation/hash_based_alg_info.hpp>
#include <virgil/crypto/foundation/hkdf.hpp>
#include <virgil/crypto/foundation/hmac.hpp>
#include <virgil/crypto/foundation/hybrid_key_alg.hpp>
#include <virgil/crypto/foundation/hybrid_key_alg_info.hpp>
#include <virgil/crypto/foundation/hybrid_private_key.hpp>
#include <virgil/crypto/foundation/hybrid_public_key.hpp>
#include <virgil/crypto/foundation/kdf1.hpp>
#include <virgil/crypto/foundation/kdf2.hpp>
#include <virgil/crypto/foundation/key_asn1_deserializer.hpp>
#include <virgil/crypto/foundation/key_asn1_serializer.hpp>
#include <virgil/crypto/foundation/key_material_rng.hpp>
#include <virgil/crypto/foundation/message_info_der_serializer.hpp>
#include <virgil/crypto/foundation/ml_dsa.hpp>
#include <virgil/crypto/foundation/ml_kem.hpp>
#include <virgil/crypto/foundation/pbe_alg_info.hpp>
#include <virgil/crypto/foundation/pkcs5_pbes2.hpp>
#include <virgil/crypto/foundation/pkcs5_pbkdf2.hpp>
#include <virgil/crypto/foundation/pkcs8_serializer.hpp>
#include <virgil/crypto/foundation/random_padding.hpp>
#include <virgil/crypto/foundation/raw_private_key.hpp>
#include <virgil/crypto/foundation/raw_public_key.hpp>
#include <virgil/crypto/foundation/rsa.hpp>
#include <virgil/crypto/foundation/rsa_private_key.hpp>
#include <virgil/crypto/foundation/rsa_public_key.hpp>
#include <virgil/crypto/foundation/salted_kdf_alg_info.hpp>
#include <virgil/crypto/foundation/sec1_serializer.hpp>
#include <virgil/crypto/foundation/seed_entropy_source.hpp>
#include <virgil/crypto/foundation/sha224.hpp>
#include <virgil/crypto/foundation/sha256.hpp>
#include <virgil/crypto/foundation/sha384.hpp>
#include <virgil/crypto/foundation/sha512.hpp>
#include <virgil/crypto/foundation/simple_alg_info.hpp>
#include <virgil/crypto/foundation/vscf_impl.h>

namespace virgil::crypto::foundation {

std::unique_ptr<Alg> FoundationImplementation::wrap_alg(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_SHA224:
        return std::make_unique<Sha224>(reinterpret_cast<vscf_sha224_t*>(impl));
    case vscf_impl_tag_SHA256:
        return std::make_unique<Sha256>(reinterpret_cast<vscf_sha256_t*>(impl));
    case vscf_impl_tag_SHA384:
        return std::make_unique<Sha384>(reinterpret_cast<vscf_sha384_t*>(impl));
    case vscf_impl_tag_SHA512:
        return std::make_unique<Sha512>(reinterpret_cast<vscf_sha512_t*>(impl));
    case vscf_impl_tag_AES256_GCM:
        return std::make_unique<Aes256Gcm>(reinterpret_cast<vscf_aes256_gcm_t*>(impl));
    case vscf_impl_tag_AES256_CBC:
        return std::make_unique<Aes256Cbc>(reinterpret_cast<vscf_aes256_cbc_t*>(impl));
    case vscf_impl_tag_AES128_KW:
        return std::make_unique<Aes128Kw>(reinterpret_cast<vscf_aes128_kw_t*>(impl));
    case vscf_impl_tag_AES256_KW:
        return std::make_unique<Aes256Kw>(reinterpret_cast<vscf_aes256_kw_t*>(impl));
    case vscf_impl_tag_HMAC:
        return std::make_unique<Hmac>(reinterpret_cast<vscf_hmac_t*>(impl));
    case vscf_impl_tag_HKDF:
        return std::make_unique<Hkdf>(reinterpret_cast<vscf_hkdf_t*>(impl));
    case vscf_impl_tag_KDF1:
        return std::make_unique<Kdf1>(reinterpret_cast<vscf_kdf1_t*>(impl));
    case vscf_impl_tag_KDF2:
        return std::make_unique<Kdf2>(reinterpret_cast<vscf_kdf2_t*>(impl));
    case vscf_impl_tag_PKCS5_PBKDF2:
        return std::make_unique<Pkcs5Pbkdf2>(reinterpret_cast<vscf_pkcs5_pbkdf2_t*>(impl));
    case vscf_impl_tag_PKCS5_PBES2:
        return std::make_unique<Pkcs5Pbes2>(reinterpret_cast<vscf_pkcs5_pbes2_t*>(impl));
    case vscf_impl_tag_FALCON:
        return std::make_unique<Falcon>(reinterpret_cast<vscf_falcon_t*>(impl));
    case vscf_impl_tag_ML_KEM:
        return std::make_unique<MlKem>(reinterpret_cast<vscf_ml_kem_t*>(impl));
    case vscf_impl_tag_ML_DSA:
        return std::make_unique<MlDsa>(reinterpret_cast<vscf_ml_dsa_t*>(impl));
    case vscf_impl_tag_COMPOUND_KEY_ALG:
        return std::make_unique<CompoundKeyAlg>(reinterpret_cast<vscf_compound_key_alg_t*>(impl));
    case vscf_impl_tag_RANDOM_PADDING:
        return std::make_unique<RandomPadding>(reinterpret_cast<vscf_random_padding_t*>(impl));
    case vscf_impl_tag_CHUNK_CIPHER:
        return std::make_unique<ChunkCipher>(reinterpret_cast<vscf_chunk_cipher_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Hash> FoundationImplementation::wrap_hash(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_SHA224:
        return std::make_unique<Sha224>(reinterpret_cast<vscf_sha224_t*>(impl));
    case vscf_impl_tag_SHA256:
        return std::make_unique<Sha256>(reinterpret_cast<vscf_sha256_t*>(impl));
    case vscf_impl_tag_SHA384:
        return std::make_unique<Sha384>(reinterpret_cast<vscf_sha384_t*>(impl));
    case vscf_impl_tag_SHA512:
        return std::make_unique<Sha512>(reinterpret_cast<vscf_sha512_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Encrypt> FoundationImplementation::wrap_encrypt(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_AES256_GCM:
        return std::make_unique<Aes256Gcm>(reinterpret_cast<vscf_aes256_gcm_t*>(impl));
    case vscf_impl_tag_AES256_CBC:
        return std::make_unique<Aes256Cbc>(reinterpret_cast<vscf_aes256_cbc_t*>(impl));
    case vscf_impl_tag_PKCS5_PBES2:
        return std::make_unique<Pkcs5Pbes2>(reinterpret_cast<vscf_pkcs5_pbes2_t*>(impl));
    case vscf_impl_tag_CHUNK_CIPHER:
        return std::make_unique<ChunkCipher>(reinterpret_cast<vscf_chunk_cipher_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Decrypt> FoundationImplementation::wrap_decrypt(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_AES256_GCM:
        return std::make_unique<Aes256Gcm>(reinterpret_cast<vscf_aes256_gcm_t*>(impl));
    case vscf_impl_tag_AES256_CBC:
        return std::make_unique<Aes256Cbc>(reinterpret_cast<vscf_aes256_cbc_t*>(impl));
    case vscf_impl_tag_PKCS5_PBES2:
        return std::make_unique<Pkcs5Pbes2>(reinterpret_cast<vscf_pkcs5_pbes2_t*>(impl));
    case vscf_impl_tag_CHUNK_CIPHER:
        return std::make_unique<ChunkCipher>(reinterpret_cast<vscf_chunk_cipher_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<CipherInfo> FoundationImplementation::wrap_cipher_info(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_AES256_GCM:
        return std::make_unique<Aes256Gcm>(reinterpret_cast<vscf_aes256_gcm_t*>(impl));
    case vscf_impl_tag_AES256_CBC:
        return std::make_unique<Aes256Cbc>(reinterpret_cast<vscf_aes256_cbc_t*>(impl));
    case vscf_impl_tag_CHUNK_CIPHER:
        return std::make_unique<ChunkCipher>(reinterpret_cast<vscf_chunk_cipher_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Cipher> FoundationImplementation::wrap_cipher(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_AES256_GCM:
        return std::make_unique<Aes256Gcm>(reinterpret_cast<vscf_aes256_gcm_t*>(impl));
    case vscf_impl_tag_AES256_CBC:
        return std::make_unique<Aes256Cbc>(reinterpret_cast<vscf_aes256_cbc_t*>(impl));
    case vscf_impl_tag_CHUNK_CIPHER:
        return std::make_unique<ChunkCipher>(reinterpret_cast<vscf_chunk_cipher_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<CipherAuthInfo> FoundationImplementation::wrap_cipher_auth_info(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_AES256_GCM:
        return std::make_unique<Aes256Gcm>(reinterpret_cast<vscf_aes256_gcm_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<AuthEncrypt> FoundationImplementation::wrap_auth_encrypt(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_AES256_GCM:
        return std::make_unique<Aes256Gcm>(reinterpret_cast<vscf_aes256_gcm_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<AuthDecrypt> FoundationImplementation::wrap_auth_decrypt(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_AES256_GCM:
        return std::make_unique<Aes256Gcm>(reinterpret_cast<vscf_aes256_gcm_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<CipherAuth> FoundationImplementation::wrap_cipher_auth(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_AES256_GCM:
        return std::make_unique<Aes256Gcm>(reinterpret_cast<vscf_aes256_gcm_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<KeyWrap> FoundationImplementation::wrap_key_wrap(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_AES128_KW:
        return std::make_unique<Aes128Kw>(reinterpret_cast<vscf_aes128_kw_t*>(impl));
    case vscf_impl_tag_AES256_KW:
        return std::make_unique<Aes256Kw>(reinterpret_cast<vscf_aes256_kw_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Asn1Reader> FoundationImplementation::wrap_asn1_reader(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_ASN1RD:
        return std::make_unique<Asn1rd>(reinterpret_cast<vscf_asn1rd_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Asn1Writer> FoundationImplementation::wrap_asn1_writer(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_ASN1WR:
        return std::make_unique<Asn1wr>(reinterpret_cast<vscf_asn1wr_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Key> FoundationImplementation::wrap_key(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        return std::make_unique<RsaPublicKey>(reinterpret_cast<vscf_rsa_public_key_t*>(impl));
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        return std::make_unique<RsaPrivateKey>(reinterpret_cast<vscf_rsa_private_key_t*>(impl));
    case vscf_impl_tag_ECC_PUBLIC_KEY:
        return std::make_unique<EccPublicKey>(reinterpret_cast<vscf_ecc_public_key_t*>(impl));
    case vscf_impl_tag_ECC_PRIVATE_KEY:
        return std::make_unique<EccPrivateKey>(reinterpret_cast<vscf_ecc_private_key_t*>(impl));
    case vscf_impl_tag_RAW_PUBLIC_KEY:
        return std::make_unique<RawPublicKey>(reinterpret_cast<vscf_raw_public_key_t*>(impl));
    case vscf_impl_tag_RAW_PRIVATE_KEY:
        return std::make_unique<RawPrivateKey>(reinterpret_cast<vscf_raw_private_key_t*>(impl));
    case vscf_impl_tag_COMPOUND_PUBLIC_KEY:
        return std::make_unique<CompoundPublicKey>(reinterpret_cast<vscf_compound_public_key_t*>(impl));
    case vscf_impl_tag_COMPOUND_PRIVATE_KEY:
        return std::make_unique<CompoundPrivateKey>(reinterpret_cast<vscf_compound_private_key_t*>(impl));
    case vscf_impl_tag_HYBRID_PUBLIC_KEY:
        return std::make_unique<HybridPublicKey>(reinterpret_cast<vscf_hybrid_public_key_t*>(impl));
    case vscf_impl_tag_HYBRID_PRIVATE_KEY:
        return std::make_unique<HybridPrivateKey>(reinterpret_cast<vscf_hybrid_private_key_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<PublicKey> FoundationImplementation::wrap_public_key(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_RSA_PUBLIC_KEY:
        return std::make_unique<RsaPublicKey>(reinterpret_cast<vscf_rsa_public_key_t*>(impl));
    case vscf_impl_tag_ECC_PUBLIC_KEY:
        return std::make_unique<EccPublicKey>(reinterpret_cast<vscf_ecc_public_key_t*>(impl));
    case vscf_impl_tag_RAW_PUBLIC_KEY:
        return std::make_unique<RawPublicKey>(reinterpret_cast<vscf_raw_public_key_t*>(impl));
    case vscf_impl_tag_COMPOUND_PUBLIC_KEY:
        return std::make_unique<CompoundPublicKey>(reinterpret_cast<vscf_compound_public_key_t*>(impl));
    case vscf_impl_tag_HYBRID_PUBLIC_KEY:
        return std::make_unique<HybridPublicKey>(reinterpret_cast<vscf_hybrid_public_key_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<PrivateKey> FoundationImplementation::wrap_private_key(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_RSA_PRIVATE_KEY:
        return std::make_unique<RsaPrivateKey>(reinterpret_cast<vscf_rsa_private_key_t*>(impl));
    case vscf_impl_tag_ECC_PRIVATE_KEY:
        return std::make_unique<EccPrivateKey>(reinterpret_cast<vscf_ecc_private_key_t*>(impl));
    case vscf_impl_tag_RAW_PRIVATE_KEY:
        return std::make_unique<RawPrivateKey>(reinterpret_cast<vscf_raw_private_key_t*>(impl));
    case vscf_impl_tag_COMPOUND_PRIVATE_KEY:
        return std::make_unique<CompoundPrivateKey>(reinterpret_cast<vscf_compound_private_key_t*>(impl));
    case vscf_impl_tag_HYBRID_PRIVATE_KEY:
        return std::make_unique<HybridPrivateKey>(reinterpret_cast<vscf_hybrid_private_key_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<KeyAlg> FoundationImplementation::wrap_key_alg(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_RSA:
        return std::make_unique<Rsa>(reinterpret_cast<vscf_rsa_t*>(impl));
    case vscf_impl_tag_ECC:
        return std::make_unique<Ecc>(reinterpret_cast<vscf_ecc_t*>(impl));
    case vscf_impl_tag_ED25519:
        return std::make_unique<Ed25519>(reinterpret_cast<vscf_ed25519_t*>(impl));
    case vscf_impl_tag_CURVE25519:
        return std::make_unique<Curve25519>(reinterpret_cast<vscf_curve25519_t*>(impl));
    case vscf_impl_tag_FALCON:
        return std::make_unique<Falcon>(reinterpret_cast<vscf_falcon_t*>(impl));
    case vscf_impl_tag_ML_KEM:
        return std::make_unique<MlKem>(reinterpret_cast<vscf_ml_kem_t*>(impl));
    case vscf_impl_tag_ML_DSA:
        return std::make_unique<MlDsa>(reinterpret_cast<vscf_ml_dsa_t*>(impl));
    case vscf_impl_tag_COMPOUND_KEY_ALG:
        return std::make_unique<CompoundKeyAlg>(reinterpret_cast<vscf_compound_key_alg_t*>(impl));
    case vscf_impl_tag_HYBRID_KEY_ALG:
        return std::make_unique<HybridKeyAlg>(reinterpret_cast<vscf_hybrid_key_alg_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<KeyCipher> FoundationImplementation::wrap_key_cipher(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_RSA:
        return std::make_unique<Rsa>(reinterpret_cast<vscf_rsa_t*>(impl));
    case vscf_impl_tag_ECC:
        return std::make_unique<Ecc>(reinterpret_cast<vscf_ecc_t*>(impl));
    case vscf_impl_tag_ED25519:
        return std::make_unique<Ed25519>(reinterpret_cast<vscf_ed25519_t*>(impl));
    case vscf_impl_tag_CURVE25519:
        return std::make_unique<Curve25519>(reinterpret_cast<vscf_curve25519_t*>(impl));
    case vscf_impl_tag_COMPOUND_KEY_ALG:
        return std::make_unique<CompoundKeyAlg>(reinterpret_cast<vscf_compound_key_alg_t*>(impl));
    case vscf_impl_tag_HYBRID_KEY_ALG:
        return std::make_unique<HybridKeyAlg>(reinterpret_cast<vscf_hybrid_key_alg_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<KeySigner> FoundationImplementation::wrap_key_signer(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_RSA:
        return std::make_unique<Rsa>(reinterpret_cast<vscf_rsa_t*>(impl));
    case vscf_impl_tag_ECC:
        return std::make_unique<Ecc>(reinterpret_cast<vscf_ecc_t*>(impl));
    case vscf_impl_tag_ED25519:
        return std::make_unique<Ed25519>(reinterpret_cast<vscf_ed25519_t*>(impl));
    case vscf_impl_tag_FALCON:
        return std::make_unique<Falcon>(reinterpret_cast<vscf_falcon_t*>(impl));
    case vscf_impl_tag_ML_DSA:
        return std::make_unique<MlDsa>(reinterpret_cast<vscf_ml_dsa_t*>(impl));
    case vscf_impl_tag_COMPOUND_KEY_ALG:
        return std::make_unique<CompoundKeyAlg>(reinterpret_cast<vscf_compound_key_alg_t*>(impl));
    case vscf_impl_tag_HYBRID_KEY_ALG:
        return std::make_unique<HybridKeyAlg>(reinterpret_cast<vscf_hybrid_key_alg_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<ComputeSharedKey> FoundationImplementation::wrap_compute_shared_key(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_ECC:
        return std::make_unique<Ecc>(reinterpret_cast<vscf_ecc_t*>(impl));
    case vscf_impl_tag_ED25519:
        return std::make_unique<Ed25519>(reinterpret_cast<vscf_ed25519_t*>(impl));
    case vscf_impl_tag_CURVE25519:
        return std::make_unique<Curve25519>(reinterpret_cast<vscf_curve25519_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Kem> FoundationImplementation::wrap_kem(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_ECC:
        return std::make_unique<Ecc>(reinterpret_cast<vscf_ecc_t*>(impl));
    case vscf_impl_tag_ED25519:
        return std::make_unique<Ed25519>(reinterpret_cast<vscf_ed25519_t*>(impl));
    case vscf_impl_tag_CURVE25519:
        return std::make_unique<Curve25519>(reinterpret_cast<vscf_curve25519_t*>(impl));
    case vscf_impl_tag_ML_KEM:
        return std::make_unique<MlKem>(reinterpret_cast<vscf_ml_kem_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<EntropySource> FoundationImplementation::wrap_entropy_source(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_ENTROPY_ACCUMULATOR:
        return std::make_unique<EntropyAccumulator>(reinterpret_cast<vscf_entropy_accumulator_t*>(impl));
    case vscf_impl_tag_FAKE_RANDOM:
        return std::make_unique<FakeRandom>(reinterpret_cast<vscf_fake_random_t*>(impl));
    case vscf_impl_tag_SEED_ENTROPY_SOURCE:
        return std::make_unique<SeedEntropySource>(reinterpret_cast<vscf_seed_entropy_source_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Random> FoundationImplementation::wrap_random(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_CTR_DRBG:
        return std::make_unique<CtrDrbg>(reinterpret_cast<vscf_ctr_drbg_t*>(impl));
    case vscf_impl_tag_FAKE_RANDOM:
        return std::make_unique<FakeRandom>(reinterpret_cast<vscf_fake_random_t*>(impl));
    case vscf_impl_tag_KEY_MATERIAL_RNG:
        return std::make_unique<KeyMaterialRng>(reinterpret_cast<vscf_key_material_rng_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Mac> FoundationImplementation::wrap_mac(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_HMAC:
        return std::make_unique<Hmac>(reinterpret_cast<vscf_hmac_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Kdf> FoundationImplementation::wrap_kdf(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_HKDF:
        return std::make_unique<Hkdf>(reinterpret_cast<vscf_hkdf_t*>(impl));
    case vscf_impl_tag_KDF1:
        return std::make_unique<Kdf1>(reinterpret_cast<vscf_kdf1_t*>(impl));
    case vscf_impl_tag_KDF2:
        return std::make_unique<Kdf2>(reinterpret_cast<vscf_kdf2_t*>(impl));
    case vscf_impl_tag_PKCS5_PBKDF2:
        return std::make_unique<Pkcs5Pbkdf2>(reinterpret_cast<vscf_pkcs5_pbkdf2_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<SaltedKdf> FoundationImplementation::wrap_salted_kdf(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_HKDF:
        return std::make_unique<Hkdf>(reinterpret_cast<vscf_hkdf_t*>(impl));
    case vscf_impl_tag_PKCS5_PBKDF2:
        return std::make_unique<Pkcs5Pbkdf2>(reinterpret_cast<vscf_pkcs5_pbkdf2_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<KeySerializer> FoundationImplementation::wrap_key_serializer(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_PKCS8_SERIALIZER:
        return std::make_unique<Pkcs8Serializer>(reinterpret_cast<vscf_pkcs8_serializer_t*>(impl));
    case vscf_impl_tag_SEC1_SERIALIZER:
        return std::make_unique<Sec1Serializer>(reinterpret_cast<vscf_sec1_serializer_t*>(impl));
    case vscf_impl_tag_KEY_ASN1_SERIALIZER:
        return std::make_unique<KeyAsn1Serializer>(reinterpret_cast<vscf_key_asn1_serializer_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<KeyDeserializer> FoundationImplementation::wrap_key_deserializer(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_KEY_ASN1_DESERIALIZER:
        return std::make_unique<KeyAsn1Deserializer>(reinterpret_cast<vscf_key_asn1_deserializer_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<AlgInfo> FoundationImplementation::wrap_alg_info(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_COMPOUND_KEY_ALG_INFO:
        return std::make_unique<CompoundKeyAlgInfo>(reinterpret_cast<vscf_compound_key_alg_info_t*>(impl));
    case vscf_impl_tag_HYBRID_KEY_ALG_INFO:
        return std::make_unique<HybridKeyAlgInfo>(reinterpret_cast<vscf_hybrid_key_alg_info_t*>(impl));
    case vscf_impl_tag_SIMPLE_ALG_INFO:
        return std::make_unique<SimpleAlgInfo>(reinterpret_cast<vscf_simple_alg_info_t*>(impl));
    case vscf_impl_tag_HASH_BASED_ALG_INFO:
        return std::make_unique<HashBasedAlgInfo>(reinterpret_cast<vscf_hash_based_alg_info_t*>(impl));
    case vscf_impl_tag_CIPHER_ALG_INFO:
        return std::make_unique<CipherAlgInfo>(reinterpret_cast<vscf_cipher_alg_info_t*>(impl));
    case vscf_impl_tag_SALTED_KDF_ALG_INFO:
        return std::make_unique<SaltedKdfAlgInfo>(reinterpret_cast<vscf_salted_kdf_alg_info_t*>(impl));
    case vscf_impl_tag_CHUNKED_ALG_INFO:
        return std::make_unique<ChunkedAlgInfo>(reinterpret_cast<vscf_chunked_alg_info_t*>(impl));
    case vscf_impl_tag_PBE_ALG_INFO:
        return std::make_unique<PbeAlgInfo>(reinterpret_cast<vscf_pbe_alg_info_t*>(impl));
    case vscf_impl_tag_ECC_ALG_INFO:
        return std::make_unique<EccAlgInfo>(reinterpret_cast<vscf_ecc_alg_info_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<AlgInfoSerializer> FoundationImplementation::wrap_alg_info_serializer(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
        return std::make_unique<AlgInfoDerSerializer>(reinterpret_cast<vscf_alg_info_der_serializer_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<AlgInfoDeserializer> FoundationImplementation::wrap_alg_info_deserializer(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
        return std::make_unique<AlgInfoDerDeserializer>(reinterpret_cast<vscf_alg_info_der_deserializer_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<MessageInfoSerializer> FoundationImplementation::wrap_message_info_serializer(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return std::make_unique<MessageInfoDerSerializer>(reinterpret_cast<vscf_message_info_der_serializer_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<MessageInfoFooterSerializer> FoundationImplementation::wrap_message_info_footer_serializer(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return std::make_unique<MessageInfoDerSerializer>(reinterpret_cast<vscf_message_info_der_serializer_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

std::unique_ptr<Padding> FoundationImplementation::wrap_padding(vscf_impl_t* impl) {
    switch (vscf_impl_tag(impl)) {
    case vscf_impl_tag_RANDOM_PADDING:
        return std::make_unique<RandomPadding>(reinterpret_cast<vscf_random_padding_t*>(impl));
    default:
        vscf_impl_delete(impl);
        return nullptr;
    }
}

}  // namespace virgil::crypto::foundation
