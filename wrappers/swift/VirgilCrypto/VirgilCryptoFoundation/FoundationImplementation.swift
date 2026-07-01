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


import Foundation
import VSCFoundation

@objc(VSCFFoundationImplementation) public class FoundationImplementation: NSObject {

    @objc public static func wrapAlg(take c_ctx: OpaquePointer) -> Alg {
        if (!vscf_alg_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Alg.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_SHA224:
            return Sha224(take: c_ctx)
        case vscf_impl_tag_SHA256:
            return Sha256(take: c_ctx)
        case vscf_impl_tag_SHA384:
            return Sha384(take: c_ctx)
        case vscf_impl_tag_SHA512:
            return Sha512(take: c_ctx)
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        case vscf_impl_tag_AES256_CBC:
            return Aes256Cbc(take: c_ctx)
        case vscf_impl_tag_AES128_KW:
            return Aes128Kw(take: c_ctx)
        case vscf_impl_tag_AES256_KW:
            return Aes256Kw(take: c_ctx)
        case vscf_impl_tag_HMAC:
            return Hmac(take: c_ctx)
        case vscf_impl_tag_HKDF:
            return Hkdf(take: c_ctx)
        case vscf_impl_tag_KDF1:
            return Kdf1(take: c_ctx)
        case vscf_impl_tag_KDF2:
            return Kdf2(take: c_ctx)
        case vscf_impl_tag_PKCS5_PBKDF2:
            return Pkcs5Pbkdf2(take: c_ctx)
        case vscf_impl_tag_PKCS5_PBES2:
            return Pkcs5Pbes2(take: c_ctx)
        case vscf_impl_tag_FALCON:
            return Falcon(take: c_ctx)
        case vscf_impl_tag_ML_KEM:
            return MlKem(take: c_ctx)
        case vscf_impl_tag_ML_DSA:
            return MlDsa(take: c_ctx)
        case vscf_impl_tag_COMPOUND_KEY_ALG:
            return CompoundKeyAlg(take: c_ctx)
        case vscf_impl_tag_RANDOM_PADDING:
            return RandomPadding(take: c_ctx)
        case vscf_impl_tag_CHUNK_CIPHER:
            return ChunkCipher(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapAlg(use c_ctx: OpaquePointer) -> Alg {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapAlg(take:shallowCopy)
    }

    @objc public static func wrapHash(take c_ctx: OpaquePointer) -> Hash {
        if (!vscf_hash_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Hash.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_SHA224:
            return Sha224(take: c_ctx)
        case vscf_impl_tag_SHA256:
            return Sha256(take: c_ctx)
        case vscf_impl_tag_SHA384:
            return Sha384(take: c_ctx)
        case vscf_impl_tag_SHA512:
            return Sha512(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapHash(use c_ctx: OpaquePointer) -> Hash {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapHash(take:shallowCopy)
    }

    @objc public static func wrapEncrypt(take c_ctx: OpaquePointer) -> Encrypt {
        if (!vscf_encrypt_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Encrypt.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        case vscf_impl_tag_AES256_CBC:
            return Aes256Cbc(take: c_ctx)
        case vscf_impl_tag_PKCS5_PBES2:
            return Pkcs5Pbes2(take: c_ctx)
        case vscf_impl_tag_CHUNK_CIPHER:
            return ChunkCipher(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapEncrypt(use c_ctx: OpaquePointer) -> Encrypt {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapEncrypt(take:shallowCopy)
    }

    @objc public static func wrapDecrypt(take c_ctx: OpaquePointer) -> Decrypt {
        if (!vscf_decrypt_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Decrypt.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        case vscf_impl_tag_AES256_CBC:
            return Aes256Cbc(take: c_ctx)
        case vscf_impl_tag_PKCS5_PBES2:
            return Pkcs5Pbes2(take: c_ctx)
        case vscf_impl_tag_CHUNK_CIPHER:
            return ChunkCipher(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapDecrypt(use c_ctx: OpaquePointer) -> Decrypt {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapDecrypt(take:shallowCopy)
    }

    @objc public static func wrapCipherInfo(take c_ctx: OpaquePointer) -> CipherInfo {
        if (!vscf_cipher_info_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface CipherInfo.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        case vscf_impl_tag_AES256_CBC:
            return Aes256Cbc(take: c_ctx)
        case vscf_impl_tag_CHUNK_CIPHER:
            return ChunkCipher(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapCipherInfo(use c_ctx: OpaquePointer) -> CipherInfo {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapCipherInfo(take:shallowCopy)
    }

    @objc public static func wrapCipher(take c_ctx: OpaquePointer) -> Cipher {
        if (!vscf_cipher_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Cipher.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        case vscf_impl_tag_AES256_CBC:
            return Aes256Cbc(take: c_ctx)
        case vscf_impl_tag_CHUNK_CIPHER:
            return ChunkCipher(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapCipher(use c_ctx: OpaquePointer) -> Cipher {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapCipher(take:shallowCopy)
    }

    @objc public static func wrapCipherAuthInfo(take c_ctx: OpaquePointer) -> CipherAuthInfo {
        if (!vscf_cipher_auth_info_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface CipherAuthInfo.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapCipherAuthInfo(use c_ctx: OpaquePointer) -> CipherAuthInfo {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapCipherAuthInfo(take:shallowCopy)
    }

    @objc public static func wrapAuthEncrypt(take c_ctx: OpaquePointer) -> AuthEncrypt {
        if (!vscf_auth_encrypt_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface AuthEncrypt.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapAuthEncrypt(use c_ctx: OpaquePointer) -> AuthEncrypt {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapAuthEncrypt(take:shallowCopy)
    }

    @objc public static func wrapAuthDecrypt(take c_ctx: OpaquePointer) -> AuthDecrypt {
        if (!vscf_auth_decrypt_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface AuthDecrypt.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapAuthDecrypt(use c_ctx: OpaquePointer) -> AuthDecrypt {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapAuthDecrypt(take:shallowCopy)
    }

    @objc public static func wrapCipherAuth(take c_ctx: OpaquePointer) -> CipherAuth {
        if (!vscf_cipher_auth_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface CipherAuth.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapCipherAuth(use c_ctx: OpaquePointer) -> CipherAuth {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapCipherAuth(take:shallowCopy)
    }

    @objc public static func wrapKeyWrap(take c_ctx: OpaquePointer) -> KeyWrap {
        if (!vscf_key_wrap_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface KeyWrap.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES128_KW:
            return Aes128Kw(take: c_ctx)
        case vscf_impl_tag_AES256_KW:
            return Aes256Kw(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapKeyWrap(use c_ctx: OpaquePointer) -> KeyWrap {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapKeyWrap(take:shallowCopy)
    }

    @objc public static func wrapAsn1Reader(take c_ctx: OpaquePointer) -> Asn1Reader {
        if (!vscf_asn1_reader_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Asn1Reader.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_ASN1RD:
            return Asn1rd(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapAsn1Reader(use c_ctx: OpaquePointer) -> Asn1Reader {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapAsn1Reader(take:shallowCopy)
    }

    @objc public static func wrapAsn1Writer(take c_ctx: OpaquePointer) -> Asn1Writer {
        if (!vscf_asn1_writer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Asn1Writer.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_ASN1WR:
            return Asn1wr(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapAsn1Writer(use c_ctx: OpaquePointer) -> Asn1Writer {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapAsn1Writer(take:shallowCopy)
    }

    @objc public static func wrapKey(take c_ctx: OpaquePointer) -> Key {
        if (!vscf_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Key.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PUBLIC_KEY:
            return RsaPublicKey(take: c_ctx)
        case vscf_impl_tag_RSA_PRIVATE_KEY:
            return RsaPrivateKey(take: c_ctx)
        case vscf_impl_tag_ECC_PUBLIC_KEY:
            return EccPublicKey(take: c_ctx)
        case vscf_impl_tag_ECC_PRIVATE_KEY:
            return EccPrivateKey(take: c_ctx)
        case vscf_impl_tag_RAW_PUBLIC_KEY:
            return RawPublicKey(take: c_ctx)
        case vscf_impl_tag_RAW_PRIVATE_KEY:
            return RawPrivateKey(take: c_ctx)
        case vscf_impl_tag_COMPOUND_PUBLIC_KEY:
            return CompoundPublicKey(take: c_ctx)
        case vscf_impl_tag_COMPOUND_PRIVATE_KEY:
            return CompoundPrivateKey(take: c_ctx)
        case vscf_impl_tag_HYBRID_PUBLIC_KEY:
            return HybridPublicKey(take: c_ctx)
        case vscf_impl_tag_HYBRID_PRIVATE_KEY:
            return HybridPrivateKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapKey(use c_ctx: OpaquePointer) -> Key {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapKey(take:shallowCopy)
    }

    @objc public static func wrapPublicKey(take c_ctx: OpaquePointer) -> PublicKey {
        if (!vscf_public_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface PublicKey.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PUBLIC_KEY:
            return RsaPublicKey(take: c_ctx)
        case vscf_impl_tag_ECC_PUBLIC_KEY:
            return EccPublicKey(take: c_ctx)
        case vscf_impl_tag_RAW_PUBLIC_KEY:
            return RawPublicKey(take: c_ctx)
        case vscf_impl_tag_COMPOUND_PUBLIC_KEY:
            return CompoundPublicKey(take: c_ctx)
        case vscf_impl_tag_HYBRID_PUBLIC_KEY:
            return HybridPublicKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapPublicKey(use c_ctx: OpaquePointer) -> PublicKey {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapPublicKey(take:shallowCopy)
    }

    @objc public static func wrapPrivateKey(take c_ctx: OpaquePointer) -> PrivateKey {
        if (!vscf_private_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface PrivateKey.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PRIVATE_KEY:
            return RsaPrivateKey(take: c_ctx)
        case vscf_impl_tag_ECC_PRIVATE_KEY:
            return EccPrivateKey(take: c_ctx)
        case vscf_impl_tag_RAW_PRIVATE_KEY:
            return RawPrivateKey(take: c_ctx)
        case vscf_impl_tag_COMPOUND_PRIVATE_KEY:
            return CompoundPrivateKey(take: c_ctx)
        case vscf_impl_tag_HYBRID_PRIVATE_KEY:
            return HybridPrivateKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapPrivateKey(use c_ctx: OpaquePointer) -> PrivateKey {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapPrivateKey(take:shallowCopy)
    }

    @objc public static func wrapKeyAlg(take c_ctx: OpaquePointer) -> KeyAlg {
        if (!vscf_key_alg_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface KeyAlg.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA:
            return Rsa(take: c_ctx)
        case vscf_impl_tag_ECC:
            return Ecc(take: c_ctx)
        case vscf_impl_tag_ED25519:
            return Ed25519(take: c_ctx)
        case vscf_impl_tag_CURVE25519:
            return Curve25519(take: c_ctx)
        case vscf_impl_tag_FALCON:
            return Falcon(take: c_ctx)
        case vscf_impl_tag_ML_KEM:
            return MlKem(take: c_ctx)
        case vscf_impl_tag_ML_DSA:
            return MlDsa(take: c_ctx)
        case vscf_impl_tag_COMPOUND_KEY_ALG:
            return CompoundKeyAlg(take: c_ctx)
        case vscf_impl_tag_HYBRID_KEY_ALG:
            return HybridKeyAlg(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapKeyAlg(use c_ctx: OpaquePointer) -> KeyAlg {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapKeyAlg(take:shallowCopy)
    }

    @objc public static func wrapKeyCipher(take c_ctx: OpaquePointer) -> KeyCipher {
        if (!vscf_key_cipher_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface KeyCipher.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA:
            return Rsa(take: c_ctx)
        case vscf_impl_tag_ECC:
            return Ecc(take: c_ctx)
        case vscf_impl_tag_ED25519:
            return Ed25519(take: c_ctx)
        case vscf_impl_tag_CURVE25519:
            return Curve25519(take: c_ctx)
        case vscf_impl_tag_COMPOUND_KEY_ALG:
            return CompoundKeyAlg(take: c_ctx)
        case vscf_impl_tag_HYBRID_KEY_ALG:
            return HybridKeyAlg(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapKeyCipher(use c_ctx: OpaquePointer) -> KeyCipher {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapKeyCipher(take:shallowCopy)
    }

    @objc public static func wrapKeySigner(take c_ctx: OpaquePointer) -> KeySigner {
        if (!vscf_key_signer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface KeySigner.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA:
            return Rsa(take: c_ctx)
        case vscf_impl_tag_ECC:
            return Ecc(take: c_ctx)
        case vscf_impl_tag_ED25519:
            return Ed25519(take: c_ctx)
        case vscf_impl_tag_FALCON:
            return Falcon(take: c_ctx)
        case vscf_impl_tag_ML_DSA:
            return MlDsa(take: c_ctx)
        case vscf_impl_tag_COMPOUND_KEY_ALG:
            return CompoundKeyAlg(take: c_ctx)
        case vscf_impl_tag_HYBRID_KEY_ALG:
            return HybridKeyAlg(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapKeySigner(use c_ctx: OpaquePointer) -> KeySigner {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapKeySigner(take:shallowCopy)
    }

    @objc public static func wrapComputeSharedKey(take c_ctx: OpaquePointer) -> ComputeSharedKey {
        if (!vscf_compute_shared_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface ComputeSharedKey.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_ECC:
            return Ecc(take: c_ctx)
        case vscf_impl_tag_ED25519:
            return Ed25519(take: c_ctx)
        case vscf_impl_tag_CURVE25519:
            return Curve25519(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapComputeSharedKey(use c_ctx: OpaquePointer) -> ComputeSharedKey {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapComputeSharedKey(take:shallowCopy)
    }

    @objc public static func wrapKem(take c_ctx: OpaquePointer) -> Kem {
        if (!vscf_kem_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Kem.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_ECC:
            return Ecc(take: c_ctx)
        case vscf_impl_tag_ED25519:
            return Ed25519(take: c_ctx)
        case vscf_impl_tag_CURVE25519:
            return Curve25519(take: c_ctx)
        case vscf_impl_tag_ML_KEM:
            return MlKem(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapKem(use c_ctx: OpaquePointer) -> Kem {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapKem(take:shallowCopy)
    }

    @objc public static func wrapEntropySource(take c_ctx: OpaquePointer) -> EntropySource {
        if (!vscf_entropy_source_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface EntropySource.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_ENTROPY_ACCUMULATOR:
            return EntropyAccumulator(take: c_ctx)
        case vscf_impl_tag_FAKE_RANDOM:
            return FakeRandom(take: c_ctx)
        case vscf_impl_tag_SEED_ENTROPY_SOURCE:
            return SeedEntropySource(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapEntropySource(use c_ctx: OpaquePointer) -> EntropySource {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapEntropySource(take:shallowCopy)
    }

    @objc public static func wrapRandom(take c_ctx: OpaquePointer) -> Random {
        if (!vscf_random_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Random.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_CTR_DRBG:
            return CtrDrbg(take: c_ctx)
        case vscf_impl_tag_FAKE_RANDOM:
            return FakeRandom(take: c_ctx)
        case vscf_impl_tag_KEY_MATERIAL_RNG:
            return KeyMaterialRng(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapRandom(use c_ctx: OpaquePointer) -> Random {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapRandom(take:shallowCopy)
    }

    @objc public static func wrapMac(take c_ctx: OpaquePointer) -> Mac {
        if (!vscf_mac_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Mac.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_HMAC:
            return Hmac(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapMac(use c_ctx: OpaquePointer) -> Mac {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapMac(take:shallowCopy)
    }

    @objc public static func wrapKdf(take c_ctx: OpaquePointer) -> Kdf {
        if (!vscf_kdf_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Kdf.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_HKDF:
            return Hkdf(take: c_ctx)
        case vscf_impl_tag_KDF1:
            return Kdf1(take: c_ctx)
        case vscf_impl_tag_KDF2:
            return Kdf2(take: c_ctx)
        case vscf_impl_tag_PKCS5_PBKDF2:
            return Pkcs5Pbkdf2(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapKdf(use c_ctx: OpaquePointer) -> Kdf {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapKdf(take:shallowCopy)
    }

    @objc public static func wrapSaltedKdf(take c_ctx: OpaquePointer) -> SaltedKdf {
        if (!vscf_salted_kdf_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface SaltedKdf.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_HKDF:
            return Hkdf(take: c_ctx)
        case vscf_impl_tag_PKCS5_PBKDF2:
            return Pkcs5Pbkdf2(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapSaltedKdf(use c_ctx: OpaquePointer) -> SaltedKdf {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapSaltedKdf(take:shallowCopy)
    }

    @objc public static func wrapKeySerializer(take c_ctx: OpaquePointer) -> KeySerializer {
        if (!vscf_key_serializer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface KeySerializer.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_PKCS8_SERIALIZER:
            return Pkcs8Serializer(take: c_ctx)
        case vscf_impl_tag_SEC1_SERIALIZER:
            return Sec1Serializer(take: c_ctx)
        case vscf_impl_tag_KEY_ASN1_SERIALIZER:
            return KeyAsn1Serializer(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapKeySerializer(use c_ctx: OpaquePointer) -> KeySerializer {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapKeySerializer(take:shallowCopy)
    }

    @objc public static func wrapKeyDeserializer(take c_ctx: OpaquePointer) -> KeyDeserializer {
        if (!vscf_key_deserializer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface KeyDeserializer.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_KEY_ASN1_DESERIALIZER:
            return KeyAsn1Deserializer(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapKeyDeserializer(use c_ctx: OpaquePointer) -> KeyDeserializer {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapKeyDeserializer(take:shallowCopy)
    }

    @objc public static func wrapAlgInfo(take c_ctx: OpaquePointer) -> AlgInfo {
        if (!vscf_alg_info_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface AlgInfo.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_COMPOUND_KEY_ALG_INFO:
            return CompoundKeyAlgInfo(take: c_ctx)
        case vscf_impl_tag_HYBRID_KEY_ALG_INFO:
            return HybridKeyAlgInfo(take: c_ctx)
        case vscf_impl_tag_SIMPLE_ALG_INFO:
            return SimpleAlgInfo(take: c_ctx)
        case vscf_impl_tag_HASH_BASED_ALG_INFO:
            return HashBasedAlgInfo(take: c_ctx)
        case vscf_impl_tag_CIPHER_ALG_INFO:
            return CipherAlgInfo(take: c_ctx)
        case vscf_impl_tag_SALTED_KDF_ALG_INFO:
            return SaltedKdfAlgInfo(take: c_ctx)
        case vscf_impl_tag_CHUNKED_ALG_INFO:
            return ChunkedAlgInfo(take: c_ctx)
        case vscf_impl_tag_PBE_ALG_INFO:
            return PbeAlgInfo(take: c_ctx)
        case vscf_impl_tag_ECC_ALG_INFO:
            return EccAlgInfo(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapAlgInfo(use c_ctx: OpaquePointer) -> AlgInfo {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapAlgInfo(take:shallowCopy)
    }

    @objc public static func wrapAlgInfoSerializer(take c_ctx: OpaquePointer) -> AlgInfoSerializer {
        if (!vscf_alg_info_serializer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface AlgInfoSerializer.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
            return AlgInfoDerSerializer(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapAlgInfoSerializer(use c_ctx: OpaquePointer) -> AlgInfoSerializer {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapAlgInfoSerializer(take:shallowCopy)
    }

    @objc public static func wrapAlgInfoDeserializer(take c_ctx: OpaquePointer) -> AlgInfoDeserializer {
        if (!vscf_alg_info_deserializer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface AlgInfoDeserializer.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
            return AlgInfoDerDeserializer(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapAlgInfoDeserializer(use c_ctx: OpaquePointer) -> AlgInfoDeserializer {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapAlgInfoDeserializer(take:shallowCopy)
    }

    @objc public static func wrapMessageInfoSerializer(take c_ctx: OpaquePointer) -> MessageInfoSerializer {
        if (!vscf_message_info_serializer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface MessageInfoSerializer.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
            return MessageInfoDerSerializer(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapMessageInfoSerializer(use c_ctx: OpaquePointer) -> MessageInfoSerializer {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapMessageInfoSerializer(take:shallowCopy)
    }

    @objc public static func wrapMessageInfoFooterSerializer(take c_ctx: OpaquePointer) -> MessageInfoFooterSerializer {
        if (!vscf_message_info_footer_serializer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface MessageInfoFooterSerializer.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
            return MessageInfoDerSerializer(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapMessageInfoFooterSerializer(use c_ctx: OpaquePointer) -> MessageInfoFooterSerializer {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapMessageInfoFooterSerializer(take:shallowCopy)
    }

    @objc public static func wrapPadding(take c_ctx: OpaquePointer) -> Padding {
        if (!vscf_padding_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Padding.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RANDOM_PADDING:
            return RandomPadding(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    @objc public static func wrapPadding(use c_ctx: OpaquePointer) -> Padding {
        let shallowCopy = vscf_impl_shallow_copy(c_ctx)!
        return FoundationImplementation.wrapPadding(take:shallowCopy)
    }

}
