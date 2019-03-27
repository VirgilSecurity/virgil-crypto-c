/// Copyright (C) 2015-2019 Virgil Security, Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
///     (1) Redistributions of source code must retain the above copyright
///     notice, this list of conditions and the following disclaimer.
///
///     (2) Redistributions in binary form must reproduce the above copyright
///     notice, this list of conditions and the following disclaimer in
///     the documentation and/or other materials provided with the
///     distribution.
///
///     (3) Neither the name of the copyright holder nor the names of its
///     contributors may be used to endorse or promote products derived from
///     this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
/// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
/// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
/// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
/// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
/// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
/// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
/// POSSIBILITY OF SUCH DAMAGE.
///
/// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


import Foundation
import VSCFoundation

@objc(VSCFFoundationImplementation) public class FoundationImplementation: NSObject {

    /// Wrap C implementation object to the Swift object that implements protocol Alg.
    @objc static func wrapAlg(take c_ctx: OpaquePointer) -> Alg {
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
        case vscf_impl_tag_RSA_PUBLIC_KEY:
            return RsaPublicKey(take: c_ctx)
        case vscf_impl_tag_RSA_PRIVATE_KEY:
            return RsaPrivateKey(take: c_ctx)
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
        case vscf_impl_tag_ED25519_PUBLIC_KEY:
            return Ed25519PublicKey(take: c_ctx)
        case vscf_impl_tag_ED25519_PRIVATE_KEY:
            return Ed25519PrivateKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
            return Curve25519PublicKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
            return Curve25519PrivateKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol Hash.
    @objc static func wrapHash(take c_ctx: OpaquePointer) -> Hash {
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

    /// Wrap C implementation object to the Swift object that implements protocol Encrypt.
    @objc static func wrapEncrypt(take c_ctx: OpaquePointer) -> Encrypt {
        if (!vscf_encrypt_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Encrypt.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        case vscf_impl_tag_AES256_CBC:
            return Aes256Cbc(take: c_ctx)
        case vscf_impl_tag_RSA_PUBLIC_KEY:
            return RsaPublicKey(take: c_ctx)
        case vscf_impl_tag_PKCS5_PBES2:
            return Pkcs5Pbes2(take: c_ctx)
        case vscf_impl_tag_ED25519_PUBLIC_KEY:
            return Ed25519PublicKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
            return Curve25519PublicKey(take: c_ctx)
        case vscf_impl_tag_ECIES:
            return Ecies(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol Decrypt.
    @objc static func wrapDecrypt(take c_ctx: OpaquePointer) -> Decrypt {
        if (!vscf_decrypt_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Decrypt.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        case vscf_impl_tag_AES256_CBC:
            return Aes256Cbc(take: c_ctx)
        case vscf_impl_tag_RSA_PRIVATE_KEY:
            return RsaPrivateKey(take: c_ctx)
        case vscf_impl_tag_PKCS5_PBES2:
            return Pkcs5Pbes2(take: c_ctx)
        case vscf_impl_tag_ED25519_PRIVATE_KEY:
            return Ed25519PrivateKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
            return Curve25519PrivateKey(take: c_ctx)
        case vscf_impl_tag_ECIES:
            return Ecies(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol CipherInfo.
    @objc static func wrapCipherInfo(take c_ctx: OpaquePointer) -> CipherInfo {
        if (!vscf_cipher_info_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface CipherInfo.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        case vscf_impl_tag_AES256_CBC:
            return Aes256Cbc(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol Cipher.
    @objc static func wrapCipher(take c_ctx: OpaquePointer) -> Cipher {
        if (!vscf_cipher_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Cipher.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_AES256_GCM:
            return Aes256Gcm(take: c_ctx)
        case vscf_impl_tag_AES256_CBC:
            return Aes256Cbc(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol CipherAuthInfo.
    @objc static func wrapCipherAuthInfo(take c_ctx: OpaquePointer) -> CipherAuthInfo {
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

    /// Wrap C implementation object to the Swift object that implements protocol AuthEncrypt.
    @objc static func wrapAuthEncrypt(take c_ctx: OpaquePointer) -> AuthEncrypt {
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

    /// Wrap C implementation object to the Swift object that implements protocol AuthDecrypt.
    @objc static func wrapAuthDecrypt(take c_ctx: OpaquePointer) -> AuthDecrypt {
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

    /// Wrap C implementation object to the Swift object that implements protocol CipherAuth.
    @objc static func wrapCipherAuth(take c_ctx: OpaquePointer) -> CipherAuth {
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

    /// Wrap C implementation object to the Swift object that implements protocol Asn1Reader.
    @objc static func wrapAsn1Reader(take c_ctx: OpaquePointer) -> Asn1Reader {
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

    /// Wrap C implementation object to the Swift object that implements protocol Asn1Writer.
    @objc static func wrapAsn1Writer(take c_ctx: OpaquePointer) -> Asn1Writer {
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

    /// Wrap C implementation object to the Swift object that implements protocol Key.
    @objc static func wrapKey(take c_ctx: OpaquePointer) -> Key {
        if (!vscf_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface Key.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PUBLIC_KEY:
            return RsaPublicKey(take: c_ctx)
        case vscf_impl_tag_RSA_PRIVATE_KEY:
            return RsaPrivateKey(take: c_ctx)
        case vscf_impl_tag_ED25519_PUBLIC_KEY:
            return Ed25519PublicKey(take: c_ctx)
        case vscf_impl_tag_ED25519_PRIVATE_KEY:
            return Ed25519PrivateKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
            return Curve25519PublicKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
            return Curve25519PrivateKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol VerifyHash.
    @objc static func wrapVerifyHash(take c_ctx: OpaquePointer) -> VerifyHash {
        if (!vscf_verify_hash_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface VerifyHash.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PUBLIC_KEY:
            return RsaPublicKey(take: c_ctx)
        case vscf_impl_tag_ED25519_PUBLIC_KEY:
            return Ed25519PublicKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol PublicKey.
    @objc static func wrapPublicKey(take c_ctx: OpaquePointer) -> PublicKey {
        if (!vscf_public_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface PublicKey.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PUBLIC_KEY:
            return RsaPublicKey(take: c_ctx)
        case vscf_impl_tag_ED25519_PUBLIC_KEY:
            return Ed25519PublicKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
            return Curve25519PublicKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol GenerateEphemeralKey.
    @objc static func wrapGenerateEphemeralKey(take c_ctx: OpaquePointer) -> GenerateEphemeralKey {
        if (!vscf_generate_ephemeral_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface GenerateEphemeralKey.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PUBLIC_KEY:
            return RsaPublicKey(take: c_ctx)
        case vscf_impl_tag_ED25519_PUBLIC_KEY:
            return Ed25519PublicKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PUBLIC_KEY:
            return Curve25519PublicKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol GenerateKey.
    @objc static func wrapGenerateKey(take c_ctx: OpaquePointer) -> GenerateKey {
        if (!vscf_generate_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface GenerateKey.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PRIVATE_KEY:
            return RsaPrivateKey(take: c_ctx)
        case vscf_impl_tag_ED25519_PRIVATE_KEY:
            return Ed25519PrivateKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
            return Curve25519PrivateKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol SignHash.
    @objc static func wrapSignHash(take c_ctx: OpaquePointer) -> SignHash {
        if (!vscf_sign_hash_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface SignHash.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PRIVATE_KEY:
            return RsaPrivateKey(take: c_ctx)
        case vscf_impl_tag_ED25519_PRIVATE_KEY:
            return Ed25519PrivateKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol PrivateKey.
    @objc static func wrapPrivateKey(take c_ctx: OpaquePointer) -> PrivateKey {
        if (!vscf_private_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface PrivateKey.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_RSA_PRIVATE_KEY:
            return RsaPrivateKey(take: c_ctx)
        case vscf_impl_tag_ED25519_PRIVATE_KEY:
            return Ed25519PrivateKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
            return Curve25519PrivateKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol EntropySource.
    @objc static func wrapEntropySource(take c_ctx: OpaquePointer) -> EntropySource {
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

    /// Wrap C implementation object to the Swift object that implements protocol Random.
    @objc static func wrapRandom(take c_ctx: OpaquePointer) -> Random {
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

    /// Wrap C implementation object to the Swift object that implements protocol Mac.
    @objc static func wrapMac(take c_ctx: OpaquePointer) -> Mac {
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

    /// Wrap C implementation object to the Swift object that implements protocol Kdf.
    @objc static func wrapKdf(take c_ctx: OpaquePointer) -> Kdf {
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

    /// Wrap C implementation object to the Swift object that implements protocol SaltedKdf.
    @objc static func wrapSaltedKdf(take c_ctx: OpaquePointer) -> SaltedKdf {
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

    /// Wrap C implementation object to the Swift object that implements protocol KeySerializer.
    @objc static func wrapKeySerializer(take c_ctx: OpaquePointer) -> KeySerializer {
        if (!vscf_key_serializer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface KeySerializer.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_PKCS8_DER_SERIALIZER:
            return Pkcs8DerSerializer(take: c_ctx)
        case vscf_impl_tag_PKCS8_SERIALIZER:
            return Pkcs8Serializer(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol KeyDeserializer.
    @objc static func wrapKeyDeserializer(take c_ctx: OpaquePointer) -> KeyDeserializer {
        if (!vscf_key_deserializer_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface KeyDeserializer.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_PKCS8_DER_DESERIALIZER:
            return Pkcs8DerDeserializer(take: c_ctx)
        case vscf_impl_tag_PKCS8_DESERIALIZER:
            return Pkcs8Deserializer(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol ComputeSharedKey.
    @objc static func wrapComputeSharedKey(take c_ctx: OpaquePointer) -> ComputeSharedKey {
        if (!vscf_compute_shared_key_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface ComputeSharedKey.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_ED25519_PRIVATE_KEY:
            return Ed25519PrivateKey(take: c_ctx)
        case vscf_impl_tag_CURVE25519_PRIVATE_KEY:
            return Curve25519PrivateKey(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol AlgInfo.
    @objc static func wrapAlgInfo(take c_ctx: OpaquePointer) -> AlgInfo {
        if (!vscf_alg_info_is_implemented(c_ctx)) {
            fatalError("Given C implementation does not implement interface AlgInfo.")
        }

        let implTag = vscf_impl_tag(c_ctx)
        switch(implTag) {
        case vscf_impl_tag_SIMPLE_ALG_INFO:
            return SimpleAlgInfo(take: c_ctx)
        case vscf_impl_tag_HASH_BASED_ALG_INFO:
            return HashBasedAlgInfo(take: c_ctx)
        case vscf_impl_tag_CIPHER_ALG_INFO:
            return CipherAlgInfo(take: c_ctx)
        case vscf_impl_tag_SALTED_KDF_ALG_INFO:
            return SaltedKdfAlgInfo(take: c_ctx)
        case vscf_impl_tag_PBE_ALG_INFO:
            return PbeAlgInfo(take: c_ctx)
        default:
            fatalError("Unexpected C implementation cast to the Swift implementation.")
        }
    }

    /// Wrap C implementation object to the Swift object that implements protocol AlgInfoSerializer.
    @objc static func wrapAlgInfoSerializer(take c_ctx: OpaquePointer) -> AlgInfoSerializer {
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

    /// Wrap C implementation object to the Swift object that implements protocol AlgInfoDeserializer.
    @objc static func wrapAlgInfoDeserializer(take c_ctx: OpaquePointer) -> AlgInfoDeserializer {
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

    /// Wrap C implementation object to the Swift object that implements protocol MessageInfoSerializer.
    @objc static func wrapMessageInfoSerializer(take c_ctx: OpaquePointer) -> MessageInfoSerializer {
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
}
