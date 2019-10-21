package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"

type FoundationImplementation struct {
}

/* Wrap C implementation object to the Go object that implements interface IAlg. */
func FoundationImplementationWrapIAlg (ctx C.size_t) IAlg {
    if (!C.vscf_alg_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IAlg.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_SHA224:
        return Sha224(ctx)
    case C.vscf_impl_tag_SHA256:
        return Sha256(ctx)
    case C.vscf_impl_tag_SHA384:
        return Sha384(ctx)
    case C.vscf_impl_tag_SHA512:
        return Sha512(ctx)
    case C.vscf_impl_tag_AES256_GCM:
        return Aes256Gcm(ctx)
    case C.vscf_impl_tag_AES256_CBC:
        return Aes256Cbc(ctx)
    case C.vscf_impl_tag_RSA:
        return Rsa(ctx)
    case C.vscf_impl_tag_ECC:
        return Ecc(ctx)
    case C.vscf_impl_tag_HMAC:
        return Hmac(ctx)
    case C.vscf_impl_tag_HKDF:
        return Hkdf(ctx)
    case C.vscf_impl_tag_KDF1:
        return Kdf1(ctx)
    case C.vscf_impl_tag_KDF2:
        return Kdf2(ctx)
    case C.vscf_impl_tag_PKCS5_PBKDF2:
        return Pkcs5Pbkdf2(ctx)
    case C.vscf_impl_tag_PKCS5_PBES2:
        return Pkcs5Pbes2(ctx)
    case C.vscf_impl_tag_ED25519:
        return Ed25519(ctx)
    case C.vscf_impl_tag_CURVE25519:
        return Curve25519(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IHash. */
func FoundationImplementationWrapIHash (ctx C.size_t) IHash {
    if (!C.vscf_hash_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IHash.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_SHA224:
        return Sha224(ctx)
    case C.vscf_impl_tag_SHA256:
        return Sha256(ctx)
    case C.vscf_impl_tag_SHA384:
        return Sha384(ctx)
    case C.vscf_impl_tag_SHA512:
        return Sha512(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IEncrypt. */
func FoundationImplementationWrapIEncrypt (ctx C.size_t) IEncrypt {
    if (!C.vscf_encrypt_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IEncrypt.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return Aes256Gcm(ctx)
    case C.vscf_impl_tag_AES256_CBC:
        return Aes256Cbc(ctx)
    case C.vscf_impl_tag_PKCS5_PBES2:
        return Pkcs5Pbes2(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IDecrypt. */
func FoundationImplementationWrapIDecrypt (ctx C.size_t) IDecrypt {
    if (!C.vscf_decrypt_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IDecrypt.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return Aes256Gcm(ctx)
    case C.vscf_impl_tag_AES256_CBC:
        return Aes256Cbc(ctx)
    case C.vscf_impl_tag_PKCS5_PBES2:
        return Pkcs5Pbes2(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface ICipherInfo. */
func FoundationImplementationWrapICipherInfo (ctx C.size_t) ICipherInfo {
    if (!C.vscf_cipher_info_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface ICipherInfo.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return Aes256Gcm(ctx)
    case C.vscf_impl_tag_AES256_CBC:
        return Aes256Cbc(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface ICipher. */
func FoundationImplementationWrapICipher (ctx C.size_t) ICipher {
    if (!C.vscf_cipher_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface ICipher.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return Aes256Gcm(ctx)
    case C.vscf_impl_tag_AES256_CBC:
        return Aes256Cbc(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface ICipherAuthInfo. */
func FoundationImplementationWrapICipherAuthInfo (ctx C.size_t) ICipherAuthInfo {
    if (!C.vscf_cipher_auth_info_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface ICipherAuthInfo.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return Aes256Gcm(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IAuthEncrypt. */
func FoundationImplementationWrapIAuthEncrypt (ctx C.size_t) IAuthEncrypt {
    if (!C.vscf_auth_encrypt_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IAuthEncrypt.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return Aes256Gcm(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IAuthDecrypt. */
func FoundationImplementationWrapIAuthDecrypt (ctx C.size_t) IAuthDecrypt {
    if (!C.vscf_auth_decrypt_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IAuthDecrypt.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return Aes256Gcm(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface ICipherAuth. */
func FoundationImplementationWrapICipherAuth (ctx C.size_t) ICipherAuth {
    if (!C.vscf_cipher_auth_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface ICipherAuth.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return Aes256Gcm(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IAsn1Reader. */
func FoundationImplementationWrapIAsn1Reader (ctx C.size_t) IAsn1Reader {
    if (!C.vscf_asn1_reader_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IAsn1Reader.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_ASN1RD:
        return Asn1rd(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IAsn1Writer. */
func FoundationImplementationWrapIAsn1Writer (ctx C.size_t) IAsn1Writer {
    if (!C.vscf_asn1_writer_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IAsn1Writer.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_ASN1WR:
        return Asn1wr(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IKey. */
func FoundationImplementationWrapIKey (ctx C.size_t) IKey {
    if (!C.vscf_key_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IKey.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_RSA_PUBLIC_KEY:
        return RsaPublicKey(ctx)
    case C.vscf_impl_tag_RSA_PRIVATE_KEY:
        return RsaPrivateKey(ctx)
    case C.vscf_impl_tag_ECC_PUBLIC_KEY:
        return EccPublicKey(ctx)
    case C.vscf_impl_tag_ECC_PRIVATE_KEY:
        return EccPrivateKey(ctx)
    case C.vscf_impl_tag_RAW_PUBLIC_KEY:
        return RawPublicKey(ctx)
    case C.vscf_impl_tag_RAW_PRIVATE_KEY:
        return RawPrivateKey(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IPublicKey. */
func FoundationImplementationWrapIPublicKey (ctx C.size_t) IPublicKey {
    if (!C.vscf_public_key_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IPublicKey.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_RSA_PUBLIC_KEY:
        return RsaPublicKey(ctx)
    case C.vscf_impl_tag_ECC_PUBLIC_KEY:
        return EccPublicKey(ctx)
    case C.vscf_impl_tag_RAW_PUBLIC_KEY:
        return RawPublicKey(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IPrivateKey. */
func FoundationImplementationWrapIPrivateKey (ctx C.size_t) IPrivateKey {
    if (!C.vscf_private_key_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IPrivateKey.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_RSA_PRIVATE_KEY:
        return RsaPrivateKey(ctx)
    case C.vscf_impl_tag_ECC_PRIVATE_KEY:
        return EccPrivateKey(ctx)
    case C.vscf_impl_tag_RAW_PRIVATE_KEY:
        return RawPrivateKey(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeyAlg. */
func FoundationImplementationWrapIKeyAlg (ctx C.size_t) IKeyAlg {
    if (!C.vscf_key_alg_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IKeyAlg.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_RSA:
        return Rsa(ctx)
    case C.vscf_impl_tag_ECC:
        return Ecc(ctx)
    case C.vscf_impl_tag_ED25519:
        return Ed25519(ctx)
    case C.vscf_impl_tag_CURVE25519:
        return Curve25519(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeyCipher. */
func FoundationImplementationWrapIKeyCipher (ctx C.size_t) IKeyCipher {
    if (!C.vscf_key_cipher_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IKeyCipher.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_RSA:
        return Rsa(ctx)
    case C.vscf_impl_tag_ECC:
        return Ecc(ctx)
    case C.vscf_impl_tag_ED25519:
        return Ed25519(ctx)
    case C.vscf_impl_tag_CURVE25519:
        return Curve25519(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeySigner. */
func FoundationImplementationWrapIKeySigner (ctx C.size_t) IKeySigner {
    if (!C.vscf_key_signer_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IKeySigner.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_RSA:
        return Rsa(ctx)
    case C.vscf_impl_tag_ECC:
        return Ecc(ctx)
    case C.vscf_impl_tag_ED25519:
        return Ed25519(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IComputeSharedKey. */
func FoundationImplementationWrapIComputeSharedKey (ctx C.size_t) IComputeSharedKey {
    if (!C.vscf_compute_shared_key_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IComputeSharedKey.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_ECC:
        return Ecc(ctx)
    case C.vscf_impl_tag_ED25519:
        return Ed25519(ctx)
    case C.vscf_impl_tag_CURVE25519:
        return Curve25519(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IEntropySource. */
func FoundationImplementationWrapIEntropySource (ctx C.size_t) IEntropySource {
    if (!C.vscf_entropy_source_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IEntropySource.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_ENTROPY_ACCUMULATOR:
        return EntropyAccumulator(ctx)
    case C.vscf_impl_tag_FAKE_RANDOM:
        return FakeRandom(ctx)
    case C.vscf_impl_tag_SEED_ENTROPY_SOURCE:
        return SeedEntropySource(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IRandom. */
func FoundationImplementationWrapIRandom (ctx C.size_t) IRandom {
    if (!C.vscf_random_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IRandom.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_CTR_DRBG:
        return CtrDrbg(ctx)
    case C.vscf_impl_tag_FAKE_RANDOM:
        return FakeRandom(ctx)
    case C.vscf_impl_tag_KEY_MATERIAL_RNG:
        return KeyMaterialRng(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IMac. */
func FoundationImplementationWrapIMac (ctx C.size_t) IMac {
    if (!C.vscf_mac_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IMac.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_HMAC:
        return Hmac(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IKdf. */
func FoundationImplementationWrapIKdf (ctx C.size_t) IKdf {
    if (!C.vscf_kdf_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IKdf.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_HKDF:
        return Hkdf(ctx)
    case C.vscf_impl_tag_KDF1:
        return Kdf1(ctx)
    case C.vscf_impl_tag_KDF2:
        return Kdf2(ctx)
    case C.vscf_impl_tag_PKCS5_PBKDF2:
        return Pkcs5Pbkdf2(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface ISaltedKdf. */
func FoundationImplementationWrapISaltedKdf (ctx C.size_t) ISaltedKdf {
    if (!C.vscf_salted_kdf_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface ISaltedKdf.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_HKDF:
        return Hkdf(ctx)
    case C.vscf_impl_tag_PKCS5_PBKDF2:
        return Pkcs5Pbkdf2(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeySerializer. */
func FoundationImplementationWrapIKeySerializer (ctx C.size_t) IKeySerializer {
    if (!C.vscf_key_serializer_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IKeySerializer.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_PKCS8_SERIALIZER:
        return Pkcs8Serializer(ctx)
    case C.vscf_impl_tag_SEC1_SERIALIZER:
        return Sec1Serializer(ctx)
    case C.vscf_impl_tag_KEY_ASN1_SERIALIZER:
        return KeyAsn1Serializer(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeyDeserializer. */
func FoundationImplementationWrapIKeyDeserializer (ctx C.size_t) IKeyDeserializer {
    if (!C.vscf_key_deserializer_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IKeyDeserializer.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_KEY_ASN1_DESERIALIZER:
        return KeyAsn1Deserializer(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IAlgInfo. */
func FoundationImplementationWrapIAlgInfo (ctx C.size_t) IAlgInfo {
    if (!C.vscf_alg_info_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IAlgInfo.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_SIMPLE_ALG_INFO:
        return SimpleAlgInfo(ctx)
    case C.vscf_impl_tag_HASH_BASED_ALG_INFO:
        return HashBasedAlgInfo(ctx)
    case C.vscf_impl_tag_CIPHER_ALG_INFO:
        return CipherAlgInfo(ctx)
    case C.vscf_impl_tag_SALTED_KDF_ALG_INFO:
        return SaltedKdfAlgInfo(ctx)
    case C.vscf_impl_tag_PBE_ALG_INFO:
        return PbeAlgInfo(ctx)
    case C.vscf_impl_tag_ECC_ALG_INFO:
        return EccAlgInfo(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IAlgInfoSerializer. */
func FoundationImplementationWrapIAlgInfoSerializer (ctx C.size_t) IAlgInfoSerializer {
    if (!C.vscf_alg_info_serializer_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IAlgInfoSerializer.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
        return AlgInfoDerSerializer(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IAlgInfoDeserializer. */
func FoundationImplementationWrapIAlgInfoDeserializer (ctx C.size_t) IAlgInfoDeserializer {
    if (!C.vscf_alg_info_deserializer_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IAlgInfoDeserializer.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
        return AlgInfoDerDeserializer(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IMessageInfoSerializer. */
func FoundationImplementationWrapIMessageInfoSerializer (ctx C.size_t) IMessageInfoSerializer {
    if (!C.vscf_message_info_serializer_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IMessageInfoSerializer.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return MessageInfoDerSerializer(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}

/* Wrap C implementation object to the Go object that implements interface IMessageInfoFooterSerializer. */
func FoundationImplementationWrapIMessageInfoFooterSerializer (ctx C.size_t) IMessageInfoFooterSerializer {
    if (!C.vscf_message_info_footer_serializer_is_implemented(ctx)) {
        //TODO fatalError("Given C implementation does not implement interface IMessageInfoFooterSerializer.")
    }

    implTag := C.vscf_impl_tag(ctx)
    switch(implTag) {
    case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return MessageInfoDerSerializer(ctx)
    default:
        //TODO fatalError("Unexpected C implementation cast to the Go implementation.")
    }
}
