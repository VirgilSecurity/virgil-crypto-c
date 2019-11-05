package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


type FoundationImplementation struct {
}

/* Wrap C implementation object to the Go object that implements interface IAlg. */
func FoundationImplementationWrapIAlg (ctx *C.vscf_impl_t) (IAlg, error) {
    if (!C.vscf_alg_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IAlg."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_SHA224:
        return newSha224WithCtx((*C.vscf_sha224_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_SHA256:
        return newSha256WithCtx((*C.vscf_sha256_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_SHA384:
        return newSha384WithCtx((*C.vscf_sha384_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_SHA512:
        return newSha512WithCtx((*C.vscf_sha512_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return newAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_RSA:
        return newRsaWithCtx((*C.vscf_rsa_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC:
        return newEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HMAC:
        return newHmacWithCtx((*C.vscf_hmac_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HKDF:
        return newHkdfWithCtx((*C.vscf_hkdf_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_KDF1:
        return newKdf1WithCtx((*C.vscf_kdf1_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_KDF2:
        return newKdf2WithCtx((*C.vscf_kdf2_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBKDF2:
        return newPkcs5Pbkdf2WithCtx((*C.vscf_pkcs5_pbkdf2_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBES2:
        return newPkcs5Pbes2WithCtx((*C.vscf_pkcs5_pbes2_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return newEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_CURVE25519:
        return newCurve25519WithCtx((*C.vscf_curve25519_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IHash. */
func FoundationImplementationWrapIHash (ctx *C.vscf_impl_t) (IHash, error) {
    if (!C.vscf_hash_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IHash."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_SHA224:
        return newSha224WithCtx((*C.vscf_sha224_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_SHA256:
        return newSha256WithCtx((*C.vscf_sha256_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_SHA384:
        return newSha384WithCtx((*C.vscf_sha384_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_SHA512:
        return newSha512WithCtx((*C.vscf_sha512_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IEncrypt. */
func FoundationImplementationWrapIEncrypt (ctx *C.vscf_impl_t) (IEncrypt, error) {
    if (!C.vscf_encrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IEncrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return newAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBES2:
        return newPkcs5Pbes2WithCtx((*C.vscf_pkcs5_pbes2_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IDecrypt. */
func FoundationImplementationWrapIDecrypt (ctx *C.vscf_impl_t) (IDecrypt, error) {
    if (!C.vscf_decrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IDecrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return newAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBES2:
        return newPkcs5Pbes2WithCtx((*C.vscf_pkcs5_pbes2_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface ICipherInfo. */
func FoundationImplementationWrapICipherInfo (ctx *C.vscf_impl_t) (ICipherInfo, error) {
    if (!C.vscf_cipher_info_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface ICipherInfo."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return newAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface ICipher. */
func FoundationImplementationWrapICipher (ctx *C.vscf_impl_t) (ICipher, error) {
    if (!C.vscf_cipher_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface ICipher."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return newAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface ICipherAuthInfo. */
func FoundationImplementationWrapICipherAuthInfo (ctx *C.vscf_impl_t) (ICipherAuthInfo, error) {
    if (!C.vscf_cipher_auth_info_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface ICipherAuthInfo."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IAuthEncrypt. */
func FoundationImplementationWrapIAuthEncrypt (ctx *C.vscf_impl_t) (IAuthEncrypt, error) {
    if (!C.vscf_auth_encrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IAuthEncrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IAuthDecrypt. */
func FoundationImplementationWrapIAuthDecrypt (ctx *C.vscf_impl_t) (IAuthDecrypt, error) {
    if (!C.vscf_auth_decrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IAuthDecrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface ICipherAuth. */
func FoundationImplementationWrapICipherAuth (ctx *C.vscf_impl_t) (ICipherAuth, error) {
    if (!C.vscf_cipher_auth_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface ICipherAuth."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IAsn1Reader. */
func FoundationImplementationWrapIAsn1Reader (ctx *C.vscf_impl_t) (IAsn1Reader, error) {
    if (!C.vscf_asn1_reader_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IAsn1Reader."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ASN1RD:
        return newAsn1rdWithCtx((*C.vscf_asn1rd_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IAsn1Writer. */
func FoundationImplementationWrapIAsn1Writer (ctx *C.vscf_impl_t) (IAsn1Writer, error) {
    if (!C.vscf_asn1_writer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IAsn1Writer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ASN1WR:
        return newAsn1wrWithCtx((*C.vscf_asn1wr_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IKey. */
func FoundationImplementationWrapIKey (ctx *C.vscf_impl_t) (IKey, error) {
    if (!C.vscf_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IKey."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA_PUBLIC_KEY:
        return newRsaPublicKeyWithCtx((*C.vscf_rsa_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_RSA_PRIVATE_KEY:
        return newRsaPrivateKeyWithCtx((*C.vscf_rsa_private_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC_PUBLIC_KEY:
        return newEccPublicKeyWithCtx((*C.vscf_ecc_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC_PRIVATE_KEY:
        return newEccPrivateKeyWithCtx((*C.vscf_ecc_private_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_RAW_PUBLIC_KEY:
        return newRawPublicKeyWithCtx((*C.vscf_raw_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_RAW_PRIVATE_KEY:
        return newRawPrivateKeyWithCtx((*C.vscf_raw_private_key_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IPublicKey. */
func FoundationImplementationWrapIPublicKey (ctx *C.vscf_impl_t) (IPublicKey, error) {
    if (!C.vscf_public_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IPublicKey."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA_PUBLIC_KEY:
        return newRsaPublicKeyWithCtx((*C.vscf_rsa_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC_PUBLIC_KEY:
        return newEccPublicKeyWithCtx((*C.vscf_ecc_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_RAW_PUBLIC_KEY:
        return newRawPublicKeyWithCtx((*C.vscf_raw_public_key_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IPrivateKey. */
func FoundationImplementationWrapIPrivateKey (ctx *C.vscf_impl_t) (IPrivateKey, error) {
    if (!C.vscf_private_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IPrivateKey."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA_PRIVATE_KEY:
        return newRsaPrivateKeyWithCtx((*C.vscf_rsa_private_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC_PRIVATE_KEY:
        return newEccPrivateKeyWithCtx((*C.vscf_ecc_private_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_RAW_PRIVATE_KEY:
        return newRawPrivateKeyWithCtx((*C.vscf_raw_private_key_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeyAlg. */
func FoundationImplementationWrapIKeyAlg (ctx *C.vscf_impl_t) (IKeyAlg, error) {
    if (!C.vscf_key_alg_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IKeyAlg."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA:
        return newRsaWithCtx((*C.vscf_rsa_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC:
        return newEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return newEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_CURVE25519:
        return newCurve25519WithCtx((*C.vscf_curve25519_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeyCipher. */
func FoundationImplementationWrapIKeyCipher (ctx *C.vscf_impl_t) (IKeyCipher, error) {
    if (!C.vscf_key_cipher_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IKeyCipher."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA:
        return newRsaWithCtx((*C.vscf_rsa_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC:
        return newEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return newEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_CURVE25519:
        return newCurve25519WithCtx((*C.vscf_curve25519_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeySigner. */
func FoundationImplementationWrapIKeySigner (ctx *C.vscf_impl_t) (IKeySigner, error) {
    if (!C.vscf_key_signer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IKeySigner."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA:
        return newRsaWithCtx((*C.vscf_rsa_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC:
        return newEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return newEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IComputeSharedKey. */
func FoundationImplementationWrapIComputeSharedKey (ctx *C.vscf_impl_t) (IComputeSharedKey, error) {
    if (!C.vscf_compute_shared_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IComputeSharedKey."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ECC:
        return newEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return newEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_CURVE25519:
        return newCurve25519WithCtx((*C.vscf_curve25519_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IEntropySource. */
func FoundationImplementationWrapIEntropySource (ctx *C.vscf_impl_t) (IEntropySource, error) {
    if (!C.vscf_entropy_source_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IEntropySource."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ENTROPY_ACCUMULATOR:
        return newEntropyAccumulatorWithCtx((*C.vscf_entropy_accumulator_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_FAKE_RANDOM:
        return newFakeRandomWithCtx((*C.vscf_fake_random_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_SEED_ENTROPY_SOURCE:
        return newSeedEntropySourceWithCtx((*C.vscf_seed_entropy_source_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IRandom. */
func FoundationImplementationWrapIRandom (ctx *C.vscf_impl_t) (IRandom, error) {
    if (!C.vscf_random_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IRandom."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_CTR_DRBG:
        return newCtrDrbgWithCtx((*C.vscf_ctr_drbg_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_FAKE_RANDOM:
        return newFakeRandomWithCtx((*C.vscf_fake_random_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_KEY_MATERIAL_RNG:
        return newKeyMaterialRngWithCtx((*C.vscf_key_material_rng_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IMac. */
func FoundationImplementationWrapIMac (ctx *C.vscf_impl_t) (IMac, error) {
    if (!C.vscf_mac_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IMac."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_HMAC:
        return newHmacWithCtx((*C.vscf_hmac_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IKdf. */
func FoundationImplementationWrapIKdf (ctx *C.vscf_impl_t) (IKdf, error) {
    if (!C.vscf_kdf_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IKdf."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_HKDF:
        return newHkdfWithCtx((*C.vscf_hkdf_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_KDF1:
        return newKdf1WithCtx((*C.vscf_kdf1_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_KDF2:
        return newKdf2WithCtx((*C.vscf_kdf2_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBKDF2:
        return newPkcs5Pbkdf2WithCtx((*C.vscf_pkcs5_pbkdf2_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface ISaltedKdf. */
func FoundationImplementationWrapISaltedKdf (ctx *C.vscf_impl_t) (ISaltedKdf, error) {
    if (!C.vscf_salted_kdf_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface ISaltedKdf."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_HKDF:
        return newHkdfWithCtx((*C.vscf_hkdf_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBKDF2:
        return newPkcs5Pbkdf2WithCtx((*C.vscf_pkcs5_pbkdf2_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeySerializer. */
func FoundationImplementationWrapIKeySerializer (ctx *C.vscf_impl_t) (IKeySerializer, error) {
    if (!C.vscf_key_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IKeySerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_PKCS8_SERIALIZER:
        return newPkcs8SerializerWithCtx((*C.vscf_pkcs8_serializer_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_SEC1_SERIALIZER:
        return newSec1SerializerWithCtx((*C.vscf_sec1_serializer_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_KEY_ASN1_SERIALIZER:
        return newKeyAsn1SerializerWithCtx((*C.vscf_key_asn1_serializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IKeyDeserializer. */
func FoundationImplementationWrapIKeyDeserializer (ctx *C.vscf_impl_t) (IKeyDeserializer, error) {
    if (!C.vscf_key_deserializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IKeyDeserializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_KEY_ASN1_DESERIALIZER:
        return newKeyAsn1DeserializerWithCtx((*C.vscf_key_asn1_deserializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IAlgInfo. */
func FoundationImplementationWrapIAlgInfo (ctx *C.vscf_impl_t) (IAlgInfo, error) {
    if (!C.vscf_alg_info_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IAlgInfo."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_SIMPLE_ALG_INFO:
        return newSimpleAlgInfoWithCtx((*C.vscf_simple_alg_info_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HASH_BASED_ALG_INFO:
        return newHashBasedAlgInfoWithCtx((*C.vscf_hash_based_alg_info_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_CIPHER_ALG_INFO:
        return newCipherAlgInfoWithCtx((*C.vscf_cipher_alg_info_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_SALTED_KDF_ALG_INFO:
        return newSaltedKdfAlgInfoWithCtx((*C.vscf_salted_kdf_alg_info_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_PBE_ALG_INFO:
        return newPbeAlgInfoWithCtx((*C.vscf_pbe_alg_info_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC_ALG_INFO:
        return newEccAlgInfoWithCtx((*C.vscf_ecc_alg_info_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IAlgInfoSerializer. */
func FoundationImplementationWrapIAlgInfoSerializer (ctx *C.vscf_impl_t) (IAlgInfoSerializer, error) {
    if (!C.vscf_alg_info_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IAlgInfoSerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
        return newAlgInfoDerSerializerWithCtx((*C.vscf_alg_info_der_serializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IAlgInfoDeserializer. */
func FoundationImplementationWrapIAlgInfoDeserializer (ctx *C.vscf_impl_t) (IAlgInfoDeserializer, error) {
    if (!C.vscf_alg_info_deserializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IAlgInfoDeserializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
        return newAlgInfoDerDeserializerWithCtx((*C.vscf_alg_info_der_deserializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IMessageInfoSerializer. */
func FoundationImplementationWrapIMessageInfoSerializer (ctx *C.vscf_impl_t) (IMessageInfoSerializer, error) {
    if (!C.vscf_message_info_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IMessageInfoSerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return newMessageInfoDerSerializerWithCtx((*C.vscf_message_info_der_serializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface IMessageInfoFooterSerializer. */
func FoundationImplementationWrapIMessageInfoFooterSerializer (ctx *C.vscf_impl_t) (IMessageInfoFooterSerializer, error) {
    if (!C.vscf_message_info_footer_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface IMessageInfoFooterSerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return newMessageInfoDerSerializerWithCtx((*C.vscf_message_info_der_serializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}
