package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


type FoundationImplementation struct {
}

/* Wrap C implementation object to the Go object that implements interface Alg. */
func FoundationImplementationWrapAlg(ctx *C.vscf_impl_t) (Alg, error) {
    if (!C.vscf_alg_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Alg."}
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
    case C.vscf_impl_tag_FALCON:
        return newFalconWithCtx((*C.vscf_falcon_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_KEY_ALG:
        return newCompoundKeyAlgWithCtx((*C.vscf_compound_key_alg_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_RANDOM_PADDING:
        return newRandomPaddingWithCtx((*C.vscf_random_padding_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Alg. */
func FoundationImplementationWrapAlgCopy(ctx *C.vscf_impl_t) (Alg, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapAlg(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Hash. */
func FoundationImplementationWrapHash(ctx *C.vscf_impl_t) (Hash, error) {
    if (!C.vscf_hash_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Hash."}
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

/* Wrap C implementation object to the Go object that implements interface Hash. */
func FoundationImplementationWrapHashCopy(ctx *C.vscf_impl_t) (Hash, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapHash(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Encrypt. */
func FoundationImplementationWrapEncrypt(ctx *C.vscf_impl_t) (Encrypt, error) {
    if (!C.vscf_encrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Encrypt."}
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

/* Wrap C implementation object to the Go object that implements interface Encrypt. */
func FoundationImplementationWrapEncryptCopy(ctx *C.vscf_impl_t) (Encrypt, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapEncrypt(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Decrypt. */
func FoundationImplementationWrapDecrypt(ctx *C.vscf_impl_t) (Decrypt, error) {
    if (!C.vscf_decrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Decrypt."}
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

/* Wrap C implementation object to the Go object that implements interface Decrypt. */
func FoundationImplementationWrapDecryptCopy(ctx *C.vscf_impl_t) (Decrypt, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapDecrypt(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface CipherInfo. */
func FoundationImplementationWrapCipherInfo(ctx *C.vscf_impl_t) (CipherInfo, error) {
    if (!C.vscf_cipher_info_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface CipherInfo."}
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

/* Wrap C implementation object to the Go object that implements interface CipherInfo. */
func FoundationImplementationWrapCipherInfoCopy(ctx *C.vscf_impl_t) (CipherInfo, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapCipherInfo(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Cipher. */
func FoundationImplementationWrapCipher(ctx *C.vscf_impl_t) (Cipher, error) {
    if (!C.vscf_cipher_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Cipher."}
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

/* Wrap C implementation object to the Go object that implements interface Cipher. */
func FoundationImplementationWrapCipherCopy(ctx *C.vscf_impl_t) (Cipher, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapCipher(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface CipherAuthInfo. */
func FoundationImplementationWrapCipherAuthInfo(ctx *C.vscf_impl_t) (CipherAuthInfo, error) {
    if (!C.vscf_cipher_auth_info_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface CipherAuthInfo."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface CipherAuthInfo. */
func FoundationImplementationWrapCipherAuthInfoCopy(ctx *C.vscf_impl_t) (CipherAuthInfo, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapCipherAuthInfo(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AuthEncrypt. */
func FoundationImplementationWrapAuthEncrypt(ctx *C.vscf_impl_t) (AuthEncrypt, error) {
    if (!C.vscf_auth_encrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AuthEncrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface AuthEncrypt. */
func FoundationImplementationWrapAuthEncryptCopy(ctx *C.vscf_impl_t) (AuthEncrypt, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapAuthEncrypt(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AuthDecrypt. */
func FoundationImplementationWrapAuthDecrypt(ctx *C.vscf_impl_t) (AuthDecrypt, error) {
    if (!C.vscf_auth_decrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AuthDecrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface AuthDecrypt. */
func FoundationImplementationWrapAuthDecryptCopy(ctx *C.vscf_impl_t) (AuthDecrypt, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapAuthDecrypt(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface CipherAuth. */
func FoundationImplementationWrapCipherAuth(ctx *C.vscf_impl_t) (CipherAuth, error) {
    if (!C.vscf_cipher_auth_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface CipherAuth."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return newAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface CipherAuth. */
func FoundationImplementationWrapCipherAuthCopy(ctx *C.vscf_impl_t) (CipherAuth, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapCipherAuth(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Asn1Reader. */
func FoundationImplementationWrapAsn1Reader(ctx *C.vscf_impl_t) (Asn1Reader, error) {
    if (!C.vscf_asn1_reader_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Asn1Reader."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ASN1RD:
        return newAsn1rdWithCtx((*C.vscf_asn1rd_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Asn1Reader. */
func FoundationImplementationWrapAsn1ReaderCopy(ctx *C.vscf_impl_t) (Asn1Reader, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapAsn1Reader(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Asn1Writer. */
func FoundationImplementationWrapAsn1Writer(ctx *C.vscf_impl_t) (Asn1Writer, error) {
    if (!C.vscf_asn1_writer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Asn1Writer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ASN1WR:
        return newAsn1wrWithCtx((*C.vscf_asn1wr_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Asn1Writer. */
func FoundationImplementationWrapAsn1WriterCopy(ctx *C.vscf_impl_t) (Asn1Writer, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapAsn1Writer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Key. */
func FoundationImplementationWrapKey(ctx *C.vscf_impl_t) (Key, error) {
    if (!C.vscf_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Key."}
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
    case C.vscf_impl_tag_COMPOUND_PUBLIC_KEY:
        return newCompoundPublicKeyWithCtx((*C.vscf_compound_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_PRIVATE_KEY:
        return newCompoundPrivateKeyWithCtx((*C.vscf_compound_private_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HYBRID_PUBLIC_KEY:
        return newHybridPublicKeyWithCtx((*C.vscf_hybrid_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HYBRID_PRIVATE_KEY:
        return newHybridPrivateKeyWithCtx((*C.vscf_hybrid_private_key_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Key. */
func FoundationImplementationWrapKeyCopy(ctx *C.vscf_impl_t) (Key, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapKey(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface PublicKey. */
func FoundationImplementationWrapPublicKey(ctx *C.vscf_impl_t) (PublicKey, error) {
    if (!C.vscf_public_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface PublicKey."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA_PUBLIC_KEY:
        return newRsaPublicKeyWithCtx((*C.vscf_rsa_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC_PUBLIC_KEY:
        return newEccPublicKeyWithCtx((*C.vscf_ecc_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_RAW_PUBLIC_KEY:
        return newRawPublicKeyWithCtx((*C.vscf_raw_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_PUBLIC_KEY:
        return newCompoundPublicKeyWithCtx((*C.vscf_compound_public_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HYBRID_PUBLIC_KEY:
        return newHybridPublicKeyWithCtx((*C.vscf_hybrid_public_key_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface PublicKey. */
func FoundationImplementationWrapPublicKeyCopy(ctx *C.vscf_impl_t) (PublicKey, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapPublicKey(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface PrivateKey. */
func FoundationImplementationWrapPrivateKey(ctx *C.vscf_impl_t) (PrivateKey, error) {
    if (!C.vscf_private_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface PrivateKey."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA_PRIVATE_KEY:
        return newRsaPrivateKeyWithCtx((*C.vscf_rsa_private_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC_PRIVATE_KEY:
        return newEccPrivateKeyWithCtx((*C.vscf_ecc_private_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_RAW_PRIVATE_KEY:
        return newRawPrivateKeyWithCtx((*C.vscf_raw_private_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_PRIVATE_KEY:
        return newCompoundPrivateKeyWithCtx((*C.vscf_compound_private_key_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HYBRID_PRIVATE_KEY:
        return newHybridPrivateKeyWithCtx((*C.vscf_hybrid_private_key_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface PrivateKey. */
func FoundationImplementationWrapPrivateKeyCopy(ctx *C.vscf_impl_t) (PrivateKey, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapPrivateKey(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeyAlg. */
func FoundationImplementationWrapKeyAlg(ctx *C.vscf_impl_t) (KeyAlg, error) {
    if (!C.vscf_key_alg_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeyAlg."}
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
    case C.vscf_impl_tag_FALCON:
        return newFalconWithCtx((*C.vscf_falcon_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ROUND5:
        return newRound5WithCtx((*C.vscf_round5_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_KEY_ALG:
        return newCompoundKeyAlgWithCtx((*C.vscf_compound_key_alg_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HYBRID_KEY_ALG:
        return newHybridKeyAlgWithCtx((*C.vscf_hybrid_key_alg_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface KeyAlg. */
func FoundationImplementationWrapKeyAlgCopy(ctx *C.vscf_impl_t) (KeyAlg, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapKeyAlg(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeyCipher. */
func FoundationImplementationWrapKeyCipher(ctx *C.vscf_impl_t) (KeyCipher, error) {
    if (!C.vscf_key_cipher_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeyCipher."}
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
    case C.vscf_impl_tag_COMPOUND_KEY_ALG:
        return newCompoundKeyAlgWithCtx((*C.vscf_compound_key_alg_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HYBRID_KEY_ALG:
        return newHybridKeyAlgWithCtx((*C.vscf_hybrid_key_alg_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface KeyCipher. */
func FoundationImplementationWrapKeyCipherCopy(ctx *C.vscf_impl_t) (KeyCipher, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapKeyCipher(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeySigner. */
func FoundationImplementationWrapKeySigner(ctx *C.vscf_impl_t) (KeySigner, error) {
    if (!C.vscf_key_signer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeySigner."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA:
        return newRsaWithCtx((*C.vscf_rsa_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ECC:
        return newEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return newEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_FALCON:
        return newFalconWithCtx((*C.vscf_falcon_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_KEY_ALG:
        return newCompoundKeyAlgWithCtx((*C.vscf_compound_key_alg_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HYBRID_KEY_ALG:
        return newHybridKeyAlgWithCtx((*C.vscf_hybrid_key_alg_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface KeySigner. */
func FoundationImplementationWrapKeySignerCopy(ctx *C.vscf_impl_t) (KeySigner, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapKeySigner(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface ComputeSharedKey. */
func FoundationImplementationWrapComputeSharedKey(ctx *C.vscf_impl_t) (ComputeSharedKey, error) {
    if (!C.vscf_compute_shared_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface ComputeSharedKey."}
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

/* Wrap C implementation object to the Go object that implements interface ComputeSharedKey. */
func FoundationImplementationWrapComputeSharedKeyCopy(ctx *C.vscf_impl_t) (ComputeSharedKey, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapComputeSharedKey(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Kem. */
func FoundationImplementationWrapKem(ctx *C.vscf_impl_t) (Kem, error) {
    if (!C.vscf_kem_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Kem."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ECC:
        return newEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return newEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_CURVE25519:
        return newCurve25519WithCtx((*C.vscf_curve25519_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_ROUND5:
        return newRound5WithCtx((*C.vscf_round5_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Kem. */
func FoundationImplementationWrapKemCopy(ctx *C.vscf_impl_t) (Kem, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapKem(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface EntropySource. */
func FoundationImplementationWrapEntropySource(ctx *C.vscf_impl_t) (EntropySource, error) {
    if (!C.vscf_entropy_source_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface EntropySource."}
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

/* Wrap C implementation object to the Go object that implements interface EntropySource. */
func FoundationImplementationWrapEntropySourceCopy(ctx *C.vscf_impl_t) (EntropySource, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapEntropySource(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Random. */
func FoundationImplementationWrapRandom(ctx *C.vscf_impl_t) (Random, error) {
    if (!C.vscf_random_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Random."}
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

/* Wrap C implementation object to the Go object that implements interface Random. */
func FoundationImplementationWrapRandomCopy(ctx *C.vscf_impl_t) (Random, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapRandom(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Mac. */
func FoundationImplementationWrapMac(ctx *C.vscf_impl_t) (Mac, error) {
    if (!C.vscf_mac_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Mac."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_HMAC:
        return newHmacWithCtx((*C.vscf_hmac_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Mac. */
func FoundationImplementationWrapMacCopy(ctx *C.vscf_impl_t) (Mac, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapMac(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Kdf. */
func FoundationImplementationWrapKdf(ctx *C.vscf_impl_t) (Kdf, error) {
    if (!C.vscf_kdf_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Kdf."}
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

/* Wrap C implementation object to the Go object that implements interface Kdf. */
func FoundationImplementationWrapKdfCopy(ctx *C.vscf_impl_t) (Kdf, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapKdf(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface SaltedKdf. */
func FoundationImplementationWrapSaltedKdf(ctx *C.vscf_impl_t) (SaltedKdf, error) {
    if (!C.vscf_salted_kdf_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface SaltedKdf."}
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

/* Wrap C implementation object to the Go object that implements interface SaltedKdf. */
func FoundationImplementationWrapSaltedKdfCopy(ctx *C.vscf_impl_t) (SaltedKdf, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapSaltedKdf(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeySerializer. */
func FoundationImplementationWrapKeySerializer(ctx *C.vscf_impl_t) (KeySerializer, error) {
    if (!C.vscf_key_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeySerializer."}
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

/* Wrap C implementation object to the Go object that implements interface KeySerializer. */
func FoundationImplementationWrapKeySerializerCopy(ctx *C.vscf_impl_t) (KeySerializer, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapKeySerializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeyDeserializer. */
func FoundationImplementationWrapKeyDeserializer(ctx *C.vscf_impl_t) (KeyDeserializer, error) {
    if (!C.vscf_key_deserializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeyDeserializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_KEY_ASN1_DESERIALIZER:
        return newKeyAsn1DeserializerWithCtx((*C.vscf_key_asn1_deserializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface KeyDeserializer. */
func FoundationImplementationWrapKeyDeserializerCopy(ctx *C.vscf_impl_t) (KeyDeserializer, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapKeyDeserializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AlgInfo. */
func FoundationImplementationWrapAlgInfo(ctx *C.vscf_impl_t) (AlgInfo, error) {
    if (!C.vscf_alg_info_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AlgInfo."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_COMPOUND_KEY_ALG_INFO:
        return newCompoundKeyAlgInfoWithCtx((*C.vscf_compound_key_alg_info_t /*ct10*/)(ctx)), nil
    case C.vscf_impl_tag_HYBRID_KEY_ALG_INFO:
        return newHybridKeyAlgInfoWithCtx((*C.vscf_hybrid_key_alg_info_t /*ct10*/)(ctx)), nil
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

/* Wrap C implementation object to the Go object that implements interface AlgInfo. */
func FoundationImplementationWrapAlgInfoCopy(ctx *C.vscf_impl_t) (AlgInfo, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapAlgInfo(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoSerializer. */
func FoundationImplementationWrapAlgInfoSerializer(ctx *C.vscf_impl_t) (AlgInfoSerializer, error) {
    if (!C.vscf_alg_info_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AlgInfoSerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
        return newAlgInfoDerSerializerWithCtx((*C.vscf_alg_info_der_serializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoSerializer. */
func FoundationImplementationWrapAlgInfoSerializerCopy(ctx *C.vscf_impl_t) (AlgInfoSerializer, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapAlgInfoSerializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoDeserializer. */
func FoundationImplementationWrapAlgInfoDeserializer(ctx *C.vscf_impl_t) (AlgInfoDeserializer, error) {
    if (!C.vscf_alg_info_deserializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AlgInfoDeserializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
        return newAlgInfoDerDeserializerWithCtx((*C.vscf_alg_info_der_deserializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoDeserializer. */
func FoundationImplementationWrapAlgInfoDeserializerCopy(ctx *C.vscf_impl_t) (AlgInfoDeserializer, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapAlgInfoDeserializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoSerializer. */
func FoundationImplementationWrapMessageInfoSerializer(ctx *C.vscf_impl_t) (MessageInfoSerializer, error) {
    if (!C.vscf_message_info_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface MessageInfoSerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return newMessageInfoDerSerializerWithCtx((*C.vscf_message_info_der_serializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoSerializer. */
func FoundationImplementationWrapMessageInfoSerializerCopy(ctx *C.vscf_impl_t) (MessageInfoSerializer, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapMessageInfoSerializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoFooterSerializer. */
func FoundationImplementationWrapMessageInfoFooterSerializer(ctx *C.vscf_impl_t) (MessageInfoFooterSerializer, error) {
    if (!C.vscf_message_info_footer_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface MessageInfoFooterSerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return newMessageInfoDerSerializerWithCtx((*C.vscf_message_info_der_serializer_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoFooterSerializer. */
func FoundationImplementationWrapMessageInfoFooterSerializerCopy(ctx *C.vscf_impl_t) (MessageInfoFooterSerializer, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapMessageInfoFooterSerializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Padding. */
func FoundationImplementationWrapPadding(ctx *C.vscf_impl_t) (Padding, error) {
    if (!C.vscf_padding_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Padding."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RANDOM_PADDING:
        return newRandomPaddingWithCtx((*C.vscf_random_padding_t /*ct10*/)(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Padding. */
func FoundationImplementationWrapPaddingCopy(ctx *C.vscf_impl_t) (Padding, error) {
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return FoundationImplementationWrapPadding(shallowCopy)
}
