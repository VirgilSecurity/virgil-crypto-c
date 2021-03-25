package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"


type Implementation struct {
}

/* Wrap C implementation object to the Go object that implements interface Alg. */
func ImplementationWrapAlg(pointer unsafe.Pointer) (Alg, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_alg_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Alg."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_SHA224:
        return NewSha224WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SHA256:
        return NewSha256WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SHA384:
        return NewSha384WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SHA512:
        return NewSha512WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_AES256_GCM:
        return NewAes256GcmWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return NewAes256CbcWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HMAC:
        return NewHmacWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HKDF:
        return NewHkdfWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_KDF1:
        return NewKdf1WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_KDF2:
        return NewKdf2WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBKDF2:
        return NewPkcs5Pbkdf2WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBES2:
        return NewPkcs5Pbes2WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_FALCON:
        return NewFalconWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_KEY_ALG:
        return NewCompoundKeyAlgWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_RANDOM_PADDING:
        return NewRandomPaddingWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Alg. */
func ImplementationWrapAlgCopy(pointer unsafe.Pointer) (Alg, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapAlg(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Hash. */
func ImplementationWrapHash(pointer unsafe.Pointer) (Hash, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_hash_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Hash."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_SHA224:
        return NewSha224WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SHA256:
        return NewSha256WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SHA384:
        return NewSha384WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SHA512:
        return NewSha512WithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Hash. */
func ImplementationWrapHashCopy(pointer unsafe.Pointer) (Hash, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapHash(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Encrypt. */
func ImplementationWrapEncrypt(pointer unsafe.Pointer) (Encrypt, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_encrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Encrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return NewAes256GcmWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return NewAes256CbcWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBES2:
        return NewPkcs5Pbes2WithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Encrypt. */
func ImplementationWrapEncryptCopy(pointer unsafe.Pointer) (Encrypt, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapEncrypt(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Decrypt. */
func ImplementationWrapDecrypt(pointer unsafe.Pointer) (Decrypt, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_decrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Decrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return NewAes256GcmWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return NewAes256CbcWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBES2:
        return NewPkcs5Pbes2WithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Decrypt. */
func ImplementationWrapDecryptCopy(pointer unsafe.Pointer) (Decrypt, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapDecrypt(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface CipherInfo. */
func ImplementationWrapCipherInfo(pointer unsafe.Pointer) (CipherInfo, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_cipher_info_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface CipherInfo."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return NewAes256GcmWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return NewAes256CbcWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface CipherInfo. */
func ImplementationWrapCipherInfoCopy(pointer unsafe.Pointer) (CipherInfo, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapCipherInfo(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Cipher. */
func ImplementationWrapCipher(pointer unsafe.Pointer) (Cipher, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_cipher_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Cipher."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return NewAes256GcmWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_AES256_CBC:
        return NewAes256CbcWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Cipher. */
func ImplementationWrapCipherCopy(pointer unsafe.Pointer) (Cipher, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapCipher(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface CipherAuthInfo. */
func ImplementationWrapCipherAuthInfo(pointer unsafe.Pointer) (CipherAuthInfo, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_cipher_auth_info_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface CipherAuthInfo."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return NewAes256GcmWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface CipherAuthInfo. */
func ImplementationWrapCipherAuthInfoCopy(pointer unsafe.Pointer) (CipherAuthInfo, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapCipherAuthInfo(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface AuthEncrypt. */
func ImplementationWrapAuthEncrypt(pointer unsafe.Pointer) (AuthEncrypt, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_auth_encrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AuthEncrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return NewAes256GcmWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface AuthEncrypt. */
func ImplementationWrapAuthEncryptCopy(pointer unsafe.Pointer) (AuthEncrypt, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapAuthEncrypt(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface AuthDecrypt. */
func ImplementationWrapAuthDecrypt(pointer unsafe.Pointer) (AuthDecrypt, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_auth_decrypt_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AuthDecrypt."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return NewAes256GcmWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface AuthDecrypt. */
func ImplementationWrapAuthDecryptCopy(pointer unsafe.Pointer) (AuthDecrypt, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapAuthDecrypt(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface CipherAuth. */
func ImplementationWrapCipherAuth(pointer unsafe.Pointer) (CipherAuth, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_cipher_auth_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface CipherAuth."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_AES256_GCM:
        return NewAes256GcmWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface CipherAuth. */
func ImplementationWrapCipherAuthCopy(pointer unsafe.Pointer) (CipherAuth, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapCipherAuth(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Asn1Reader. */
func ImplementationWrapAsn1Reader(pointer unsafe.Pointer) (Asn1Reader, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_asn1_reader_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Asn1Reader."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ASN1RD:
        return NewAsn1rdWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Asn1Reader. */
func ImplementationWrapAsn1ReaderCopy(pointer unsafe.Pointer) (Asn1Reader, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapAsn1Reader(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Asn1Writer. */
func ImplementationWrapAsn1Writer(pointer unsafe.Pointer) (Asn1Writer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_asn1_writer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Asn1Writer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ASN1WR:
        return NewAsn1wrWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Asn1Writer. */
func ImplementationWrapAsn1WriterCopy(pointer unsafe.Pointer) (Asn1Writer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapAsn1Writer(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Key. */
func ImplementationWrapKey(pointer unsafe.Pointer) (Key, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Key."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA_PUBLIC_KEY:
        return NewRsaPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_RSA_PRIVATE_KEY:
        return NewRsaPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ECC_PUBLIC_KEY:
        return NewEccPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ECC_PRIVATE_KEY:
        return NewEccPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_RAW_PUBLIC_KEY:
        return NewRawPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_RAW_PRIVATE_KEY:
        return NewRawPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_PUBLIC_KEY:
        return NewCompoundPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_PRIVATE_KEY:
        return NewCompoundPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HYBRID_PUBLIC_KEY:
        return NewHybridPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HYBRID_PRIVATE_KEY:
        return NewHybridPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Key. */
func ImplementationWrapKeyCopy(pointer unsafe.Pointer) (Key, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapKey(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface PublicKey. */
func ImplementationWrapPublicKey(pointer unsafe.Pointer) (PublicKey, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_public_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface PublicKey."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA_PUBLIC_KEY:
        return NewRsaPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ECC_PUBLIC_KEY:
        return NewEccPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_RAW_PUBLIC_KEY:
        return NewRawPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_PUBLIC_KEY:
        return NewCompoundPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HYBRID_PUBLIC_KEY:
        return NewHybridPublicKeyWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface PublicKey. */
func ImplementationWrapPublicKeyCopy(pointer unsafe.Pointer) (PublicKey, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapPublicKey(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface PrivateKey. */
func ImplementationWrapPrivateKey(pointer unsafe.Pointer) (PrivateKey, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_private_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface PrivateKey."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA_PRIVATE_KEY:
        return NewRsaPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ECC_PRIVATE_KEY:
        return NewEccPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_RAW_PRIVATE_KEY:
        return NewRawPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_PRIVATE_KEY:
        return NewCompoundPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HYBRID_PRIVATE_KEY:
        return NewHybridPrivateKeyWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface PrivateKey. */
func ImplementationWrapPrivateKeyCopy(pointer unsafe.Pointer) (PrivateKey, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapPrivateKey(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface KeyAlg. */
func ImplementationWrapKeyAlg(pointer unsafe.Pointer) (KeyAlg, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_key_alg_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeyAlg."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA:
        return NewRsaWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ECC:
        return NewEccWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return NewEd25519WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_CURVE25519:
        return NewCurve25519WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_FALCON:
        return NewFalconWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ROUND5:
        return NewRound5WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_KEY_ALG:
        return NewCompoundKeyAlgWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HYBRID_KEY_ALG:
        return NewHybridKeyAlgWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface KeyAlg. */
func ImplementationWrapKeyAlgCopy(pointer unsafe.Pointer) (KeyAlg, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapKeyAlg(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface KeyCipher. */
func ImplementationWrapKeyCipher(pointer unsafe.Pointer) (KeyCipher, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_key_cipher_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeyCipher."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA:
        return NewRsaWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ECC:
        return NewEccWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return NewEd25519WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_CURVE25519:
        return NewCurve25519WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_KEY_ALG:
        return NewCompoundKeyAlgWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HYBRID_KEY_ALG:
        return NewHybridKeyAlgWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface KeyCipher. */
func ImplementationWrapKeyCipherCopy(pointer unsafe.Pointer) (KeyCipher, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapKeyCipher(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface KeySigner. */
func ImplementationWrapKeySigner(pointer unsafe.Pointer) (KeySigner, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_key_signer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeySigner."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RSA:
        return NewRsaWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ECC:
        return NewEccWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return NewEd25519WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_FALCON:
        return NewFalconWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_COMPOUND_KEY_ALG:
        return NewCompoundKeyAlgWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HYBRID_KEY_ALG:
        return NewHybridKeyAlgWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface KeySigner. */
func ImplementationWrapKeySignerCopy(pointer unsafe.Pointer) (KeySigner, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapKeySigner(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface ComputeSharedKey. */
func ImplementationWrapComputeSharedKey(pointer unsafe.Pointer) (ComputeSharedKey, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_compute_shared_key_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface ComputeSharedKey."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ECC:
        return NewEccWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return NewEd25519WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_CURVE25519:
        return NewCurve25519WithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface ComputeSharedKey. */
func ImplementationWrapComputeSharedKeyCopy(pointer unsafe.Pointer) (ComputeSharedKey, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapComputeSharedKey(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Kem. */
func ImplementationWrapKem(pointer unsafe.Pointer) (Kem, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_kem_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Kem."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ECC:
        return NewEccWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ED25519:
        return NewEd25519WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_CURVE25519:
        return NewCurve25519WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ROUND5:
        return NewRound5WithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Kem. */
func ImplementationWrapKemCopy(pointer unsafe.Pointer) (Kem, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapKem(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface EntropySource. */
func ImplementationWrapEntropySource(pointer unsafe.Pointer) (EntropySource, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_entropy_source_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface EntropySource."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ENTROPY_ACCUMULATOR:
        return NewEntropyAccumulatorWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_FAKE_RANDOM:
        return NewFakeRandomWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SEED_ENTROPY_SOURCE:
        return NewSeedEntropySourceWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface EntropySource. */
func ImplementationWrapEntropySourceCopy(pointer unsafe.Pointer) (EntropySource, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapEntropySource(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Random. */
func ImplementationWrapRandom(pointer unsafe.Pointer) (Random, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_random_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Random."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_CTR_DRBG:
        return NewCtrDrbgWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_FAKE_RANDOM:
        return NewFakeRandomWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_KEY_MATERIAL_RNG:
        return NewKeyMaterialRngWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Random. */
func ImplementationWrapRandomCopy(pointer unsafe.Pointer) (Random, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapRandom(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Mac. */
func ImplementationWrapMac(pointer unsafe.Pointer) (Mac, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_mac_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Mac."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_HMAC:
        return NewHmacWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Mac. */
func ImplementationWrapMacCopy(pointer unsafe.Pointer) (Mac, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapMac(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Kdf. */
func ImplementationWrapKdf(pointer unsafe.Pointer) (Kdf, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_kdf_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Kdf."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_HKDF:
        return NewHkdfWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_KDF1:
        return NewKdf1WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_KDF2:
        return NewKdf2WithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBKDF2:
        return NewPkcs5Pbkdf2WithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Kdf. */
func ImplementationWrapKdfCopy(pointer unsafe.Pointer) (Kdf, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapKdf(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface SaltedKdf. */
func ImplementationWrapSaltedKdf(pointer unsafe.Pointer) (SaltedKdf, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_salted_kdf_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface SaltedKdf."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_HKDF:
        return NewHkdfWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_PKCS5_PBKDF2:
        return NewPkcs5Pbkdf2WithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface SaltedKdf. */
func ImplementationWrapSaltedKdfCopy(pointer unsafe.Pointer) (SaltedKdf, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapSaltedKdf(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface KeySerializer. */
func ImplementationWrapKeySerializer(pointer unsafe.Pointer) (KeySerializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_key_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeySerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_PKCS8_SERIALIZER:
        return NewPkcs8SerializerWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SEC1_SERIALIZER:
        return NewSec1SerializerWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_KEY_ASN1_SERIALIZER:
        return NewKeyAsn1SerializerWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface KeySerializer. */
func ImplementationWrapKeySerializerCopy(pointer unsafe.Pointer) (KeySerializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapKeySerializer(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface KeyDeserializer. */
func ImplementationWrapKeyDeserializer(pointer unsafe.Pointer) (KeyDeserializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_key_deserializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface KeyDeserializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_KEY_ASN1_DESERIALIZER:
        return NewKeyAsn1DeserializerWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface KeyDeserializer. */
func ImplementationWrapKeyDeserializerCopy(pointer unsafe.Pointer) (KeyDeserializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapKeyDeserializer(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface AlgInfo. */
func ImplementationWrapAlgInfo(pointer unsafe.Pointer) (AlgInfo, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_alg_info_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AlgInfo."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_COMPOUND_KEY_ALG_INFO:
        return NewCompoundKeyAlgInfoWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HYBRID_KEY_ALG_INFO:
        return NewHybridKeyAlgInfoWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SIMPLE_ALG_INFO:
        return NewSimpleAlgInfoWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_HASH_BASED_ALG_INFO:
        return NewHashBasedAlgInfoWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_CIPHER_ALG_INFO:
        return NewCipherAlgInfoWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_SALTED_KDF_ALG_INFO:
        return NewSaltedKdfAlgInfoWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_PBE_ALG_INFO:
        return NewPbeAlgInfoWithCtx(unsafe.Pointer(ctx)), nil
    case C.vscf_impl_tag_ECC_ALG_INFO:
        return NewEccAlgInfoWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface AlgInfo. */
func ImplementationWrapAlgInfoCopy(pointer unsafe.Pointer) (AlgInfo, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapAlgInfo(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoSerializer. */
func ImplementationWrapAlgInfoSerializer(pointer unsafe.Pointer) (AlgInfoSerializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_alg_info_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AlgInfoSerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
        return NewAlgInfoDerSerializerWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoSerializer. */
func ImplementationWrapAlgInfoSerializerCopy(pointer unsafe.Pointer) (AlgInfoSerializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapAlgInfoSerializer(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoDeserializer. */
func ImplementationWrapAlgInfoDeserializer(pointer unsafe.Pointer) (AlgInfoDeserializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_alg_info_deserializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface AlgInfoDeserializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
        return NewAlgInfoDerDeserializerWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoDeserializer. */
func ImplementationWrapAlgInfoDeserializerCopy(pointer unsafe.Pointer) (AlgInfoDeserializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapAlgInfoDeserializer(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoSerializer. */
func ImplementationWrapMessageInfoSerializer(pointer unsafe.Pointer) (MessageInfoSerializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_message_info_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface MessageInfoSerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return NewMessageInfoDerSerializerWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoSerializer. */
func ImplementationWrapMessageInfoSerializerCopy(pointer unsafe.Pointer) (MessageInfoSerializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapMessageInfoSerializer(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoFooterSerializer. */
func ImplementationWrapMessageInfoFooterSerializer(pointer unsafe.Pointer) (MessageInfoFooterSerializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_message_info_footer_serializer_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface MessageInfoFooterSerializer."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
        return NewMessageInfoDerSerializerWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoFooterSerializer. */
func ImplementationWrapMessageInfoFooterSerializerCopy(pointer unsafe.Pointer) (MessageInfoFooterSerializer, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapMessageInfoFooterSerializer(unsafe.Pointer(shallowCopy))
}

/* Wrap C implementation object to the Go object that implements interface Padding. */
func ImplementationWrapPadding(pointer unsafe.Pointer) (Padding, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    if (!C.vscf_padding_is_implemented(ctx)) {
        return nil, &FoundationError{-1,"Given C implementation does not implement interface Padding."}
    }

    implTag := C.vscf_impl_tag(ctx)
    switch (implTag) {
    case C.vscf_impl_tag_RANDOM_PADDING:
        return NewRandomPaddingWithCtx(unsafe.Pointer(ctx)), nil
    default:
        return nil, &FoundationError{-1,"Unexpected C implementation cast to the Go implementation."}
    }
}

/* Wrap C implementation object to the Go object that implements interface Padding. */
func ImplementationWrapPaddingCopy(pointer unsafe.Pointer) (Padding, error) {
    ctx := (*C.vscf_impl_t)(pointer)
    shallowCopy := C.vscf_impl_shallow_copy(ctx)
    return ImplementationWrapPadding(unsafe.Pointer(shallowCopy))
}
