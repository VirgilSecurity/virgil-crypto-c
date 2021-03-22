package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

type Implementation struct {
}

/* Wrap C implementation object to the Go object that implements interface Alg. */
func ImplementationWrapAlg(anyctx interface{}) (Alg, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Alg."}
	}
	if !C.vscf_alg_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Alg."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_SHA224:
		return NewSha224WithCtx((*C.vscf_sha224_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SHA256:
		return NewSha256WithCtx((*C.vscf_sha256_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SHA384:
		return NewSha384WithCtx((*C.vscf_sha384_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SHA512:
		return NewSha512WithCtx((*C.vscf_sha512_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_AES256_GCM:
		return NewAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_AES256_CBC:
		return NewAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HMAC:
		return NewHmacWithCtx((*C.vscf_hmac_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HKDF:
		return NewHkdfWithCtx((*C.vscf_hkdf_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_KDF1:
		return NewKdf1WithCtx((*C.vscf_kdf1_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_KDF2:
		return NewKdf2WithCtx((*C.vscf_kdf2_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_PKCS5_PBKDF2:
		return NewPkcs5Pbkdf2WithCtx((*C.vscf_pkcs5_pbkdf2_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_PKCS5_PBES2:
		return NewPkcs5Pbes2WithCtx((*C.vscf_pkcs5_pbes2_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_FALCON:
		return NewFalconWithCtx((*C.vscf_falcon_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_COMPOUND_KEY_ALG:
		return NewCompoundKeyAlgWithCtx((*C.vscf_compound_key_alg_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_RANDOM_PADDING:
		return NewRandomPaddingWithCtx((*C.vscf_random_padding_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Alg. */
func ImplementationWrapAlgCopy(anyctx interface{}) (Alg, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Alg."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapAlg(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Hash. */
func ImplementationWrapHash(anyctx interface{}) (Hash, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Hash."}
	}
	if !C.vscf_hash_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Hash."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_SHA224:
		return NewSha224WithCtx((*C.vscf_sha224_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SHA256:
		return NewSha256WithCtx((*C.vscf_sha256_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SHA384:
		return NewSha384WithCtx((*C.vscf_sha384_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SHA512:
		return NewSha512WithCtx((*C.vscf_sha512_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Hash. */
func ImplementationWrapHashCopy(anyctx interface{}) (Hash, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Hash."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapHash(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Encrypt. */
func ImplementationWrapEncrypt(anyctx interface{}) (Encrypt, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Encrypt."}
	}
	if !C.vscf_encrypt_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Encrypt."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_AES256_GCM:
		return NewAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_AES256_CBC:
		return NewAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_PKCS5_PBES2:
		return NewPkcs5Pbes2WithCtx((*C.vscf_pkcs5_pbes2_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Encrypt. */
func ImplementationWrapEncryptCopy(anyctx interface{}) (Encrypt, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Encrypt."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapEncrypt(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Decrypt. */
func ImplementationWrapDecrypt(anyctx interface{}) (Decrypt, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Decrypt."}
	}
	if !C.vscf_decrypt_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Decrypt."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_AES256_GCM:
		return NewAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_AES256_CBC:
		return NewAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_PKCS5_PBES2:
		return NewPkcs5Pbes2WithCtx((*C.vscf_pkcs5_pbes2_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Decrypt. */
func ImplementationWrapDecryptCopy(anyctx interface{}) (Decrypt, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Decrypt."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapDecrypt(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface CipherInfo. */
func ImplementationWrapCipherInfo(anyctx interface{}) (CipherInfo, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface CipherInfo."}
	}
	if !C.vscf_cipher_info_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface CipherInfo."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_AES256_GCM:
		return NewAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_AES256_CBC:
		return NewAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface CipherInfo. */
func ImplementationWrapCipherInfoCopy(anyctx interface{}) (CipherInfo, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface CipherInfo."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapCipherInfo(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Cipher. */
func ImplementationWrapCipher(anyctx interface{}) (Cipher, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Cipher."}
	}
	if !C.vscf_cipher_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Cipher."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_AES256_GCM:
		return NewAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_AES256_CBC:
		return NewAes256CbcWithCtx((*C.vscf_aes256_cbc_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Cipher. */
func ImplementationWrapCipherCopy(anyctx interface{}) (Cipher, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Cipher."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapCipher(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface CipherAuthInfo. */
func ImplementationWrapCipherAuthInfo(anyctx interface{}) (CipherAuthInfo, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface CipherAuthInfo."}
	}
	if !C.vscf_cipher_auth_info_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface CipherAuthInfo."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_AES256_GCM:
		return NewAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface CipherAuthInfo. */
func ImplementationWrapCipherAuthInfoCopy(anyctx interface{}) (CipherAuthInfo, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface CipherAuthInfo."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapCipherAuthInfo(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AuthEncrypt. */
func ImplementationWrapAuthEncrypt(anyctx interface{}) (AuthEncrypt, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AuthEncrypt."}
	}
	if !C.vscf_auth_encrypt_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface AuthEncrypt."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_AES256_GCM:
		return NewAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface AuthEncrypt. */
func ImplementationWrapAuthEncryptCopy(anyctx interface{}) (AuthEncrypt, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AuthEncrypt."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapAuthEncrypt(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AuthDecrypt. */
func ImplementationWrapAuthDecrypt(anyctx interface{}) (AuthDecrypt, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AuthDecrypt."}
	}
	if !C.vscf_auth_decrypt_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface AuthDecrypt."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_AES256_GCM:
		return NewAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface AuthDecrypt. */
func ImplementationWrapAuthDecryptCopy(anyctx interface{}) (AuthDecrypt, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AuthDecrypt."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapAuthDecrypt(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface CipherAuth. */
func ImplementationWrapCipherAuth(anyctx interface{}) (CipherAuth, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface CipherAuth."}
	}
	if !C.vscf_cipher_auth_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface CipherAuth."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_AES256_GCM:
		return NewAes256GcmWithCtx((*C.vscf_aes256_gcm_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface CipherAuth. */
func ImplementationWrapCipherAuthCopy(anyctx interface{}) (CipherAuth, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface CipherAuth."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapCipherAuth(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Asn1Reader. */
func ImplementationWrapAsn1Reader(anyctx interface{}) (Asn1Reader, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Asn1Reader."}
	}
	if !C.vscf_asn1_reader_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Asn1Reader."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_ASN1RD:
		return NewAsn1rdWithCtx((*C.vscf_asn1rd_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Asn1Reader. */
func ImplementationWrapAsn1ReaderCopy(anyctx interface{}) (Asn1Reader, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Asn1Reader."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapAsn1Reader(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Asn1Writer. */
func ImplementationWrapAsn1Writer(anyctx interface{}) (Asn1Writer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Asn1Writer."}
	}
	if !C.vscf_asn1_writer_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Asn1Writer."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_ASN1WR:
		return NewAsn1wrWithCtx((*C.vscf_asn1wr_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Asn1Writer. */
func ImplementationWrapAsn1WriterCopy(anyctx interface{}) (Asn1Writer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Asn1Writer."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapAsn1Writer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Key. */
func ImplementationWrapKey(anyctx interface{}) (Key, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Key."}
	}
	if !C.vscf_key_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Key."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_RSA_PUBLIC_KEY:
		return NewRsaPublicKeyWithCtx((*C.vscf_rsa_public_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_RSA_PRIVATE_KEY:
		return NewRsaPrivateKeyWithCtx((*C.vscf_rsa_private_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ECC_PUBLIC_KEY:
		return NewEccPublicKeyWithCtx((*C.vscf_ecc_public_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ECC_PRIVATE_KEY:
		return NewEccPrivateKeyWithCtx((*C.vscf_ecc_private_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_RAW_PUBLIC_KEY:
		return NewRawPublicKeyWithCtx((*C.vscf_raw_public_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_RAW_PRIVATE_KEY:
		return NewRawPrivateKeyWithCtx((*C.vscf_raw_private_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_COMPOUND_PUBLIC_KEY:
		return NewCompoundPublicKeyWithCtx((*C.vscf_compound_public_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_COMPOUND_PRIVATE_KEY:
		return NewCompoundPrivateKeyWithCtx((*C.vscf_compound_private_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HYBRID_PUBLIC_KEY:
		return NewHybridPublicKeyWithCtx((*C.vscf_hybrid_public_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HYBRID_PRIVATE_KEY:
		return NewHybridPrivateKeyWithCtx((*C.vscf_hybrid_private_key_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Key. */
func ImplementationWrapKeyCopy(anyctx interface{}) (Key, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Key."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapKey(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface PublicKey. */
func ImplementationWrapPublicKey(anyctx interface{}) (PublicKey, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface PublicKey."}
	}
	if !C.vscf_public_key_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface PublicKey."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_RSA_PUBLIC_KEY:
		return NewRsaPublicKeyWithCtx((*C.vscf_rsa_public_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ECC_PUBLIC_KEY:
		return NewEccPublicKeyWithCtx((*C.vscf_ecc_public_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_RAW_PUBLIC_KEY:
		return NewRawPublicKeyWithCtx((*C.vscf_raw_public_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_COMPOUND_PUBLIC_KEY:
		return NewCompoundPublicKeyWithCtx((*C.vscf_compound_public_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HYBRID_PUBLIC_KEY:
		return NewHybridPublicKeyWithCtx((*C.vscf_hybrid_public_key_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface PublicKey. */
func ImplementationWrapPublicKeyCopy(anyctx interface{}) (PublicKey, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface PublicKey."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapPublicKey(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface PrivateKey. */
func ImplementationWrapPrivateKey(anyctx interface{}) (PrivateKey, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface PrivateKey."}
	}
	if !C.vscf_private_key_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface PrivateKey."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_RSA_PRIVATE_KEY:
		return NewRsaPrivateKeyWithCtx((*C.vscf_rsa_private_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ECC_PRIVATE_KEY:
		return NewEccPrivateKeyWithCtx((*C.vscf_ecc_private_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_RAW_PRIVATE_KEY:
		return NewRawPrivateKeyWithCtx((*C.vscf_raw_private_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_COMPOUND_PRIVATE_KEY:
		return NewCompoundPrivateKeyWithCtx((*C.vscf_compound_private_key_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HYBRID_PRIVATE_KEY:
		return NewHybridPrivateKeyWithCtx((*C.vscf_hybrid_private_key_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface PrivateKey. */
func ImplementationWrapPrivateKeyCopy(anyctx interface{}) (PrivateKey, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface PrivateKey."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapPrivateKey(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeyAlg. */
func ImplementationWrapKeyAlg(anyctx interface{}) (KeyAlg, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeyAlg."}
	}
	if !C.vscf_key_alg_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface KeyAlg."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_RSA:
		return NewRsaWithCtx((*C.vscf_rsa_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ECC:
		return NewEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ED25519:
		return NewEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_CURVE25519:
		return NewCurve25519WithCtx((*C.vscf_curve25519_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_FALCON:
		return NewFalconWithCtx((*C.vscf_falcon_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ROUND5:
		return NewRound5WithCtx((*C.vscf_round5_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_COMPOUND_KEY_ALG:
		return NewCompoundKeyAlgWithCtx((*C.vscf_compound_key_alg_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HYBRID_KEY_ALG:
		return NewHybridKeyAlgWithCtx((*C.vscf_hybrid_key_alg_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface KeyAlg. */
func ImplementationWrapKeyAlgCopy(anyctx interface{}) (KeyAlg, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeyAlg."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapKeyAlg(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeyCipher. */
func ImplementationWrapKeyCipher(anyctx interface{}) (KeyCipher, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeyCipher."}
	}
	if !C.vscf_key_cipher_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface KeyCipher."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_RSA:
		return NewRsaWithCtx((*C.vscf_rsa_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ECC:
		return NewEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ED25519:
		return NewEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_CURVE25519:
		return NewCurve25519WithCtx((*C.vscf_curve25519_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_COMPOUND_KEY_ALG:
		return NewCompoundKeyAlgWithCtx((*C.vscf_compound_key_alg_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HYBRID_KEY_ALG:
		return NewHybridKeyAlgWithCtx((*C.vscf_hybrid_key_alg_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface KeyCipher. */
func ImplementationWrapKeyCipherCopy(anyctx interface{}) (KeyCipher, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeyCipher."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapKeyCipher(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeySigner. */
func ImplementationWrapKeySigner(anyctx interface{}) (KeySigner, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeySigner."}
	}
	if !C.vscf_key_signer_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface KeySigner."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_RSA:
		return NewRsaWithCtx((*C.vscf_rsa_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ECC:
		return NewEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ED25519:
		return NewEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_FALCON:
		return NewFalconWithCtx((*C.vscf_falcon_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_COMPOUND_KEY_ALG:
		return NewCompoundKeyAlgWithCtx((*C.vscf_compound_key_alg_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HYBRID_KEY_ALG:
		return NewHybridKeyAlgWithCtx((*C.vscf_hybrid_key_alg_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface KeySigner. */
func ImplementationWrapKeySignerCopy(anyctx interface{}) (KeySigner, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeySigner."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapKeySigner(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface ComputeSharedKey. */
func ImplementationWrapComputeSharedKey(anyctx interface{}) (ComputeSharedKey, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface ComputeSharedKey."}
	}
	if !C.vscf_compute_shared_key_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface ComputeSharedKey."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_ECC:
		return NewEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ED25519:
		return NewEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_CURVE25519:
		return NewCurve25519WithCtx((*C.vscf_curve25519_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface ComputeSharedKey. */
func ImplementationWrapComputeSharedKeyCopy(anyctx interface{}) (ComputeSharedKey, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface ComputeSharedKey."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapComputeSharedKey(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Kem. */
func ImplementationWrapKem(anyctx interface{}) (Kem, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Kem."}
	}
	if !C.vscf_kem_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Kem."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_ECC:
		return NewEccWithCtx((*C.vscf_ecc_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ED25519:
		return NewEd25519WithCtx((*C.vscf_ed25519_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_CURVE25519:
		return NewCurve25519WithCtx((*C.vscf_curve25519_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ROUND5:
		return NewRound5WithCtx((*C.vscf_round5_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Kem. */
func ImplementationWrapKemCopy(anyctx interface{}) (Kem, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Kem."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapKem(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface EntropySource. */
func ImplementationWrapEntropySource(anyctx interface{}) (EntropySource, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface EntropySource."}
	}
	if !C.vscf_entropy_source_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface EntropySource."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_ENTROPY_ACCUMULATOR:
		return NewEntropyAccumulatorWithCtx((*C.vscf_entropy_accumulator_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_FAKE_RANDOM:
		return NewFakeRandomWithCtx((*C.vscf_fake_random_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SEED_ENTROPY_SOURCE:
		return NewSeedEntropySourceWithCtx((*C.vscf_seed_entropy_source_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface EntropySource. */
func ImplementationWrapEntropySourceCopy(anyctx interface{}) (EntropySource, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface EntropySource."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapEntropySource(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Random. */
func ImplementationWrapRandom(anyctx interface{}) (Random, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Random."}
	}
	if !C.vscf_random_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Random."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_CTR_DRBG:
		return NewCtrDrbgWithCtx((*C.vscf_ctr_drbg_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_FAKE_RANDOM:
		return NewFakeRandomWithCtx((*C.vscf_fake_random_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_KEY_MATERIAL_RNG:
		return NewKeyMaterialRngWithCtx((*C.vscf_key_material_rng_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Random. */
func ImplementationWrapRandomCopy(anyctx interface{}) (Random, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Random."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapRandom(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Mac. */
func ImplementationWrapMac(anyctx interface{}) (Mac, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Mac."}
	}
	if !C.vscf_mac_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Mac."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_HMAC:
		return NewHmacWithCtx((*C.vscf_hmac_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Mac. */
func ImplementationWrapMacCopy(anyctx interface{}) (Mac, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Mac."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapMac(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Kdf. */
func ImplementationWrapKdf(anyctx interface{}) (Kdf, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Kdf."}
	}
	if !C.vscf_kdf_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Kdf."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_HKDF:
		return NewHkdfWithCtx((*C.vscf_hkdf_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_KDF1:
		return NewKdf1WithCtx((*C.vscf_kdf1_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_KDF2:
		return NewKdf2WithCtx((*C.vscf_kdf2_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_PKCS5_PBKDF2:
		return NewPkcs5Pbkdf2WithCtx((*C.vscf_pkcs5_pbkdf2_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Kdf. */
func ImplementationWrapKdfCopy(anyctx interface{}) (Kdf, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Kdf."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapKdf(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface SaltedKdf. */
func ImplementationWrapSaltedKdf(anyctx interface{}) (SaltedKdf, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface SaltedKdf."}
	}
	if !C.vscf_salted_kdf_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface SaltedKdf."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_HKDF:
		return NewHkdfWithCtx((*C.vscf_hkdf_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_PKCS5_PBKDF2:
		return NewPkcs5Pbkdf2WithCtx((*C.vscf_pkcs5_pbkdf2_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface SaltedKdf. */
func ImplementationWrapSaltedKdfCopy(anyctx interface{}) (SaltedKdf, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface SaltedKdf."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapSaltedKdf(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeySerializer. */
func ImplementationWrapKeySerializer(anyctx interface{}) (KeySerializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeySerializer."}
	}
	if !C.vscf_key_serializer_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface KeySerializer."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_PKCS8_SERIALIZER:
		return NewPkcs8SerializerWithCtx((*C.vscf_pkcs8_serializer_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SEC1_SERIALIZER:
		return NewSec1SerializerWithCtx((*C.vscf_sec1_serializer_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_KEY_ASN1_SERIALIZER:
		return NewKeyAsn1SerializerWithCtx((*C.vscf_key_asn1_serializer_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface KeySerializer. */
func ImplementationWrapKeySerializerCopy(anyctx interface{}) (KeySerializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeySerializer."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapKeySerializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface KeyDeserializer. */
func ImplementationWrapKeyDeserializer(anyctx interface{}) (KeyDeserializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeyDeserializer."}
	}
	if !C.vscf_key_deserializer_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface KeyDeserializer."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_KEY_ASN1_DESERIALIZER:
		return NewKeyAsn1DeserializerWithCtx((*C.vscf_key_asn1_deserializer_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface KeyDeserializer. */
func ImplementationWrapKeyDeserializerCopy(anyctx interface{}) (KeyDeserializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface KeyDeserializer."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapKeyDeserializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AlgInfo. */
func ImplementationWrapAlgInfo(anyctx interface{}) (AlgInfo, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AlgInfo."}
	}
	if !C.vscf_alg_info_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface AlgInfo."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_COMPOUND_KEY_ALG_INFO:
		return NewCompoundKeyAlgInfoWithCtx((*C.vscf_compound_key_alg_info_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HYBRID_KEY_ALG_INFO:
		return NewHybridKeyAlgInfoWithCtx((*C.vscf_hybrid_key_alg_info_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SIMPLE_ALG_INFO:
		return NewSimpleAlgInfoWithCtx((*C.vscf_simple_alg_info_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_HASH_BASED_ALG_INFO:
		return NewHashBasedAlgInfoWithCtx((*C.vscf_hash_based_alg_info_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_CIPHER_ALG_INFO:
		return NewCipherAlgInfoWithCtx((*C.vscf_cipher_alg_info_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_SALTED_KDF_ALG_INFO:
		return NewSaltedKdfAlgInfoWithCtx((*C.vscf_salted_kdf_alg_info_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_PBE_ALG_INFO:
		return NewPbeAlgInfoWithCtx((*C.vscf_pbe_alg_info_t /*ct10*/)(ctx)), nil
	case C.vscf_impl_tag_ECC_ALG_INFO:
		return NewEccAlgInfoWithCtx((*C.vscf_ecc_alg_info_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface AlgInfo. */
func ImplementationWrapAlgInfoCopy(anyctx interface{}) (AlgInfo, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AlgInfo."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapAlgInfo(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoSerializer. */
func ImplementationWrapAlgInfoSerializer(anyctx interface{}) (AlgInfoSerializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AlgInfoSerializer."}
	}
	if !C.vscf_alg_info_serializer_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface AlgInfoSerializer."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_ALG_INFO_DER_SERIALIZER:
		return NewAlgInfoDerSerializerWithCtx((*C.vscf_alg_info_der_serializer_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoSerializer. */
func ImplementationWrapAlgInfoSerializerCopy(anyctx interface{}) (AlgInfoSerializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AlgInfoSerializer."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapAlgInfoSerializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoDeserializer. */
func ImplementationWrapAlgInfoDeserializer(anyctx interface{}) (AlgInfoDeserializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AlgInfoDeserializer."}
	}
	if !C.vscf_alg_info_deserializer_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface AlgInfoDeserializer."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_ALG_INFO_DER_DESERIALIZER:
		return NewAlgInfoDerDeserializerWithCtx((*C.vscf_alg_info_der_deserializer_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface AlgInfoDeserializer. */
func ImplementationWrapAlgInfoDeserializerCopy(anyctx interface{}) (AlgInfoDeserializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface AlgInfoDeserializer."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapAlgInfoDeserializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoSerializer. */
func ImplementationWrapMessageInfoSerializer(anyctx interface{}) (MessageInfoSerializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface MessageInfoSerializer."}
	}
	if !C.vscf_message_info_serializer_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface MessageInfoSerializer."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
		return NewMessageInfoDerSerializerWithCtx((*C.vscf_message_info_der_serializer_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoSerializer. */
func ImplementationWrapMessageInfoSerializerCopy(anyctx interface{}) (MessageInfoSerializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface MessageInfoSerializer."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapMessageInfoSerializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoFooterSerializer. */
func ImplementationWrapMessageInfoFooterSerializer(anyctx interface{}) (MessageInfoFooterSerializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface MessageInfoFooterSerializer."}
	}
	if !C.vscf_message_info_footer_serializer_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface MessageInfoFooterSerializer."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER:
		return NewMessageInfoDerSerializerWithCtx((*C.vscf_message_info_der_serializer_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface MessageInfoFooterSerializer. */
func ImplementationWrapMessageInfoFooterSerializerCopy(anyctx interface{}) (MessageInfoFooterSerializer, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface MessageInfoFooterSerializer."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapMessageInfoFooterSerializer(shallowCopy)
}

/* Wrap C implementation object to the Go object that implements interface Padding. */
func ImplementationWrapPadding(anyctx interface{}) (Padding, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Padding."}
	}
	if !C.vscf_padding_is_implemented(ctx) {
		return nil, &FoundationError{-1, "Given C implementation does not implement interface Padding."}
	}

	implTag := C.vscf_impl_tag(ctx)
	switch implTag {
	case C.vscf_impl_tag_RANDOM_PADDING:
		return NewRandomPaddingWithCtx((*C.vscf_random_padding_t /*ct10*/)(ctx)), nil
	default:
		return nil, &FoundationError{-1, "Unexpected C implementation cast to the Go implementation."}
	}
}

/* Wrap C implementation object to the Go object that implements interface Padding. */
func ImplementationWrapPaddingCopy(anyctx interface{}) (Padding, error) {
	ctx, ok := anyctx.(*C.vscf_impl_t)
	if !ok {
		return nil, &FoundationError{-1, "Cast error for interface Padding."}
	}
	shallowCopy := C.vscf_impl_shallow_copy(ctx)
	return ImplementationWrapPadding(shallowCopy)
}
