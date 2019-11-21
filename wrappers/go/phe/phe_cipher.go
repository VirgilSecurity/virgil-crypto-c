package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"
import "runtime"
import foundation "virgil/foundation"


/*
* Class for encryption using PHE account key
* This class is thread-safe.
*/
type PheCipher struct {
    cCtx *C.vsce_phe_cipher_t /*ct2*/
}
const (
    PheCipherSaltLen uint32 = 32
    PheCipherKeyLen uint32 = 32
    PheCipherNonceLen uint32 = 12
)

/* Handle underlying C context. */
func (obj *PheCipher) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewPheCipher() *PheCipher {
    ctx := C.vsce_phe_cipher_new()
    obj := &PheCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPheCipherWithCtx(ctx *C.vsce_phe_cipher_t /*ct2*/) *PheCipher {
    obj := &PheCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPheCipherCopy(ctx *C.vsce_phe_cipher_t /*ct2*/) *PheCipher {
    obj := &PheCipher {
        cCtx: C.vsce_phe_cipher_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *PheCipher) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *PheCipher) delete() {
    C.vsce_phe_cipher_delete(obj.cCtx)
}

/*
* Random used for salt generation
*/
func (obj *PheCipher) SetRandom(random foundation.Random) {
    C.vsce_phe_cipher_release_random(obj.cCtx)
    C.vsce_phe_cipher_use_random(obj.cCtx, (*C.vscf_impl_t)(random.(context).ctx()))
}

/*
* Setups dependencies with default values.
*/
func (obj *PheCipher) SetupDefaults() error {
    proxyResult := /*pr4*/C.vsce_phe_cipher_setup_defaults(obj.cCtx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Returns buffer capacity needed to fit cipher text
*/
func (obj *PheCipher) EncryptLen(plainTextLen uint32) uint32 {
    proxyResult := /*pr4*/C.vsce_phe_cipher_encrypt_len(obj.cCtx, (C.size_t)(plainTextLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns buffer capacity needed to fit plain text
*/
func (obj *PheCipher) DecryptLen(cipherTextLen uint32) uint32 {
    proxyResult := /*pr4*/C.vsce_phe_cipher_decrypt_len(obj.cCtx, (C.size_t)(cipherTextLen)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Encrypts data using account key
*/
func (obj *PheCipher) Encrypt(plainText []byte, accountKey []byte) ([]byte, error) {
    cipherTextBuf, cipherTextBufErr := bufferNewBuffer(int(obj.EncryptLen(uint32(len(plainText))) /* lg2 */))
    if cipherTextBufErr != nil {
        return nil, cipherTextBufErr
    }
    defer cipherTextBuf.Delete()
    plainTextData := helperWrapData (plainText)
    accountKeyData := helperWrapData (accountKey)

    proxyResult := /*pr4*/C.vsce_phe_cipher_encrypt(obj.cCtx, plainTextData, accountKeyData, cipherTextBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return cipherTextBuf.getData() /* r7 */, nil
}

/*
* Decrypts data using account key
*/
func (obj *PheCipher) Decrypt(cipherText []byte, accountKey []byte) ([]byte, error) {
    plainTextBuf, plainTextBufErr := bufferNewBuffer(int(obj.DecryptLen(uint32(len(cipherText))) /* lg2 */))
    if plainTextBufErr != nil {
        return nil, plainTextBufErr
    }
    defer plainTextBuf.Delete()
    cipherTextData := helperWrapData (cipherText)
    accountKeyData := helperWrapData (accountKey)

    proxyResult := /*pr4*/C.vsce_phe_cipher_decrypt(obj.cCtx, cipherTextData, accountKeyData, plainTextBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return plainTextBuf.getData() /* r7 */, nil
}

/*
* Encrypts data (and authenticates additional data) using account key
*/
func (obj *PheCipher) AuthEncrypt(plainText []byte, additionalData []byte, accountKey []byte) ([]byte, error) {
    cipherTextBuf, cipherTextBufErr := bufferNewBuffer(int(obj.EncryptLen(uint32(len(plainText))) /* lg2 */))
    if cipherTextBufErr != nil {
        return nil, cipherTextBufErr
    }
    defer cipherTextBuf.Delete()
    plainTextData := helperWrapData (plainText)
    additionalDataData := helperWrapData (additionalData)
    accountKeyData := helperWrapData (accountKey)

    proxyResult := /*pr4*/C.vsce_phe_cipher_auth_encrypt(obj.cCtx, plainTextData, additionalDataData, accountKeyData, cipherTextBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return cipherTextBuf.getData() /* r7 */, nil
}

/*
* Decrypts data (and verifies additional data) using account key
*/
func (obj *PheCipher) AuthDecrypt(cipherText []byte, additionalData []byte, accountKey []byte) ([]byte, error) {
    plainTextBuf, plainTextBufErr := bufferNewBuffer(int(obj.DecryptLen(uint32(len(cipherText))) /* lg2 */))
    if plainTextBufErr != nil {
        return nil, plainTextBufErr
    }
    defer plainTextBuf.Delete()
    cipherTextData := helperWrapData (cipherText)
    additionalDataData := helperWrapData (additionalData)
    accountKeyData := helperWrapData (accountKey)

    proxyResult := /*pr4*/C.vsce_phe_cipher_auth_decrypt(obj.cCtx, cipherTextData, additionalDataData, accountKeyData, plainTextBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return plainTextBuf.getData() /* r7 */, nil
}
