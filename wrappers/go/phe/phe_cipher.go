package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"


/*
* Class for encryption using PHE account key
* This class is thread-safe.
*/
type PheCipher struct {
    cCtx *C.vsce_phe_cipher_t
}

/* Handle underlying C context. */
func (obj *PheCipher) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewPheCipher() *PheCipher {
    ctx := C.vsce_phe_cipher_new()
    obj := &PheCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*PheCipher).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPheCipherWithCtx(ctx *C.vsce_phe_cipher_t) *PheCipher {
    obj := &PheCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*PheCipher).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPheCipherCopy(ctx *C.vsce_phe_cipher_t) *PheCipher {
    obj := &PheCipher {
        cCtx: C.vsce_phe_cipher_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*PheCipher).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *PheCipher) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *PheCipher) delete() {
    C.vsce_phe_cipher_delete(obj.cCtx)
}

func (obj *PheCipher) SetRandom(random foundation.Random) {
    C.vsce_phe_cipher_release_random(obj.cCtx)
    C.vsce_phe_cipher_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Setups dependencies with default values.
*/
func (obj *PheCipher) SetupDefaults() error {
    proxyResult := C.vsce_phe_cipher_setup_defaults(obj.cCtx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Returns buffer capacity needed to fit cipher text
*/
func (obj *PheCipher) EncryptLen(plainTextLen uint) uint {
    proxyResult := C.vsce_phe_cipher_encrypt_len(obj.cCtx, (C.size_t)(plainTextLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Returns buffer capacity needed to fit plain text
*/
func (obj *PheCipher) DecryptLen(cipherTextLen uint) uint {
    proxyResult := C.vsce_phe_cipher_decrypt_len(obj.cCtx, (C.size_t)(cipherTextLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Encrypts data using account key
*/
func (obj *PheCipher) Encrypt(plainText []byte, accountKey []byte) ([]byte, error) {
    cipherTextBuf, cipherTextBufErr := newBuffer(int(obj.EncryptLen(uint(len(plainText)))))
    if cipherTextBufErr != nil {
        return nil, cipherTextBufErr
    }
    defer cipherTextBuf.delete()
    plainTextData := helperWrapData (plainText)
    accountKeyData := helperWrapData (accountKey)

    proxyResult := C.vsce_phe_cipher_encrypt(obj.cCtx, plainTextData, accountKeyData, cipherTextBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return cipherTextBuf.getData(), nil
}

/*
* Decrypts data using account key
*/
func (obj *PheCipher) Decrypt(cipherText []byte, accountKey []byte) ([]byte, error) {
    plainTextBuf, plainTextBufErr := newBuffer(int(obj.DecryptLen(uint(len(cipherText)))))
    if plainTextBufErr != nil {
        return nil, plainTextBufErr
    }
    defer plainTextBuf.delete()
    cipherTextData := helperWrapData (cipherText)
    accountKeyData := helperWrapData (accountKey)

    proxyResult := C.vsce_phe_cipher_decrypt(obj.cCtx, cipherTextData, accountKeyData, plainTextBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return plainTextBuf.getData(), nil
}

/*
* Encrypts data (and authenticates additional data) using account key
*/
func (obj *PheCipher) AuthEncrypt(plainText []byte, additionalData []byte, accountKey []byte) ([]byte, error) {
    cipherTextBuf, cipherTextBufErr := newBuffer(int(obj.EncryptLen(uint(len(plainText)))))
    if cipherTextBufErr != nil {
        return nil, cipherTextBufErr
    }
    defer cipherTextBuf.delete()
    plainTextData := helperWrapData (plainText)
    additionalDataData := helperWrapData (additionalData)
    accountKeyData := helperWrapData (accountKey)

    proxyResult := C.vsce_phe_cipher_auth_encrypt(obj.cCtx, plainTextData, additionalDataData, accountKeyData, cipherTextBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return cipherTextBuf.getData(), nil
}

/*
* Decrypts data (and verifies additional data) using account key
*/
func (obj *PheCipher) AuthDecrypt(cipherText []byte, additionalData []byte, accountKey []byte) ([]byte, error) {
    plainTextBuf, plainTextBufErr := newBuffer(int(obj.DecryptLen(uint(len(cipherText)))))
    if plainTextBufErr != nil {
        return nil, plainTextBufErr
    }
    defer plainTextBuf.delete()
    cipherTextData := helperWrapData (cipherText)
    additionalDataData := helperWrapData (additionalData)
    accountKeyData := helperWrapData (accountKey)

    proxyResult := C.vsce_phe_cipher_auth_decrypt(obj.cCtx, cipherTextData, additionalDataData, accountKeyData, plainTextBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return plainTextBuf.getData(), nil
}
