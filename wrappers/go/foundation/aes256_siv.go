package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Implementation of AES-256-SIV deterministic authenticated encryption (RFC 5297).
*
* WARNING: SIV is a deterministic AEAD. Equal (key, associated data, plaintext)
* inputs always produce equal ciphertext, so it intentionally leaks plaintext
* equality. A key shared across isolation domains (e.g. tenants) leaks equality
* across them: use a unique key per domain and/or include a domain-specific value
* in the associated data. Do not assume IND-CPA semantics.
*/
type Aes256Siv struct {
    cCtx *C.vscf_aes256_siv_t
}

/* Handle underlying C context. */
func (obj *Aes256Siv) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewAes256Siv() *Aes256Siv {
    ctx := C.vscf_aes256_siv_new()
    obj := &Aes256Siv {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Aes256Siv).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAes256SivWithCtx(ctx *C.vscf_aes256_siv_t) *Aes256Siv {
    obj := &Aes256Siv {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Aes256Siv).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAes256SivCopy(ctx *C.vscf_aes256_siv_t) *Aes256Siv {
    obj := &Aes256Siv {
        cCtx: C.vscf_aes256_siv_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Aes256Siv).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Aes256Siv) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Aes256Siv) delete() {
    C.vscf_aes256_siv_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Aes256Siv) AlgId() AlgId {
    proxyResult := C.vscf_aes256_siv_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult)
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Aes256Siv) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := C.vscf_aes256_siv_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult)
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Aes256Siv) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := C.vscf_aes256_siv_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return nil
}

/*
* Encrypt given data.
*/
func (obj *Aes256Siv) Encrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptedLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := C.vscf_aes256_siv_encrypt(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Aes256Siv) EncryptedLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_siv_encrypted_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Precise length calculation of encrypted data.
*/
func (obj *Aes256Siv) PreciseEncryptedLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_siv_precise_encrypted_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Decrypt given data.
*/
func (obj *Aes256Siv) Decrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptedLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := C.vscf_aes256_siv_decrypt(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Aes256Siv) DecryptedLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_siv_decrypted_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
*/
func (obj *Aes256Siv) GetNonceLen() uint {
    return 0
}

/*
* Cipher key length in bytes.
*/
func (obj *Aes256Siv) GetKeyLen() uint {
    return 64
}

/*
* Cipher key length in bits.
*/
func (obj *Aes256Siv) GetKeyBitlen() uint {
    return 512
}

/*
* Cipher block length in bytes.
*/
func (obj *Aes256Siv) GetBlockLen() uint {
    return 16
}

/*
* Setup IV or nonce.
*/
func (obj *Aes256Siv) SetNonce(nonce []byte) {
    nonceData := helperWrapData (nonce)

    C.vscf_aes256_siv_set_nonce(obj.cCtx, nonceData)

    runtime.KeepAlive(obj)

    return
}

/*
* Set cipher encryption / decryption key.
*/
func (obj *Aes256Siv) SetKey(key []byte) {
    keyData := helperWrapData (key)

    C.vscf_aes256_siv_set_key(obj.cCtx, keyData)

    runtime.KeepAlive(obj)

    return
}

/*
* Start sequential encryption.
*/
func (obj *Aes256Siv) StartEncryption() {
    C.vscf_aes256_siv_start_encryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Start sequential decryption.
*/
func (obj *Aes256Siv) StartDecryption() {
    C.vscf_aes256_siv_start_decryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Process encryption or decryption of the given data chunk.
*/
func (obj *Aes256Siv) Update(data []byte) []byte {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(uint(len(data)))))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    C.vscf_aes256_siv_update(obj.cCtx, dataData, outBuf.ctx)

    runtime.KeepAlive(obj)

    return outBuf.getData()
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an current mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *Aes256Siv) OutLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_siv_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an encryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *Aes256Siv) EncryptedOutLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_siv_encrypted_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an decryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *Aes256Siv) DecryptedOutLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_siv_decrypted_out_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Accomplish encryption or decryption process.
*/
func (obj *Aes256Siv) Finish() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(0)))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := C.vscf_aes256_siv_finish(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Defines authentication tag length in bytes.
*/
func (obj *Aes256Siv) GetAuthTagLen() uint {
    return 16
}

/*
* Encrypt given data.
* If 'tag' is not given, then it will written to the 'enc'.
*/
func (obj *Aes256Siv) AuthEncrypt(data []byte, authData []byte) ([]byte, []byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.AuthEncryptedLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, nil, outBufErr
    }
    defer outBuf.delete()

    tagBuf, tagBufErr := newBuffer(int(obj.GetAuthTagLen()))
    if tagBufErr != nil {
        return nil, nil, tagBufErr
    }
    defer tagBuf.delete()
    dataData := helperWrapData (data)
    authDataData := helperWrapData (authData)

    proxyResult := C.vscf_aes256_siv_auth_encrypt(obj.cCtx, dataData, authDataData, outBuf.ctx, tagBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), tagBuf.getData(), nil
}

/*
* Calculate required buffer length to hold the authenticated encrypted data.
*/
func (obj *Aes256Siv) AuthEncryptedLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_siv_auth_encrypted_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Decrypt given data.
* If 'tag' is not given, then it will be taken from the 'enc'.
*/
func (obj *Aes256Siv) AuthDecrypt(data []byte, authData []byte, tag []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.AuthDecryptedLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)
    authDataData := helperWrapData (authData)
    tagData := helperWrapData (tag)

    proxyResult := C.vscf_aes256_siv_auth_decrypt(obj.cCtx, dataData, authDataData, tagData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Calculate required buffer length to hold the authenticated decrypted data.
*/
func (obj *Aes256Siv) AuthDecryptedLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_siv_auth_decrypted_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Set additional data for for AEAD ciphers.
*/
func (obj *Aes256Siv) SetAuthData(authData []byte) {
    authDataData := helperWrapData (authData)

    C.vscf_aes256_siv_set_auth_data(obj.cCtx, authDataData)

    runtime.KeepAlive(obj)

    return
}

/*
* Accomplish an authenticated encryption and place tag separately.
*
* Note, if authentication tag should be added to an encrypted data,
* method "finish" can be used.
*/
func (obj *Aes256Siv) FinishAuthEncryption() ([]byte, []byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(0)))
    if outBufErr != nil {
        return nil, nil, outBufErr
    }
    defer outBuf.delete()

    tagBuf, tagBufErr := newBuffer(int(obj.GetAuthTagLen()))
    if tagBufErr != nil {
        return nil, nil, tagBufErr
    }
    defer tagBuf.delete()


    proxyResult := C.vscf_aes256_siv_finish_auth_encryption(obj.cCtx, outBuf.ctx, tagBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), tagBuf.getData(), nil
}

/*
* Accomplish an authenticated decryption with explicitly given tag.
*
* Note, if authentication tag is a part of an encrypted data then,
* method "finish" can be used for simplicity.
*/
func (obj *Aes256Siv) FinishAuthDecryption(tag []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(0)))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    tagData := helperWrapData (tag)

    proxyResult := C.vscf_aes256_siv_finish_auth_decryption(obj.cCtx, tagData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}
