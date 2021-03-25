package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Implementation of the symmetric cipher AES-256 bit in a GCM mode.
* Note, this implementation contains dynamic memory allocations,
* this should be improved in the future releases.
*/
type Aes256Gcm struct {
    cCtx *C.vscf_aes256_gcm_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *Aes256Gcm) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewAes256Gcm() *Aes256Gcm {
    ctx := C.vscf_aes256_gcm_new()
    obj := &Aes256Gcm {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Aes256Gcm).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAes256GcmWithCtx(pointer unsafe.Pointer) *Aes256Gcm {
    ctx := (*C.vscf_aes256_gcm_t /*ct10*/)(pointer)
    obj := &Aes256Gcm {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Aes256Gcm).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAes256GcmCopy(pointer unsafe.Pointer) *Aes256Gcm {
    ctx := (*C.vscf_aes256_gcm_t /*ct10*/)(pointer)
    obj := &Aes256Gcm {
        cCtx: C.vscf_aes256_gcm_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Aes256Gcm).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Aes256Gcm) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Aes256Gcm) delete() {
    C.vscf_aes256_gcm_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Aes256Gcm) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Aes256Gcm) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return ImplementationWrapAlgInfo(unsafe.Pointer(proxyResult)) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Aes256Gcm) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

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
func (obj *Aes256Gcm) Encrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptedLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_aes256_gcm_encrypt(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate required buffer length to hold the encrypted data.
*/
func (obj *Aes256Gcm) EncryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_encrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Precise length calculation of encrypted data.
*/
func (obj *Aes256Gcm) PreciseEncryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_precise_encrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Aes256Gcm) Decrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptedLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_aes256_gcm_decrypt(obj.cCtx, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate required buffer length to hold the decrypted data.
*/
func (obj *Aes256Gcm) DecryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_decrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
*/
func (obj *Aes256Gcm) GetNonceLen() uint {
    return 12
}

/*
* Cipher key length in bytes.
*/
func (obj *Aes256Gcm) GetKeyLen() uint {
    return 32
}

/*
* Cipher key length in bits.
*/
func (obj *Aes256Gcm) GetKeyBitlen() uint {
    return 256
}

/*
* Cipher block length in bytes.
*/
func (obj *Aes256Gcm) GetBlockLen() uint {
    return 16
}

/*
* Setup IV or nonce.
*/
func (obj *Aes256Gcm) SetNonce(nonce []byte) {
    nonceData := helperWrapData (nonce)

    C.vscf_aes256_gcm_set_nonce(obj.cCtx, nonceData)

    runtime.KeepAlive(obj)

    return
}

/*
* Set cipher encryption / decryption key.
*/
func (obj *Aes256Gcm) SetKey(key []byte) {
    keyData := helperWrapData (key)

    C.vscf_aes256_gcm_set_key(obj.cCtx, keyData)

    runtime.KeepAlive(obj)

    return
}

/*
* Start sequential encryption.
*/
func (obj *Aes256Gcm) StartEncryption() {
    C.vscf_aes256_gcm_start_encryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Start sequential decryption.
*/
func (obj *Aes256Gcm) StartDecryption() {
    C.vscf_aes256_gcm_start_decryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Process encryption or decryption of the given data chunk.
*/
func (obj *Aes256Gcm) Update(data []byte) []byte {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    C.vscf_aes256_gcm_update(obj.cCtx, dataData, outBuf.ctx)

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an current mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *Aes256Gcm) OutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an encryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *Aes256Gcm) EncryptedOutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_encrypted_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an decryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *Aes256Gcm) DecryptedOutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_decrypted_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Accomplish encryption or decryption process.
*/
func (obj *Aes256Gcm) Finish() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(0) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_aes256_gcm_finish(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Defines authentication tag length in bytes.
*/
func (obj *Aes256Gcm) GetAuthTagLen() uint {
    return 16
}

/*
* Encrypt given data.
* If 'tag' is not given, then it will written to the 'enc'.
*/
func (obj *Aes256Gcm) AuthEncrypt(data []byte, authData []byte) ([]byte, []byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.AuthEncryptedLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, nil, outBufErr
    }
    defer outBuf.delete()

    tagBuf, tagBufErr := newBuffer(int(obj.GetAuthTagLen() /* lg3 */))
    if tagBufErr != nil {
        return nil, nil, tagBufErr
    }
    defer tagBuf.delete()
    dataData := helperWrapData (data)
    authDataData := helperWrapData (authData)

    proxyResult := /*pr4*/C.vscf_aes256_gcm_auth_encrypt(obj.cCtx, dataData, authDataData, outBuf.ctx, tagBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, tagBuf.getData() /* r7 */, nil
}

/*
* Calculate required buffer length to hold the authenticated encrypted data.
*/
func (obj *Aes256Gcm) AuthEncryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_auth_encrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Decrypt given data.
* If 'tag' is not given, then it will be taken from the 'enc'.
*/
func (obj *Aes256Gcm) AuthDecrypt(data []byte, authData []byte, tag []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.AuthDecryptedLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)
    authDataData := helperWrapData (authData)
    tagData := helperWrapData (tag)

    proxyResult := /*pr4*/C.vscf_aes256_gcm_auth_decrypt(obj.cCtx, dataData, authDataData, tagData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate required buffer length to hold the authenticated decrypted data.
*/
func (obj *Aes256Gcm) AuthDecryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_gcm_auth_decrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Set additional data for for AEAD ciphers.
*/
func (obj *Aes256Gcm) SetAuthData(authData []byte) {
    authDataData := helperWrapData (authData)

    C.vscf_aes256_gcm_set_auth_data(obj.cCtx, authDataData)

    runtime.KeepAlive(obj)

    return
}

/*
* Accomplish an authenticated encryption and place tag separately.
*
* Note, if authentication tag should be added to an encrypted data,
* method "finish" can be used.
*/
func (obj *Aes256Gcm) FinishAuthEncryption() ([]byte, []byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(0) /* lg2 */))
    if outBufErr != nil {
        return nil, nil, outBufErr
    }
    defer outBuf.delete()

    tagBuf, tagBufErr := newBuffer(int(obj.GetAuthTagLen() /* lg3 */))
    if tagBufErr != nil {
        return nil, nil, tagBufErr
    }
    defer tagBuf.delete()


    proxyResult := /*pr4*/C.vscf_aes256_gcm_finish_auth_encryption(obj.cCtx, outBuf.ctx, tagBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, tagBuf.getData() /* r7 */, nil
}

/*
* Accomplish an authenticated decryption with explicitly given tag.
*
* Note, if authentication tag is a part of an encrypted data then,
* method "finish" can be used for simplicity.
*/
func (obj *Aes256Gcm) FinishAuthDecryption(tag []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.OutLen(0) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    tagData := helperWrapData (tag)

    proxyResult := /*pr4*/C.vscf_aes256_gcm_finish_auth_decryption(obj.cCtx, tagData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}
