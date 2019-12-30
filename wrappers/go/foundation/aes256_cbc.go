package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Implementation of the symmetric cipher AES-256 bit in a CBC mode.
* Note, this implementation contains dynamic memory allocations,
* this should be improved in the future releases.
*/
type Aes256Cbc struct {
    cCtx *C.vscf_aes256_cbc_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *Aes256Cbc) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewAes256Cbc() *Aes256Cbc {
    ctx := C.vscf_aes256_cbc_new()
    obj := &Aes256Cbc {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Aes256Cbc).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAes256CbcWithCtx(ctx *C.vscf_aes256_cbc_t /*ct10*/) *Aes256Cbc {
    obj := &Aes256Cbc {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Aes256Cbc).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAes256CbcCopy(ctx *C.vscf_aes256_cbc_t /*ct10*/) *Aes256Cbc {
    obj := &Aes256Cbc {
        cCtx: C.vscf_aes256_cbc_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Aes256Cbc).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Aes256Cbc) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Aes256Cbc) delete() {
    C.vscf_aes256_cbc_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Aes256Cbc) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Aes256Cbc) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Aes256Cbc) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

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
func (obj *Aes256Cbc) Encrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.EncryptedLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_aes256_cbc_encrypt(obj.cCtx, dataData, outBuf.ctx)

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
func (obj *Aes256Cbc) EncryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_encrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Precise length calculation of encrypted data.
*/
func (obj *Aes256Cbc) PreciseEncryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_precise_encrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Aes256Cbc) Decrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.DecryptedLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_aes256_cbc_decrypt(obj.cCtx, dataData, outBuf.ctx)

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
func (obj *Aes256Cbc) DecryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_decrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
*/
func (obj *Aes256Cbc) GetNonceLen() uint {
    return 16
}

/*
* Cipher key length in bytes.
*/
func (obj *Aes256Cbc) GetKeyLen() uint {
    return 32
}

/*
* Cipher key length in bits.
*/
func (obj *Aes256Cbc) GetKeyBitlen() uint {
    return 256
}

/*
* Cipher block length in bytes.
*/
func (obj *Aes256Cbc) GetBlockLen() uint {
    return 16
}

/*
* Setup IV or nonce.
*/
func (obj *Aes256Cbc) SetNonce(nonce []byte) {
    nonceData := helperWrapData (nonce)

    C.vscf_aes256_cbc_set_nonce(obj.cCtx, nonceData)

    runtime.KeepAlive(obj)

    return
}

/*
* Set cipher encryption / decryption key.
*/
func (obj *Aes256Cbc) SetKey(key []byte) {
    keyData := helperWrapData (key)

    C.vscf_aes256_cbc_set_key(obj.cCtx, keyData)

    runtime.KeepAlive(obj)

    return
}

/*
* Start sequential encryption.
*/
func (obj *Aes256Cbc) StartEncryption() {
    C.vscf_aes256_cbc_start_encryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Start sequential decryption.
*/
func (obj *Aes256Cbc) StartDecryption() {
    C.vscf_aes256_cbc_start_decryption(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Process encryption or decryption of the given data chunk.
*/
func (obj *Aes256Cbc) Update(data []byte) []byte {
    outBuf, outBufErr := bufferNewBuffer(int(obj.OutLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.Delete()
    dataData := helperWrapData (data)

    C.vscf_aes256_cbc_update(obj.cCtx, dataData, outBuf.ctx)

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an current mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *Aes256Cbc) OutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an encryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *Aes256Cbc) EncryptedOutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_encrypted_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return buffer length required to hold an output of the methods
* "update" or "finish" in an decryption mode.
* Pass zero length to define buffer length of the method "finish".
*/
func (obj *Aes256Cbc) DecryptedOutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_aes256_cbc_decrypted_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Accomplish encryption or decryption process.
*/
func (obj *Aes256Cbc) Finish() ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.OutLen(0) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_aes256_cbc_finish(obj.cCtx, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}
