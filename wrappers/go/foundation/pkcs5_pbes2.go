package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Virgil Security implementation of the PBES2 (RFC 8018) algorithm.
*/
type Pkcs5Pbes2 struct {
    cCtx *C.vscf_pkcs5_pbes2_t /*ct10*/
}

func (obj *Pkcs5Pbes2) SetKdf(kdf SaltedKdf) {
    C.vscf_pkcs5_pbes2_release_kdf(obj.cCtx)
    C.vscf_pkcs5_pbes2_use_kdf(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(kdf.Ctx())))

    runtime.KeepAlive(kdf)
    runtime.KeepAlive(obj)
}

func (obj *Pkcs5Pbes2) SetCipher(cipher Cipher) {
    C.vscf_pkcs5_pbes2_release_cipher(obj.cCtx)
    C.vscf_pkcs5_pbes2_use_cipher(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(cipher.Ctx())))

    runtime.KeepAlive(cipher)
    runtime.KeepAlive(obj)
}

/*
* Configure cipher with a new password.
*/
func (obj *Pkcs5Pbes2) Reset(pwd []byte) {
    pwdData := helperWrapData (pwd)

    C.vscf_pkcs5_pbes2_reset(obj.cCtx, pwdData)

    runtime.KeepAlive(obj)

    return
}

/* Handle underlying C context. */
func (obj *Pkcs5Pbes2) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewPkcs5Pbes2() *Pkcs5Pbes2 {
    ctx := C.vscf_pkcs5_pbes2_new()
    obj := &Pkcs5Pbes2 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Pkcs5Pbes2).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPkcs5Pbes2WithCtx(ctx *C.vscf_pkcs5_pbes2_t /*ct10*/) *Pkcs5Pbes2 {
    obj := &Pkcs5Pbes2 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Pkcs5Pbes2).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPkcs5Pbes2Copy(ctx *C.vscf_pkcs5_pbes2_t /*ct10*/) *Pkcs5Pbes2 {
    obj := &Pkcs5Pbes2 {
        cCtx: C.vscf_pkcs5_pbes2_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Pkcs5Pbes2).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Pkcs5Pbes2) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Pkcs5Pbes2) delete() {
    C.vscf_pkcs5_pbes2_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Pkcs5Pbes2) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbes2_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Pkcs5Pbes2) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbes2_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Pkcs5Pbes2) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbes2_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

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
func (obj *Pkcs5Pbes2) Encrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptedLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_pkcs5_pbes2_encrypt(obj.cCtx, dataData, outBuf.ctx)

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
func (obj *Pkcs5Pbes2) EncryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbes2_encrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Precise length calculation of encrypted data.
*/
func (obj *Pkcs5Pbes2) PreciseEncryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbes2_precise_encrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Decrypt given data.
*/
func (obj *Pkcs5Pbes2) Decrypt(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptedLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_pkcs5_pbes2_decrypt(obj.cCtx, dataData, outBuf.ctx)

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
func (obj *Pkcs5Pbes2) DecryptedLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbes2_decrypted_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}
