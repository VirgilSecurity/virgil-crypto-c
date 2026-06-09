package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Implementation of AES-256 Key Wrap algorithm (RFC 3394).
*/
type Aes256Kw struct {
    cCtx *C.vscf_aes256_kw_t
}

/* Handle underlying C context. */
func (obj *Aes256Kw) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewAes256Kw() *Aes256Kw {
    ctx := C.vscf_aes256_kw_new()
    obj := &Aes256Kw {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Aes256Kw).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAes256KwWithCtx(ctx *C.vscf_aes256_kw_t) *Aes256Kw {
    obj := &Aes256Kw {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Aes256Kw).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAes256KwCopy(ctx *C.vscf_aes256_kw_t) *Aes256Kw {
    obj := &Aes256Kw {
        cCtx: C.vscf_aes256_kw_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Aes256Kw).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Aes256Kw) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Aes256Kw) delete() {
    C.vscf_aes256_kw_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Aes256Kw) AlgId() AlgId {
    proxyResult := C.vscf_aes256_kw_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult)
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Aes256Kw) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := C.vscf_aes256_kw_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult)
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Aes256Kw) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := C.vscf_aes256_kw_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return nil
}

/*
* Return buffer length required to hold a wrapped key for the given plain key length.
*/
func (obj *Aes256Kw) WrappedLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_kw_wrapped_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Return buffer length required to hold an unwrapped key for the given wrapped key length.
*/
func (obj *Aes256Kw) UnwrappedLen(dataLen uint) uint {
    proxyResult := C.vscf_aes256_kw_unwrapped_len(obj.cCtx, (C.size_t)(dataLen))

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Wrap given key data using the Key Encryption Key (KEK).
*/
func (obj *Aes256Kw) Wrap(kek []byte, data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.WrappedLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    kekData := helperWrapData (kek)
    dataData := helperWrapData (data)

    proxyResult := C.vscf_aes256_kw_wrap(obj.cCtx, kekData, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}

/*
* Unwrap given key data using the Key Encryption Key (KEK).
*/
func (obj *Aes256Kw) Unwrap(kek []byte, data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.UnwrappedLen(uint(len(data)))))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    kekData := helperWrapData (kek)
    dataData := helperWrapData (data)

    proxyResult := C.vscf_aes256_kw_unwrap(obj.cCtx, kekData, dataData, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData(), nil
}
