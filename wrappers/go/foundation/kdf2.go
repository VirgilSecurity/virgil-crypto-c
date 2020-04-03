package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Virgil Security implementation of the KDF2 (ISO-18033-2) algorithm.
*/
type Kdf2 struct {
    cCtx *C.vscf_kdf2_t /*ct10*/
}

func (obj *Kdf2) SetHash(hash Hash) {
    C.vscf_kdf2_release_hash(obj.cCtx)
    C.vscf_kdf2_use_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(hash.Ctx())))

    runtime.KeepAlive(hash)
    runtime.KeepAlive(obj)
}

/* Handle underlying C context. */
func (obj *Kdf2) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKdf2() *Kdf2 {
    ctx := C.vscf_kdf2_new()
    obj := &Kdf2 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Kdf2).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKdf2WithCtx(ctx *C.vscf_kdf2_t /*ct10*/) *Kdf2 {
    obj := &Kdf2 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Kdf2).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKdf2Copy(ctx *C.vscf_kdf2_t /*ct10*/) *Kdf2 {
    obj := &Kdf2 {
        cCtx: C.vscf_kdf2_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Kdf2).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Kdf2) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Kdf2) delete() {
    C.vscf_kdf2_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Kdf2) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_kdf2_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Kdf2) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_kdf2_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4.1 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Kdf2) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_kdf2_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return nil
}

/*
* Derive key of the requested length from the given data.
*/
func (obj *Kdf2) Derive(data []byte, keyLen uint) []byte {
    keyBuf, keyBufErr := newBuffer(int(keyLen))
    if keyBufErr != nil {
        return nil
    }
    defer keyBuf.delete()
    dataData := helperWrapData (data)

    C.vscf_kdf2_derive(obj.cCtx, dataData, (C.size_t)(keyLen)/*pa10*/, keyBuf.ctx)

    runtime.KeepAlive(obj)

    return keyBuf.getData() /* r7 */
}
