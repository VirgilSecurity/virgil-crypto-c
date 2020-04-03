package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Virgil Security implementation of the KDF1 (ISO-18033-2) algorithm.
*/
type Kdf1 struct {
    cCtx *C.vscf_kdf1_t /*ct10*/
}

func (obj *Kdf1) SetHash(hash Hash) {
    C.vscf_kdf1_release_hash(obj.cCtx)
    C.vscf_kdf1_use_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(hash.Ctx())))

    runtime.KeepAlive(hash)
    runtime.KeepAlive(obj)
}

/* Handle underlying C context. */
func (obj *Kdf1) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKdf1() *Kdf1 {
    ctx := C.vscf_kdf1_new()
    obj := &Kdf1 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Kdf1).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKdf1WithCtx(ctx *C.vscf_kdf1_t /*ct10*/) *Kdf1 {
    obj := &Kdf1 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Kdf1).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKdf1Copy(ctx *C.vscf_kdf1_t /*ct10*/) *Kdf1 {
    obj := &Kdf1 {
        cCtx: C.vscf_kdf1_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Kdf1).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Kdf1) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Kdf1) delete() {
    C.vscf_kdf1_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Kdf1) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_kdf1_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Kdf1) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_kdf1_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Kdf1) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_kdf1_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

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
func (obj *Kdf1) Derive(data []byte, keyLen uint) []byte {
    keyBuf, keyBufErr := newBuffer(int(keyLen))
    if keyBufErr != nil {
        return nil
    }
    defer keyBuf.delete()
    dataData := helperWrapData (data)

    C.vscf_kdf1_derive(obj.cCtx, dataData, (C.size_t)(keyLen)/*pa10*/, keyBuf.ctx)

    runtime.KeepAlive(obj)

    return keyBuf.getData() /* r7 */
}
