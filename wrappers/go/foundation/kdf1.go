package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Virgil Security implementation of the KDF1 (ISO-18033-2) algorithm.
*/
type Kdf1 struct {
    cCtx *C.vscf_kdf1_t /*ct10*/
}

func (obj *Kdf1) SetHash(hash Hash) {
    C.vscf_kdf1_release_hash(obj.cCtx)
    C.vscf_kdf1_use_hash(obj.cCtx, (*C.vscf_impl_t)(hash.ctx()))
}

/* Handle underlying C context. */
func (obj *Kdf1) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewKdf1() *Kdf1 {
    ctx := C.vscf_kdf1_new()
    obj := &Kdf1 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKdf1WithCtx(ctx *C.vscf_kdf1_t /*ct10*/) *Kdf1 {
    obj := &Kdf1 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKdf1Copy(ctx *C.vscf_kdf1_t /*ct10*/) *Kdf1 {
    obj := &Kdf1 {
        cCtx: C.vscf_kdf1_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Kdf1) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.clear()
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

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Kdf1) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_kdf1_produce_alg_info(obj.cCtx)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Kdf1) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_kdf1_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Derive key of the requested length from the given data.
*/
func (obj *Kdf1) Derive(data []byte, keyLen uint32) []byte {
    keyBuf, keyBufErr := bufferNewBuffer(int(keyLen))
    if keyBufErr != nil {
        return nil
    }
    defer keyBuf.Delete()
    dataData := helperWrapData (data)

    C.vscf_kdf1_derive(obj.cCtx, dataData, (C.size_t)(keyLen)/*pa10*/, keyBuf.ctx)

    return keyBuf.getData() /* r7 */
}
