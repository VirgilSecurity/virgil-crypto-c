package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* This is MbedTLS implementation of SHA224.
*/
type Sha224 struct {
    cCtx *C.vscf_sha224_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *Sha224) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewSha224() *Sha224 {
    ctx := C.vscf_sha224_new()
    obj := &Sha224 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Sha224).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha224WithCtx(ctx *C.vscf_sha224_t /*ct10*/) *Sha224 {
    obj := &Sha224 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Sha224).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha224Copy(ctx *C.vscf_sha224_t /*ct10*/) *Sha224 {
    obj := &Sha224 {
        cCtx: C.vscf_sha224_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Sha224).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Sha224) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Sha224) delete() {
    C.vscf_sha224_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Sha224) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_sha224_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Sha224) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_sha224_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4.1 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Sha224) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_sha224_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(algInfo)

    return nil
}

/*
* Length of the digest (hashing output) in bytes.
*/
func (obj *Sha224) GetDigestLen() uint {
    return 28
}

/*
* Block length of the digest function in bytes.
*/
func (obj *Sha224) GetBlockLen() uint {
    return 64
}

/*
* Calculate hash over given data.
*/
func (obj *Sha224) Hash(data []byte) []byte {
    digestBuf, digestBufErr := newBuffer(int(obj.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.delete()
    dataData := helperWrapData (data)

    C.vscf_sha224_hash(dataData, digestBuf.ctx)

    runtime.KeepAlive(obj)

    return digestBuf.getData() /* r7 */
}

/*
* Start a new hashing.
*/
func (obj *Sha224) Start() {
    C.vscf_sha224_start(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Add given data to the hash.
*/
func (obj *Sha224) Update(data []byte) {
    dataData := helperWrapData (data)

    C.vscf_sha224_update(obj.cCtx, dataData)

    runtime.KeepAlive(obj)

    return
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (obj *Sha224) Finish() []byte {
    digestBuf, digestBufErr := newBuffer(int(obj.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.delete()


    C.vscf_sha224_finish(obj.cCtx, digestBuf.ctx)

    runtime.KeepAlive(obj)

    return digestBuf.getData() /* r7 */
}
