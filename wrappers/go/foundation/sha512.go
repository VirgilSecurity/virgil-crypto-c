package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* This is MbedTLS implementation of SHA512.
*/
type Sha512 struct {
    cCtx *C.vscf_sha512_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *Sha512) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewSha512() *Sha512 {
    ctx := C.vscf_sha512_new()
    obj := &Sha512 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Sha512).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha512WithCtx(ctx *C.vscf_sha512_t /*ct10*/) *Sha512 {
    obj := &Sha512 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Sha512).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha512Copy(ctx *C.vscf_sha512_t /*ct10*/) *Sha512 {
    obj := &Sha512 {
        cCtx: C.vscf_sha512_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Sha512).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Sha512) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Sha512) delete() {
    C.vscf_sha512_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Sha512) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_sha512_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Sha512) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_sha512_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Sha512) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_sha512_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

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
func (obj *Sha512) GetDigestLen() int {
    return 64
}

/*
* Block length of the digest function in bytes.
*/
func (obj *Sha512) GetBlockLen() int {
    return 128
}

/*
* Calculate hash over given data.
*/
func (obj *Sha512) Hash(data []byte) []byte {
    digestBuf, digestBufErr := bufferNewBuffer(int(obj.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.Delete()
    dataData := helperWrapData (data)

    C.vscf_sha512_hash(dataData, digestBuf.ctx)

    runtime.KeepAlive(obj)

    return digestBuf.getData() /* r7 */
}

/*
* Start a new hashing.
*/
func (obj *Sha512) Start() {
    C.vscf_sha512_start(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Add given data to the hash.
*/
func (obj *Sha512) Update(data []byte) {
    dataData := helperWrapData (data)

    C.vscf_sha512_update(obj.cCtx, dataData)

    runtime.KeepAlive(obj)

    return
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (obj *Sha512) Finish() []byte {
    digestBuf, digestBufErr := bufferNewBuffer(int(obj.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.Delete()


    C.vscf_sha512_finish(obj.cCtx, digestBuf.ctx)

    runtime.KeepAlive(obj)

    return digestBuf.getData() /* r7 */
}
