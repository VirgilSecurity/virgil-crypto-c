package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* This is MbedTLS implementation of SHA256.
*/
type Sha256 struct {
    cCtx *C.vscf_sha256_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *Sha256) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewSha256() *Sha256 {
    ctx := C.vscf_sha256_new()
    obj := &Sha256 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Sha256).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha256WithCtx(ctx *C.vscf_sha256_t /*ct10*/) *Sha256 {
    obj := &Sha256 {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Sha256).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha256Copy(ctx *C.vscf_sha256_t /*ct10*/) *Sha256 {
    obj := &Sha256 {
        cCtx: C.vscf_sha256_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Sha256).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Sha256) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Sha256) delete() {
    C.vscf_sha256_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Sha256) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_sha256_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Sha256) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_sha256_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Sha256) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_sha256_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

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
func (obj *Sha256) GetDigestLen() uint32 {
    return 32
}

/*
* Block length of the digest function in bytes.
*/
func (obj *Sha256) GetBlockLen() uint32 {
    return 64
}

/*
* Calculate hash over given data.
*/
func (obj *Sha256) Hash(data []byte) []byte {
    digestBuf, digestBufErr := bufferNewBuffer(int(obj.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.Delete()
    dataData := helperWrapData (data)

    C.vscf_sha256_hash(dataData, digestBuf.ctx)

    runtime.KeepAlive(obj)

    return digestBuf.getData() /* r7 */
}

/*
* Start a new hashing.
*/
func (obj *Sha256) Start() {
    C.vscf_sha256_start(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Add given data to the hash.
*/
func (obj *Sha256) Update(data []byte) {
    dataData := helperWrapData (data)

    C.vscf_sha256_update(obj.cCtx, dataData)

    runtime.KeepAlive(obj)

    return
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (obj *Sha256) Finish() []byte {
    digestBuf, digestBufErr := bufferNewBuffer(int(obj.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.Delete()


    C.vscf_sha256_finish(obj.cCtx, digestBuf.ctx)

    runtime.KeepAlive(obj)

    return digestBuf.getData() /* r7 */
}
