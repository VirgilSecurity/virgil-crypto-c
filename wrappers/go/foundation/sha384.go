package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* This is MbedTLS implementation of SHA384.
*/
type Sha384 struct {
    cCtx *C.vscf_sha384_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *Sha384) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewSha384() *Sha384 {
    ctx := C.vscf_sha384_new()
    obj := &Sha384 {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *Sha384) {o.Delete()})
    runtime.SetFinalizer(obj, (*Sha384).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha384WithCtx(ctx *C.vscf_sha384_t /*ct10*/) *Sha384 {
    obj := &Sha384 {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *Sha384) {o.Delete()})
    runtime.SetFinalizer(obj, (*Sha384).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha384Copy(ctx *C.vscf_sha384_t /*ct10*/) *Sha384 {
    obj := &Sha384 {
        cCtx: C.vscf_sha384_shallow_copy(ctx),
    }
    //runtime.SetFinalizer(obj, func (o *Sha384) {o.Delete()})
    runtime.SetFinalizer(obj, (*Sha384).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Sha384) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Sha384) delete() {
    C.vscf_sha384_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Sha384) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_sha384_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Sha384) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_sha384_produce_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Sha384) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_sha384_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

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
func (obj *Sha384) GetDigestLen() uint32 {
    return 48
}

/*
* Block length of the digest function in bytes.
*/
func (obj *Sha384) GetBlockLen() uint32 {
    return 128
}

/*
* Calculate hash over given data.
*/
func (obj *Sha384) Hash(data []byte) []byte {
    digestBuf, digestBufErr := bufferNewBuffer(int(obj.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.Delete()
    dataData := helperWrapData (data)

    C.vscf_sha384_hash(dataData, digestBuf.ctx)

    runtime.KeepAlive(obj)

    return digestBuf.getData() /* r7 */
}

/*
* Start a new hashing.
*/
func (obj *Sha384) Start() {
    C.vscf_sha384_start(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Add given data to the hash.
*/
func (obj *Sha384) Update(data []byte) {
    dataData := helperWrapData (data)

    C.vscf_sha384_update(obj.cCtx, dataData)

    runtime.KeepAlive(obj)

    return
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (obj *Sha384) Finish() []byte {
    digestBuf, digestBufErr := bufferNewBuffer(int(obj.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.Delete()


    C.vscf_sha384_finish(obj.cCtx, digestBuf.ctx)

    runtime.KeepAlive(obj)

    return digestBuf.getData() /* r7 */
}
