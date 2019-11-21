package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Handle simple algorithm information (just id).
*/
type SimpleAlgInfo struct {
    cCtx *C.vscf_simple_alg_info_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *SimpleAlgInfo) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewSimpleAlgInfo() *SimpleAlgInfo {
    ctx := C.vscf_simple_alg_info_new()
    obj := &SimpleAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, func (o *SimpleAlgInfo) {o.Delete()})
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSimpleAlgInfoWithCtx(ctx *C.vscf_simple_alg_info_t /*ct10*/) *SimpleAlgInfo {
    obj := &SimpleAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, func (o *SimpleAlgInfo) {o.Delete()})
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSimpleAlgInfoCopy(ctx *C.vscf_simple_alg_info_t /*ct10*/) *SimpleAlgInfo {
    obj := &SimpleAlgInfo {
        cCtx: C.vscf_simple_alg_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, func (o *SimpleAlgInfo) {o.Delete()})
    return obj
}

/*
* Release underlying C context.
*/
func (obj *SimpleAlgInfo) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *SimpleAlgInfo) delete() {
    C.vscf_simple_alg_info_delete(obj.cCtx)
}

/*
* Create algorithm info with identificator.
*/
func NewSimpleAlgInfoWithAlgId(algId AlgId) *SimpleAlgInfo {
    proxyResult := /*pr4*/C.vscf_simple_alg_info_new_with_alg_id(C.vscf_alg_id_t(algId) /*pa7*/)

    obj := &SimpleAlgInfo {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, func (o *SimpleAlgInfo) {o.Delete()})
    return obj
}

/*
* Provide algorithm identificator.
*/
func (obj *SimpleAlgInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_simple_alg_info_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}
