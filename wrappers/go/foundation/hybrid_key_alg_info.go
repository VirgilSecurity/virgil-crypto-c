package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handle information about hybrid key algorithm.
*/
type HybridKeyAlgInfo struct {
    cCtx *C.vscf_hybrid_key_alg_info_t /*ct10*/
}

/*
* Return algorithm information about the first key.
*/
func (obj *HybridKeyAlgInfo) FirstKeyAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_info_first_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4.1 */
}

/*
* Return algorithm information about the second key.
*/
func (obj *HybridKeyAlgInfo) SecondKeyAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_info_second_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4.1 */
}

/* Handle underlying C context. */
func (obj *HybridKeyAlgInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHybridKeyAlgInfo() *HybridKeyAlgInfo {
    ctx := C.vscf_hybrid_key_alg_info_new()
    obj := &HybridKeyAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HybridKeyAlgInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHybridKeyAlgInfoWithCtx(ctx *C.vscf_hybrid_key_alg_info_t /*ct10*/) *HybridKeyAlgInfo {
    obj := &HybridKeyAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HybridKeyAlgInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHybridKeyAlgInfoCopy(ctx *C.vscf_hybrid_key_alg_info_t /*ct10*/) *HybridKeyAlgInfo {
    obj := &HybridKeyAlgInfo {
        cCtx: C.vscf_hybrid_key_alg_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*HybridKeyAlgInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *HybridKeyAlgInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *HybridKeyAlgInfo) delete() {
    C.vscf_hybrid_key_alg_info_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *HybridKeyAlgInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_hybrid_key_alg_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}
