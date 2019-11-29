package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handle information about chained key algorithm.
*/
type ChainedKeyAlgInfo struct {
    cCtx *C.vscf_chained_key_alg_info_t /*ct10*/
}

/*
* Return algorithm information about l1 key.
*/
func (obj *ChainedKeyAlgInfo) L1KeyAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_chained_key_alg_info_l1_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Return algorithm information about l2 key.
*/
func (obj *ChainedKeyAlgInfo) L2KeyAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_chained_key_alg_info_l2_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *ChainedKeyAlgInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewChainedKeyAlgInfo() *ChainedKeyAlgInfo {
    ctx := C.vscf_chained_key_alg_info_new()
    obj := &ChainedKeyAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChainedKeyAlgInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChainedKeyAlgInfoWithCtx(ctx *C.vscf_chained_key_alg_info_t /*ct10*/) *ChainedKeyAlgInfo {
    obj := &ChainedKeyAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*ChainedKeyAlgInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newChainedKeyAlgInfoCopy(ctx *C.vscf_chained_key_alg_info_t /*ct10*/) *ChainedKeyAlgInfo {
    obj := &ChainedKeyAlgInfo {
        cCtx: C.vscf_chained_key_alg_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*ChainedKeyAlgInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *ChainedKeyAlgInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *ChainedKeyAlgInfo) delete() {
    C.vscf_chained_key_alg_info_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *ChainedKeyAlgInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_chained_key_alg_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}
