package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handle hashed based algorithm information, i.e. HKDF, HMAC, etc.
*/
type HashBasedAlgInfo struct {
    cCtx *C.vscf_hash_based_alg_info_t /*ct10*/
}

/*
* Return hash algorithm information.
*/
func (obj *HashBasedAlgInfo) HashAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_hash_based_alg_info_hash_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *HashBasedAlgInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHashBasedAlgInfo() *HashBasedAlgInfo {
    ctx := C.vscf_hash_based_alg_info_new()
    obj := &HashBasedAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HashBasedAlgInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHashBasedAlgInfoWithCtx(ctx *C.vscf_hash_based_alg_info_t /*ct10*/) *HashBasedAlgInfo {
    obj := &HashBasedAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HashBasedAlgInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHashBasedAlgInfoCopy(ctx *C.vscf_hash_based_alg_info_t /*ct10*/) *HashBasedAlgInfo {
    obj := &HashBasedAlgInfo {
        cCtx: C.vscf_hash_based_alg_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*HashBasedAlgInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *HashBasedAlgInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *HashBasedAlgInfo) delete() {
    C.vscf_hash_based_alg_info_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *HashBasedAlgInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_hash_based_alg_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}
