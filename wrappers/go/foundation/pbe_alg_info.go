package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handle information about password-based encryption algorithm.
*/
type PbeAlgInfo struct {
    cCtx *C.vscf_pbe_alg_info_t /*ct10*/
}

/*
* Return KDF algorithm information.
*/
func (obj *PbeAlgInfo) KdfAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_pbe_alg_info_kdf_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return ImplementationWrapAlgInfoCopy(unsafe.Pointer(proxyResult)) /* r4.1 */
}

/*
* Return cipher algorithm information.
*/
func (obj *PbeAlgInfo) CipherAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_pbe_alg_info_cipher_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return ImplementationWrapAlgInfoCopy(unsafe.Pointer(proxyResult)) /* r4.1 */
}

/* Handle underlying C context. */
func (obj *PbeAlgInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewPbeAlgInfo() *PbeAlgInfo {
    ctx := C.vscf_pbe_alg_info_new()
    obj := &PbeAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*PbeAlgInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPbeAlgInfoWithCtx(pointer unsafe.Pointer) *PbeAlgInfo {
    ctx := (*C.vscf_pbe_alg_info_t /*ct10*/)(pointer)
    obj := &PbeAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*PbeAlgInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPbeAlgInfoCopy(pointer unsafe.Pointer) *PbeAlgInfo {
    ctx := (*C.vscf_pbe_alg_info_t /*ct10*/)(pointer)
    obj := &PbeAlgInfo {
        cCtx: C.vscf_pbe_alg_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*PbeAlgInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *PbeAlgInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *PbeAlgInfo) delete() {
    C.vscf_pbe_alg_info_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *PbeAlgInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_pbe_alg_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}
