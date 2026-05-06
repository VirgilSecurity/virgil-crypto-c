package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handle information about password-based encryption algorithm.
*/
type PbeAlgInfo struct {
    cCtx *C.vscf_pbe_alg_info_t
}

/*
* Return KDF algorithm information.
*/
func (obj *PbeAlgInfo) KdfAlgInfo() (AlgInfo, error) {
    proxyResult := C.vscf_pbe_alg_info_kdf_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult)
}

/*
* Return cipher algorithm information.
*/
func (obj *PbeAlgInfo) CipherAlgInfo() (AlgInfo, error) {
    proxyResult := C.vscf_pbe_alg_info_cipher_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult)
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
func newPbeAlgInfoWithCtx(ctx *C.vscf_pbe_alg_info_t) *PbeAlgInfo {
    obj := &PbeAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*PbeAlgInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPbeAlgInfoCopy(ctx *C.vscf_pbe_alg_info_t) *PbeAlgInfo {
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
    proxyResult := C.vscf_pbe_alg_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult)
}
