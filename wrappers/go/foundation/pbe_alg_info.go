package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


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

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Return cipher algorithm information.
*/
func (obj *PbeAlgInfo) CipherAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_pbe_alg_info_cipher_alg_info(obj.cCtx)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *PbeAlgInfo) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewPbeAlgInfo() *PbeAlgInfo {
    ctx := C.vscf_pbe_alg_info_new()
    obj := &PbeAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPbeAlgInfoWithCtx(ctx *C.vscf_pbe_alg_info_t /*ct10*/) *PbeAlgInfo {
    obj := &PbeAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPbeAlgInfoCopy(ctx *C.vscf_pbe_alg_info_t /*ct10*/) *PbeAlgInfo {
    obj := &PbeAlgInfo {
        cCtx: C.vscf_pbe_alg_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *PbeAlgInfo) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.clear()
}

/*
* Release underlying C context.
*/
func (obj *PbeAlgInfo) delete() {
    C.vscf_pbe_alg_info_delete(obj.cCtx)
}

/*
* Create algorithm info with identificator, KDF algorithm info and
* cipher alg info.
*/
func NewPbeAlgInfoWithMembers(algId AlgId, kdfAlgInfo AlgInfo, cipherAlgInfo AlgInfo) *PbeAlgInfo {
    kdfAlgInfoCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(kdfAlgInfo.ctx()))
    cipherAlgInfoCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(cipherAlgInfo.ctx()))

    proxyResult := /*pr4*/C.vscf_pbe_alg_info_new_with_members(C.vscf_alg_id_t(algId) /*pa7*/, &kdfAlgInfoCopy, &cipherAlgInfoCopy)

    obj := &PbeAlgInfo {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Provide algorithm identificator.
*/
func (obj *PbeAlgInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_pbe_alg_info_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}
