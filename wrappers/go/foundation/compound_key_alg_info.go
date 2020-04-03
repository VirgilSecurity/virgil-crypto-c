package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handle information about compound key algorithm.
*/
type CompoundKeyAlgInfo struct {
    cCtx *C.vscf_compound_key_alg_info_t /*ct10*/
}

/*
* Return information about encrypt/decrypt algorithm.
*/
func (obj *CompoundKeyAlgInfo) CipherAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_info_cipher_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult) /* r4 */
}

/*
* Return information about sign/verify algorithm.
*/
func (obj *CompoundKeyAlgInfo) SignerAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_info_signer_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *CompoundKeyAlgInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCompoundKeyAlgInfo() *CompoundKeyAlgInfo {
    ctx := C.vscf_compound_key_alg_info_new()
    obj := &CompoundKeyAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CompoundKeyAlgInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCompoundKeyAlgInfoWithCtx(ctx *C.vscf_compound_key_alg_info_t /*ct10*/) *CompoundKeyAlgInfo {
    obj := &CompoundKeyAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CompoundKeyAlgInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCompoundKeyAlgInfoCopy(ctx *C.vscf_compound_key_alg_info_t /*ct10*/) *CompoundKeyAlgInfo {
    obj := &CompoundKeyAlgInfo {
        cCtx: C.vscf_compound_key_alg_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*CompoundKeyAlgInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *CompoundKeyAlgInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *CompoundKeyAlgInfo) delete() {
    C.vscf_compound_key_alg_info_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *CompoundKeyAlgInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_compound_key_alg_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}
