package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handle information about signer that is defined by an identifer and
* a Public Key.
*/
type SignerInfo struct {
    cCtx *C.vscf_signer_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *SignerInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewSignerInfo() *SignerInfo {
    ctx := C.vscf_signer_info_new()
    obj := &SignerInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*SignerInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerInfoWithCtx(ctx *C.vscf_signer_info_t /*ct2*/) *SignerInfo {
    obj := &SignerInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*SignerInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerInfoCopy(ctx *C.vscf_signer_info_t /*ct2*/) *SignerInfo {
    obj := &SignerInfo {
        cCtx: C.vscf_signer_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*SignerInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *SignerInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *SignerInfo) delete() {
    C.vscf_signer_info_delete(obj.cCtx)
}

/*
* Return signer identifier.
*/
func (obj *SignerInfo) SignerId() []byte {
    proxyResult := /*pr4*/C.vscf_signer_info_signer_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return algorithm information that was used for data signing.
*/
func (obj *SignerInfo) SignerAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_signer_info_signer_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult) /* r4.1 */
}

/*
* Return data signature.
*/
func (obj *SignerInfo) Signature() []byte {
    proxyResult := /*pr4*/C.vscf_signer_info_signature(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}
