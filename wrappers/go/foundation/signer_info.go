package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Handle information about signer that is defined by an identifer and
* a Public Key.
*/
type SignerInfo struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this SignerInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSignerInfo () *SignerInfo {
    ctx := C.vscf_signer_info_new()
    return &SignerInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignerInfoWithCtx (ctx *C.vscf_impl_t) *SignerInfo {
    return &SignerInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignerInfoCopy (ctx *C.vscf_impl_t) *SignerInfo {
    return &SignerInfo {
        ctx: C.vscf_signer_info_shallow_copy(ctx),
    }
}

/*
* Return signer identifier.
*/
func (this SignerInfo) SignerId () []byte {
    proxyResult := C.vscf_signer_info_signer_id(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Return algorithm information that was used for data signing.
*/
func (this SignerInfo) SignerAlgInfo () IAlgInfo {
    proxyResult := C.vscf_signer_info_signer_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return data signature.
*/
func (this SignerInfo) Signature () []byte {
    proxyResult := C.vscf_signer_info_signature(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}
