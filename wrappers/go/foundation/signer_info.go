package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handle information about signer that is defined by an identifer and
* a Public Key.
*/
type SignerInfo struct {
    cCtx *C.vscf_signer_info_t /*ct2*/
}

/* Handle underlying C context. */
func (this SignerInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewSignerInfo () *SignerInfo {
    ctx := C.vscf_signer_info_new()
    return &SignerInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerInfoWithCtx (ctx *C.vscf_signer_info_t /*ct2*/) *SignerInfo {
    return &SignerInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerInfoCopy (ctx *C.vscf_signer_info_t /*ct2*/) *SignerInfo {
    return &SignerInfo {
        cCtx: C.vscf_signer_info_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this SignerInfo) clear () {
    C.vscf_signer_info_delete(this.cCtx)
}

/*
* Return signer identifier.
*/
func (this SignerInfo) SignerId () []byte {
    proxyResult := /*pr4*/C.vscf_signer_info_signer_id(this.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return algorithm information that was used for data signing.
*/
func (this SignerInfo) SignerAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_signer_info_signer_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return data signature.
*/
func (this SignerInfo) Signature () []byte {
    proxyResult := /*pr4*/C.vscf_signer_info_signature(this.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}
