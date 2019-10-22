package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Handle message signatures and related information.
*/
type MessageInfoFooter struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this MessageInfoFooter) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewMessageInfoFooter () *MessageInfoFooter {
    ctx := C.vscf_message_info_footer_new()
    return &MessageInfoFooter {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoFooterWithCtx (ctx *C.vscf_impl_t) *MessageInfoFooter {
    return &MessageInfoFooter {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoFooterCopy (ctx *C.vscf_impl_t) *MessageInfoFooter {
    return &MessageInfoFooter {
        ctx: C.vscf_message_info_footer_shallow_copy(ctx),
    }
}

/*
* Return true if at least one signer info presents.
*/
func (this MessageInfoFooter) HasSignerInfos () bool {
    proxyResult := C.vscf_message_info_footer_has_signer_infos(this.ctx)

    return proxyResult //r9
}

/*
* Return list with a "signer info" elements.
*/
func (this MessageInfoFooter) SignerInfos () SignerInfoList {
    proxyResult := C.vscf_message_info_footer_signer_infos(this.ctx)

    return SignerInfoList(proxyResult) /* r5 */
}

/*
* Return information about algorithm that was used for data hashing.
*/
func (this MessageInfoFooter) SignerHashAlgInfo () IAlgInfo {
    proxyResult := C.vscf_message_info_footer_signer_hash_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return plain text digest that was used to produce signature.
*/
func (this MessageInfoFooter) SignerDigest () []byte {
    proxyResult := C.vscf_message_info_footer_signer_digest(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}
