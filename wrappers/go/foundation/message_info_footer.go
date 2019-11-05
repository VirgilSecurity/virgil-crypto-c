package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handle message signatures and related information.
*/
type MessageInfoFooter struct {
    cCtx *C.vscf_message_info_footer_t /*ct2*/
}

/* Handle underlying C context. */
func (this MessageInfoFooter) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewMessageInfoFooter () *MessageInfoFooter {
    ctx := C.vscf_message_info_footer_new()
    return &MessageInfoFooter {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoFooterWithCtx (ctx *C.vscf_message_info_footer_t /*ct2*/) *MessageInfoFooter {
    return &MessageInfoFooter {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoFooterCopy (ctx *C.vscf_message_info_footer_t /*ct2*/) *MessageInfoFooter {
    return &MessageInfoFooter {
        cCtx: C.vscf_message_info_footer_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this MessageInfoFooter) clear () {
    C.vscf_message_info_footer_delete(this.cCtx)
}

/*
* Return true if at least one signer info presents.
*/
func (this MessageInfoFooter) HasSignerInfos () bool {
    proxyResult := /*pr4*/C.vscf_message_info_footer_has_signer_infos(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return list with a "signer info" elements.
*/
func (this MessageInfoFooter) SignerInfos () *SignerInfoList {
    proxyResult := /*pr4*/C.vscf_message_info_footer_signer_infos(this.cCtx)

    return newSignerInfoListWithCtx(proxyResult) /* r5 */
}

/*
* Return information about algorithm that was used for data hashing.
*/
func (this MessageInfoFooter) SignerHashAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_message_info_footer_signer_hash_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return plain text digest that was used to produce signature.
*/
func (this MessageInfoFooter) SignerDigest () []byte {
    proxyResult := /*pr4*/C.vscf_message_info_footer_signer_digest(this.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}
