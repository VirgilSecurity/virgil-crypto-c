package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Handle message signatures and related information.
*/
type MessageInfoFooter struct {
    cCtx *C.vscf_message_info_footer_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessageInfoFooter) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewMessageInfoFooter() *MessageInfoFooter {
    ctx := C.vscf_message_info_footer_new()
    obj := &MessageInfoFooter {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoFooterWithCtx(ctx *C.vscf_message_info_footer_t /*ct2*/) *MessageInfoFooter {
    obj := &MessageInfoFooter {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoFooterCopy(ctx *C.vscf_message_info_footer_t /*ct2*/) *MessageInfoFooter {
    obj := &MessageInfoFooter {
        cCtx: C.vscf_message_info_footer_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessageInfoFooter) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.clear()
}

/*
* Release underlying C context.
*/
func (obj *MessageInfoFooter) delete() {
    C.vscf_message_info_footer_delete(obj.cCtx)
}

/*
* Return true if at least one signer info presents.
*/
func (obj *MessageInfoFooter) HasSignerInfos() bool {
    proxyResult := /*pr4*/C.vscf_message_info_footer_has_signer_infos(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return list with a "signer info" elements.
*/
func (obj *MessageInfoFooter) SignerInfos() *SignerInfoList {
    proxyResult := /*pr4*/C.vscf_message_info_footer_signer_infos(obj.cCtx)

    return newSignerInfoListWithCtx(proxyResult) /* r5 */
}

/*
* Return information about algorithm that was used for data hashing.
*/
func (obj *MessageInfoFooter) SignerHashAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_message_info_footer_signer_hash_alg_info(obj.cCtx)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Return plain text digest that was used to produce signature.
*/
func (obj *MessageInfoFooter) SignerDigest() []byte {
    proxyResult := /*pr4*/C.vscf_message_info_footer_signer_digest(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}
