package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handles a list of "signer info" class objects.
*/
type SignerInfoList struct {
    cCtx *C.vscf_signer_info_list_t /*ct2*/
}

/* Handle underlying C context. */
func (this SignerInfoList) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewSignerInfoList () *SignerInfoList {
    ctx := C.vscf_signer_info_list_new()
    return &SignerInfoList {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerInfoListWithCtx (ctx *C.vscf_signer_info_list_t /*ct2*/) *SignerInfoList {
    return &SignerInfoList {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerInfoListCopy (ctx *C.vscf_signer_info_list_t /*ct2*/) *SignerInfoList {
    return &SignerInfoList {
        cCtx: C.vscf_signer_info_list_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this SignerInfoList) close () {
    C.vscf_signer_info_list_delete(this.cCtx)
}

/*
* Return true if given list has item.
*/
func (this SignerInfoList) HasItem () bool {
    proxyResult := /*pr4*/C.vscf_signer_info_list_has_item(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (this SignerInfoList) Item () *SignerInfo {
    proxyResult := /*pr4*/C.vscf_signer_info_list_item(this.cCtx)

    return newSignerInfoWithCtx(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
*/
func (this SignerInfoList) HasNext () bool {
    proxyResult := /*pr4*/C.vscf_signer_info_list_has_next(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (this SignerInfoList) Next () *SignerInfoList {
    proxyResult := /*pr4*/C.vscf_signer_info_list_next(this.cCtx)

    return newSignerInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Return true if list has previous item.
*/
func (this SignerInfoList) HasPrev () bool {
    proxyResult := /*pr4*/C.vscf_signer_info_list_has_prev(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (this SignerInfoList) Prev () *SignerInfoList {
    proxyResult := /*pr4*/C.vscf_signer_info_list_prev(this.cCtx)

    return newSignerInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Remove all items.
*/
func (this SignerInfoList) Clear () {
    C.vscf_signer_info_list_clear(this.cCtx)

    return
}
