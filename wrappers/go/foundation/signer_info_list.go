package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"

/*
* Handles a list of "signer info" class objects.
*/
type SignerInfoList struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this SignerInfoList) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSignerInfoList () *SignerInfoList {
    ctx := C.vscf_signer_info_list_new()
    return &SignerInfoList {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignerInfoListWithCtx (ctx *C.vscf_impl_t) *SignerInfoList {
    return &SignerInfoList {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignerInfoListCopy (ctx *C.vscf_impl_t) *SignerInfoList {
    return &SignerInfoList {
        ctx: C.vscf_signer_info_list_shallow_copy(ctx),
    }
}

/*
* Return true if given list has item.
*/
func (this SignerInfoList) HasItem () bool {
    proxyResult := C.vscf_signer_info_list_has_item(this.ctx)

    return proxyResult //r9
}

/*
* Return list item.
*/
func (this SignerInfoList) Item () SignerInfo {
    proxyResult := C.vscf_signer_info_list_item(this.ctx)

    return SignerInfo.init(use: proxyResult!) /* r5 */
}

/*
* Return true if list has next item.
*/
func (this SignerInfoList) HasNext () bool {
    proxyResult := C.vscf_signer_info_list_has_next(this.ctx)

    return proxyResult //r9
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (this SignerInfoList) Next () SignerInfoList {
    proxyResult := C.vscf_signer_info_list_next(this.ctx)

    return *NewSignerInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Return true if list has previous item.
*/
func (this SignerInfoList) HasPrev () bool {
    proxyResult := C.vscf_signer_info_list_has_prev(this.ctx)

    return proxyResult //r9
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (this SignerInfoList) Prev () SignerInfoList {
    proxyResult := C.vscf_signer_info_list_prev(this.ctx)

    return *NewSignerInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Remove all items.
*/
func (this SignerInfoList) Clear () {
    C.vscf_signer_info_list_clear(this.ctx)
}
