package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"

/*
* Handles a list of "key recipient info" class objects.
*/
type KeyRecipientInfoList struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this KeyRecipientInfoList) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewKeyRecipientInfoList () *KeyRecipientInfoList {
    ctx := C.vscf_key_recipient_info_list_new()
    return &KeyRecipientInfoList {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyRecipientInfoListWithCtx (ctx *C.vscf_impl_t) *KeyRecipientInfoList {
    return &KeyRecipientInfoList {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyRecipientInfoListCopy (ctx *C.vscf_impl_t) *KeyRecipientInfoList {
    return &KeyRecipientInfoList {
        ctx: C.vscf_key_recipient_info_list_shallow_copy(ctx),
    }
}

/*
* Return true if given list has item.
*/
func (this KeyRecipientInfoList) HasItem () bool {
    proxyResult := C.vscf_key_recipient_info_list_has_item(this.ctx)

    return proxyResult //r9
}

/*
* Return list item.
*/
func (this KeyRecipientInfoList) Item () KeyRecipientInfo {
    proxyResult := C.vscf_key_recipient_info_list_item(this.ctx)

    return KeyRecipientInfo.init(use: proxyResult!) /* r5 */
}

/*
* Return true if list has next item.
*/
func (this KeyRecipientInfoList) HasNext () bool {
    proxyResult := C.vscf_key_recipient_info_list_has_next(this.ctx)

    return proxyResult //r9
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (this KeyRecipientInfoList) Next () KeyRecipientInfoList {
    proxyResult := C.vscf_key_recipient_info_list_next(this.ctx)

    return *NewKeyRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Return true if list has previous item.
*/
func (this KeyRecipientInfoList) HasPrev () bool {
    proxyResult := C.vscf_key_recipient_info_list_has_prev(this.ctx)

    return proxyResult //r9
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (this KeyRecipientInfoList) Prev () KeyRecipientInfoList {
    proxyResult := C.vscf_key_recipient_info_list_prev(this.ctx)

    return *NewKeyRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Remove all items.
*/
func (this KeyRecipientInfoList) Clear () {
    C.vscf_key_recipient_info_list_clear(this.ctx)
}
