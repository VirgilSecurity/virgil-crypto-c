package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handles a list of "key recipient info" class objects.
*/
type KeyRecipientInfoList struct {
    cCtx *C.vscf_key_recipient_info_list_t /*ct2*/
}

/* Handle underlying C context. */
func (this KeyRecipientInfoList) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewKeyRecipientInfoList () *KeyRecipientInfoList {
    ctx := C.vscf_key_recipient_info_list_new()
    return &KeyRecipientInfoList {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyRecipientInfoListWithCtx (ctx *C.vscf_key_recipient_info_list_t /*ct2*/) *KeyRecipientInfoList {
    return &KeyRecipientInfoList {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyRecipientInfoListCopy (ctx *C.vscf_key_recipient_info_list_t /*ct2*/) *KeyRecipientInfoList {
    return &KeyRecipientInfoList {
        cCtx: C.vscf_key_recipient_info_list_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this KeyRecipientInfoList) close () {
    C.vscf_key_recipient_info_list_delete(this.cCtx)
}

/*
* Return true if given list has item.
*/
func (this KeyRecipientInfoList) HasItem () bool {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_has_item(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (this KeyRecipientInfoList) Item () *KeyRecipientInfo {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_item(this.cCtx)

    return newKeyRecipientInfoWithCtx(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
*/
func (this KeyRecipientInfoList) HasNext () bool {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_has_next(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (this KeyRecipientInfoList) Next () *KeyRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_next(this.cCtx)

    return newKeyRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Return true if list has previous item.
*/
func (this KeyRecipientInfoList) HasPrev () bool {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_has_prev(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (this KeyRecipientInfoList) Prev () *KeyRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_prev(this.cCtx)

    return newKeyRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Remove all items.
*/
func (this KeyRecipientInfoList) Clear () {
    C.vscf_key_recipient_info_list_clear(this.cCtx)

    return
}
