package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handles a list of "key recipient info" class objects.
*/
type KeyRecipientInfoList struct {
    cCtx *C.vscf_key_recipient_info_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyRecipientInfoList) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
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

/*
* Release underlying C context.
*/
func (obj *KeyRecipientInfoList) Delete () {
    C.vscf_key_recipient_info_list_delete(obj.cCtx)
}

/*
* Return true if given list has item.
*/
func (obj *KeyRecipientInfoList) HasItem () bool {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_has_item(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (obj *KeyRecipientInfoList) Item () *KeyRecipientInfo {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_item(obj.cCtx)

    return newKeyRecipientInfoWithCtx(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
*/
func (obj *KeyRecipientInfoList) HasNext () bool {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_has_next(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (obj *KeyRecipientInfoList) Next () *KeyRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_next(obj.cCtx)

    return newKeyRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Return true if list has previous item.
*/
func (obj *KeyRecipientInfoList) HasPrev () bool {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_has_prev(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (obj *KeyRecipientInfoList) Prev () *KeyRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_prev(obj.cCtx)

    return newKeyRecipientInfoListWithCtx(proxyResult) /* r6 */
}

/*
* Remove all items.
*/
func (obj *KeyRecipientInfoList) Clear () {
    C.vscf_key_recipient_info_list_clear(obj.cCtx)

    return
}
