package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles a list of "key recipient info" class objects.
*/
type KeyRecipientInfoList struct {
    cCtx *C.vscf_key_recipient_info_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyRecipientInfoList) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKeyRecipientInfoList() *KeyRecipientInfoList {
    ctx := C.vscf_key_recipient_info_list_new()
    obj := &KeyRecipientInfoList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyRecipientInfoList).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyRecipientInfoListWithCtx(pointer unsafe.Pointer) *KeyRecipientInfoList {
    ctx := (*C.vscf_key_recipient_info_list_t /*ct2*/)(pointer)
    obj := &KeyRecipientInfoList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyRecipientInfoList).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyRecipientInfoListCopy(pointer unsafe.Pointer) *KeyRecipientInfoList {
    ctx := (*C.vscf_key_recipient_info_list_t /*ct2*/)(pointer)
    obj := &KeyRecipientInfoList {
        cCtx: C.vscf_key_recipient_info_list_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*KeyRecipientInfoList).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KeyRecipientInfoList) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KeyRecipientInfoList) delete() {
    C.vscf_key_recipient_info_list_delete(obj.cCtx)
}

/*
* Return true if given list has item.
*/
func (obj *KeyRecipientInfoList) HasItem() bool {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_has_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (obj *KeyRecipientInfoList) Item() *KeyRecipientInfo {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewKeyRecipientInfoCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if list has next item.
*/
func (obj *KeyRecipientInfoList) HasNext() bool {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_has_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (obj *KeyRecipientInfoList) Next() *KeyRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewKeyRecipientInfoListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if list has previous item.
*/
func (obj *KeyRecipientInfoList) HasPrev() bool {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_has_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (obj *KeyRecipientInfoList) Prev() *KeyRecipientInfoList {
    proxyResult := /*pr4*/C.vscf_key_recipient_info_list_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewKeyRecipientInfoListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Remove all items.
*/
func (obj *KeyRecipientInfoList) Clear() {
    C.vscf_key_recipient_info_list_clear(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}
