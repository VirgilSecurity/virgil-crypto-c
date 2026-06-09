package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles a list of "kek recipient info" class objects.
*/
type KekRecipientInfoList struct {
    cCtx *C.vscf_kek_recipient_info_list_t
}

/* Handle underlying C context. */
func (obj *KekRecipientInfoList) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKekRecipientInfoList() *KekRecipientInfoList {
    ctx := C.vscf_kek_recipient_info_list_new()
    obj := &KekRecipientInfoList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KekRecipientInfoList).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKekRecipientInfoListWithCtx(ctx *C.vscf_kek_recipient_info_list_t) *KekRecipientInfoList {
    obj := &KekRecipientInfoList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KekRecipientInfoList).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKekRecipientInfoListCopy(ctx *C.vscf_kek_recipient_info_list_t) *KekRecipientInfoList {
    obj := &KekRecipientInfoList {
        cCtx: C.vscf_kek_recipient_info_list_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*KekRecipientInfoList).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KekRecipientInfoList) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KekRecipientInfoList) delete() {
    C.vscf_kek_recipient_info_list_delete(obj.cCtx)
}

/*
* Return true if given list has item.
*/
func (obj *KekRecipientInfoList) HasItem() bool {
    proxyResult := C.vscf_kek_recipient_info_list_has_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult)
}

/*
* Return list item.
*/
func (obj *KekRecipientInfoList) Item() *KekRecipientInfo {
    proxyResult := C.vscf_kek_recipient_info_list_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return newKekRecipientInfoCopy(proxyResult)
}

/*
* Return true if list has next item.
*/
func (obj *KekRecipientInfoList) HasNext() bool {
    proxyResult := C.vscf_kek_recipient_info_list_has_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult)
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (obj *KekRecipientInfoList) Next() *KekRecipientInfoList {
    proxyResult := C.vscf_kek_recipient_info_list_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return newKekRecipientInfoListCopy(proxyResult)
}

/*
* Return true if list has previous item.
*/
func (obj *KekRecipientInfoList) HasPrev() bool {
    proxyResult := C.vscf_kek_recipient_info_list_has_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult)
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (obj *KekRecipientInfoList) Prev() *KekRecipientInfoList {
    proxyResult := C.vscf_kek_recipient_info_list_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return newKekRecipientInfoListCopy(proxyResult)
}

/*
* Remove all items.
*/
func (obj *KekRecipientInfoList) Clear() {
    C.vscf_kek_recipient_info_list_clear(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}
