package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles a list of "card" class objects.
*/
type CardList struct {
    cCtx *C.vssc_card_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *CardList) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCardList() *CardList {
    ctx := C.vssc_card_list_new()
    obj := &CardList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CardList).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCardListWithCtx(ctx *C.vssc_card_list_t /*ct2*/) *CardList {
    obj := &CardList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CardList).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCardListCopy(ctx *C.vssc_card_list_t /*ct2*/) *CardList {
    obj := &CardList {
        cCtx: C.vssc_card_list_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*CardList).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *CardList) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *CardList) delete() {
    C.vssc_card_list_delete(obj.cCtx)
}

/*
* Return true if given list has item.
*/
func (obj *CardList) HasItem() bool {
    proxyResult := /*pr4*/C.vssc_card_list_has_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (obj *CardList) Item() *Card {
    proxyResult := /*pr4*/C.vssc_card_list_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return newCardCopy(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
*/
func (obj *CardList) HasNext() bool {
    proxyResult := /*pr4*/C.vssc_card_list_has_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (obj *CardList) Next() *CardList {
    proxyResult := /*pr4*/C.vssc_card_list_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return newCardListCopy(proxyResult) /* r5 */
}

/*
* Return true if list has previous item.
*/
func (obj *CardList) HasPrev() bool {
    proxyResult := /*pr4*/C.vssc_card_list_has_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (obj *CardList) Prev() *CardList {
    proxyResult := /*pr4*/C.vssc_card_list_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return newCardListCopy(proxyResult) /* r5 */
}

/*
* Remove all items.
*/
func (obj *CardList) Clear() {
    C.vssc_card_list_clear(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Find first card with it's identity.
*/
func (obj *CardList) FindWithIdentity(identity string) (*Card, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)

    proxyResult := /*pr4*/C.vssc_card_list_find_with_identity(obj.cCtx, identityStr, &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(identity)

    return newCardCopy(proxyResult) /* r5 */, nil
}

/*
* Find card with it's identifier.
*/
func (obj *CardList) FindWithIdentifier(identifier string) (*Card, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)
    identifierChar := C.CString(identifier)
    defer C.free(unsafe.Pointer(identifierChar))
    identifierStr := C.vsc_str_from_str(identifierChar)

    proxyResult := /*pr4*/C.vssc_card_list_find_with_identifier(obj.cCtx, identifierStr, &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(identifier)

    return newCardCopy(proxyResult) /* r5 */, nil
}
