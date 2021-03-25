package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles a list of "key handler" class objects.
*/
type KeyHandlerList struct {
    cCtx *C.vssc_key_handler_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyHandlerList) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKeyHandlerList() *KeyHandlerList {
    ctx := C.vssc_key_handler_list_new()
    obj := &KeyHandlerList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyHandlerList).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyHandlerListWithCtx(pointer unsafe.Pointer) *KeyHandlerList {
    ctx := (*C.vssc_key_handler_list_t /*ct2*/)(pointer)
    obj := &KeyHandlerList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyHandlerList).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyHandlerListCopy(pointer unsafe.Pointer) *KeyHandlerList {
    ctx := (*C.vssc_key_handler_list_t /*ct2*/)(pointer)
    obj := &KeyHandlerList {
        cCtx: C.vssc_key_handler_list_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*KeyHandlerList).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KeyHandlerList) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KeyHandlerList) delete() {
    C.vssc_key_handler_list_delete(obj.cCtx)
}

/*
* Return true if given list has item.
*/
func (obj *KeyHandlerList) HasItem() bool {
    proxyResult := /*pr4*/C.vssc_key_handler_list_has_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (obj *KeyHandlerList) Item() *KeyHandler {
    proxyResult := /*pr4*/C.vssc_key_handler_list_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewKeyHandlerCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if list has next item.
*/
func (obj *KeyHandlerList) HasNext() bool {
    proxyResult := /*pr4*/C.vssc_key_handler_list_has_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (obj *KeyHandlerList) Next() *KeyHandlerList {
    proxyResult := /*pr4*/C.vssc_key_handler_list_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewKeyHandlerListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if list has previous item.
*/
func (obj *KeyHandlerList) HasPrev() bool {
    proxyResult := /*pr4*/C.vssc_key_handler_list_has_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (obj *KeyHandlerList) Prev() *KeyHandlerList {
    proxyResult := /*pr4*/C.vssc_key_handler_list_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewKeyHandlerListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Remove all items.
*/
func (obj *KeyHandlerList) Clear() {
    C.vssc_key_handler_list_clear(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Find first key handler by it's identity.
*/
func (obj *KeyHandlerList) FindWithIdentity(identity string) (*KeyHandler, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)

    proxyResult := /*pr4*/C.vssc_key_handler_list_find_with_identity(obj.cCtx, identityStr, &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(identity)

    return NewKeyHandlerCopy(unsafe.Pointer(proxyResult)) /* r5 */, nil
}

/*
* Find key handler by it's key identifier.
*/
func (obj *KeyHandlerList) FindWithKeyId(keyId []byte) (*KeyHandler, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)
    keyIdData := helperWrapData (keyId)

    proxyResult := /*pr4*/C.vssc_key_handler_list_find_with_key_id(obj.cCtx, keyIdData, &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return NewKeyHandlerCopy(unsafe.Pointer(proxyResult)) /* r5 */, nil
}
