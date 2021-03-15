package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles a list of "string" class objects.
*/
type StringList struct {
    cCtx *C.vssc_string_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *StringList) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewStringList() *StringList {
    ctx := C.vssc_string_list_new()
    obj := &StringList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*StringList).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newStringListWithCtx(ctx *C.vssc_string_list_t /*ct2*/) *StringList {
    obj := &StringList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*StringList).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newStringListCopy(ctx *C.vssc_string_list_t /*ct2*/) *StringList {
    obj := &StringList {
        cCtx: C.vssc_string_list_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*StringList).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *StringList) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *StringList) delete() {
    C.vssc_string_list_delete(obj.cCtx)
}

/*
* Add new item to the list.
*/
func (obj *StringList) Add(str string) {
    strChar := C.CString(str)
    defer C.free(unsafe.Pointer(strChar))
    strStr := C.vsc_str_from_str(strChar)

    C.vssc_string_list_add(obj.cCtx, strStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(str)

    return
}

/*
* Return true if given list has item.
*/
func (obj *StringList) HasItem() bool {
    proxyResult := /*pr4*/C.vssc_string_list_has_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (obj *StringList) Item() string {
    proxyResult := /*pr4*/C.vssc_string_list_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return true if list has next item.
*/
func (obj *StringList) HasNext() bool {
    proxyResult := /*pr4*/C.vssc_string_list_has_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (obj *StringList) Next() *StringList {
    proxyResult := /*pr4*/C.vssc_string_list_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return newStringListCopy(proxyResult) /* r5 */
}

/*
* Return true if list has previous item.
*/
func (obj *StringList) HasPrev() bool {
    proxyResult := /*pr4*/C.vssc_string_list_has_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (obj *StringList) Prev() *StringList {
    proxyResult := /*pr4*/C.vssc_string_list_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return newStringListCopy(proxyResult) /* r5 */
}

/*
* Remove all items.
*/
func (obj *StringList) Clear() {
    C.vssc_string_list_clear(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Return number of items within list.
*/
func (obj *StringList) Count() uint {
    proxyResult := /*pr4*/C.vssc_string_list_count(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return true if list contains a given value.
*/
func (obj *StringList) Contains(str string) bool {
    strChar := C.CString(str)
    defer C.free(unsafe.Pointer(strChar))
    strStr := C.vsc_str_from_str(strChar)

    proxyResult := /*pr4*/C.vssc_string_list_contains(obj.cCtx, strStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(str)

    return bool(proxyResult) /* r9 */
}
