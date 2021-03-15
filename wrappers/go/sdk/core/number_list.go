package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles a list of numbers.
*/
type NumberList struct {
    cCtx *C.vssc_number_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *NumberList) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewNumberList() *NumberList {
    ctx := C.vssc_number_list_new()
    obj := &NumberList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*NumberList).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newNumberListWithCtx(ctx *C.vssc_number_list_t /*ct2*/) *NumberList {
    obj := &NumberList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*NumberList).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newNumberListCopy(ctx *C.vssc_number_list_t /*ct2*/) *NumberList {
    obj := &NumberList {
        cCtx: C.vssc_number_list_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*NumberList).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *NumberList) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *NumberList) delete() {
    C.vssc_number_list_delete(obj.cCtx)
}

/*
* Add new item to the list.
* Note, ownership is transfered.
*/
func (obj *NumberList) Add(number uint) {
    C.vssc_number_list_add(obj.cCtx, (C.size_t)(number)/*pa10*/)

    runtime.KeepAlive(obj)

    return
}

/*
* Return true if given list has item.
*/
func (obj *NumberList) HasItem() bool {
    proxyResult := /*pr4*/C.vssc_number_list_has_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (obj *NumberList) Item() uint {
    proxyResult := /*pr4*/C.vssc_number_list_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return true if list has next item.
*/
func (obj *NumberList) HasNext() bool {
    proxyResult := /*pr4*/C.vssc_number_list_has_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (obj *NumberList) Next() *NumberList {
    proxyResult := /*pr4*/C.vssc_number_list_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return newNumberListCopy(proxyResult) /* r5 */
}

/*
* Return true if list has previous item.
*/
func (obj *NumberList) HasPrev() bool {
    proxyResult := /*pr4*/C.vssc_number_list_has_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (obj *NumberList) Prev() *NumberList {
    proxyResult := /*pr4*/C.vssc_number_list_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return newNumberListCopy(proxyResult) /* r5 */
}

/*
* Remove all items.
*/
func (obj *NumberList) Clear() {
    C.vssc_number_list_clear(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Return true if list contains a given value.
*/
func (obj *NumberList) Contains(number uint) bool {
    proxyResult := /*pr4*/C.vssc_number_list_contains(obj.cCtx, (C.size_t)(number)/*pa10*/)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}
