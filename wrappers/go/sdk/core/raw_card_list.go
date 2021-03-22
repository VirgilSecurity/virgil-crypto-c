package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Handles a list of "raw card" class objects.
 */
type RawCardList struct {
	cCtx *C.vssc_raw_card_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RawCardList) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRawCardList() *RawCardList {
	ctx := C.vssc_raw_card_list_new()
	obj := &RawCardList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*RawCardList).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewRawCardListWithCtx(anyctx interface{}) *RawCardList {
	ctx, ok := anyctx.(*C.vssc_raw_card_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct RawCardList."}
	}
	obj := &RawCardList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*RawCardList).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewRawCardListCopy(anyctx interface{}) *RawCardList {
	ctx, ok := anyctx.(*C.vssc_raw_card_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct RawCardList."}
	}
	obj := &RawCardList{
		cCtx: C.vssc_raw_card_list_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*RawCardList).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *RawCardList) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *RawCardList) delete() {
	C.vssc_raw_card_list_delete(obj.cCtx)
}

/*
* Return true if given list has item.
 */
func (obj *RawCardList) HasItem() bool {
	proxyResult := /*pr4*/ C.vssc_raw_card_list_has_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return list item.
 */
func (obj *RawCardList) Item() *RawCard {
	proxyResult := /*pr4*/ C.vssc_raw_card_list_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewRawCardCopy(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
 */
func (obj *RawCardList) HasNext() bool {
	proxyResult := /*pr4*/ C.vssc_raw_card_list_has_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
 */
func (obj *RawCardList) Next() *RawCardList {
	proxyResult := /*pr4*/ C.vssc_raw_card_list_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewRawCardListCopy(proxyResult) /* r5 */
}

/*
* Return true if list has previous item.
 */
func (obj *RawCardList) HasPrev() bool {
	proxyResult := /*pr4*/ C.vssc_raw_card_list_has_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
 */
func (obj *RawCardList) Prev() *RawCardList {
	proxyResult := /*pr4*/ C.vssc_raw_card_list_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewRawCardListCopy(proxyResult) /* r5 */
}

/*
* Remove all items.
 */
func (obj *RawCardList) Clear() {
	C.vssc_raw_card_list_clear(obj.cCtx)

	runtime.KeepAlive(obj)

	return
}
