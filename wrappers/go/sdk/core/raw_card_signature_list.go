package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Handles a list of "raw card signature" class objects.
 */
type RawCardSignatureList struct {
	cCtx *C.vssc_raw_card_signature_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RawCardSignatureList) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRawCardSignatureList() *RawCardSignatureList {
	ctx := C.vssc_raw_card_signature_list_new()
	obj := &RawCardSignatureList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*RawCardSignatureList).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewRawCardSignatureListWithCtx(anyctx interface{}) *RawCardSignatureList {
	ctx, ok := anyctx.(*C.vssc_raw_card_signature_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct RawCardSignatureList."}
	}
	obj := &RawCardSignatureList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*RawCardSignatureList).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewRawCardSignatureListCopy(anyctx interface{}) *RawCardSignatureList {
	ctx, ok := anyctx.(*C.vssc_raw_card_signature_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct RawCardSignatureList."}
	}
	obj := &RawCardSignatureList{
		cCtx: C.vssc_raw_card_signature_list_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*RawCardSignatureList).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *RawCardSignatureList) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *RawCardSignatureList) delete() {
	C.vssc_raw_card_signature_list_delete(obj.cCtx)
}

/*
* Return true if given list has item.
 */
func (obj *RawCardSignatureList) HasItem() bool {
	proxyResult := /*pr4*/ C.vssc_raw_card_signature_list_has_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return list item.
 */
func (obj *RawCardSignatureList) Item() *RawCardSignature {
	proxyResult := /*pr4*/ C.vssc_raw_card_signature_list_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewRawCardSignatureCopy(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
 */
func (obj *RawCardSignatureList) HasNext() bool {
	proxyResult := /*pr4*/ C.vssc_raw_card_signature_list_has_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
 */
func (obj *RawCardSignatureList) Next() *RawCardSignatureList {
	proxyResult := /*pr4*/ C.vssc_raw_card_signature_list_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewRawCardSignatureListCopy(proxyResult) /* r5 */
}

/*
* Return true if list has previous item.
 */
func (obj *RawCardSignatureList) HasPrev() bool {
	proxyResult := /*pr4*/ C.vssc_raw_card_signature_list_has_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
 */
func (obj *RawCardSignatureList) Prev() *RawCardSignatureList {
	proxyResult := /*pr4*/ C.vssc_raw_card_signature_list_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewRawCardSignatureListCopy(proxyResult) /* r5 */
}

/*
* Remove all items.
 */
func (obj *RawCardSignatureList) Clear() {
	C.vssc_raw_card_signature_list_clear(obj.cCtx)

	runtime.KeepAlive(obj)

	return
}
