package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Handles a list of "password recipient info" class objects.
 */
type PasswordRecipientInfoList struct {
	cCtx *C.vscf_password_recipient_info_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *PasswordRecipientInfoList) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewPasswordRecipientInfoList() *PasswordRecipientInfoList {
	ctx := C.vscf_password_recipient_info_list_new()
	obj := &PasswordRecipientInfoList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*PasswordRecipientInfoList).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewPasswordRecipientInfoListWithCtx(anyctx interface{}) *PasswordRecipientInfoList {
	ctx, ok := anyctx.(*C.vscf_password_recipient_info_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &FoundationError{-1,"Cast error for struct PasswordRecipientInfoList."}
	}
	obj := &PasswordRecipientInfoList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*PasswordRecipientInfoList).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewPasswordRecipientInfoListCopy(anyctx interface{}) *PasswordRecipientInfoList {
	ctx, ok := anyctx.(*C.vscf_password_recipient_info_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &FoundationError{-1,"Cast error for struct PasswordRecipientInfoList."}
	}
	obj := &PasswordRecipientInfoList{
		cCtx: C.vscf_password_recipient_info_list_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*PasswordRecipientInfoList).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *PasswordRecipientInfoList) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *PasswordRecipientInfoList) delete() {
	C.vscf_password_recipient_info_list_delete(obj.cCtx)
}

/*
* Return true if given list has item.
 */
func (obj *PasswordRecipientInfoList) HasItem() bool {
	proxyResult := /*pr4*/ C.vscf_password_recipient_info_list_has_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return list item.
 */
func (obj *PasswordRecipientInfoList) Item() *PasswordRecipientInfo {
	proxyResult := /*pr4*/ C.vscf_password_recipient_info_list_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewPasswordRecipientInfoCopy(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
 */
func (obj *PasswordRecipientInfoList) HasNext() bool {
	proxyResult := /*pr4*/ C.vscf_password_recipient_info_list_has_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
 */
func (obj *PasswordRecipientInfoList) Next() *PasswordRecipientInfoList {
	proxyResult := /*pr4*/ C.vscf_password_recipient_info_list_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewPasswordRecipientInfoListCopy(proxyResult) /* r5 */
}

/*
* Return true if list has previous item.
 */
func (obj *PasswordRecipientInfoList) HasPrev() bool {
	proxyResult := /*pr4*/ C.vscf_password_recipient_info_list_has_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
 */
func (obj *PasswordRecipientInfoList) Prev() *PasswordRecipientInfoList {
	proxyResult := /*pr4*/ C.vscf_password_recipient_info_list_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewPasswordRecipientInfoListCopy(proxyResult) /* r5 */
}

/*
* Remove all items.
 */
func (obj *PasswordRecipientInfoList) Clear() {
	C.vscf_password_recipient_info_list_clear(obj.cCtx)

	runtime.KeepAlive(obj)

	return
}
