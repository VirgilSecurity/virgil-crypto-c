package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Handles a list of "messenger user" class objects.
 */
type MessengerUserList struct {
	cCtx *C.vssq_messenger_user_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerUserList) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerUserList() *MessengerUserList {
	ctx := C.vssq_messenger_user_list_new()
	obj := &MessengerUserList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerUserList).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerUserListWithCtx(anyctx interface{}) *MessengerUserList {
	ctx, ok := anyctx.(*C.vssq_messenger_user_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerUserList."}
	}
	obj := &MessengerUserList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerUserList).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerUserListCopy(anyctx interface{}) *MessengerUserList {
	ctx, ok := anyctx.(*C.vssq_messenger_user_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerUserList."}
	}
	obj := &MessengerUserList{
		cCtx: C.vssq_messenger_user_list_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerUserList).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerUserList) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerUserList) delete() {
	C.vssq_messenger_user_list_delete(obj.cCtx)
}

/*
* Add new item to the list.
* Note, ownership is transfered.
 */
func (obj *MessengerUserList) Add(messengerUser *MessengerUser) {
	C.vssq_messenger_user_list_add(obj.cCtx, (*C.vssq_messenger_user_t)(unsafe.Pointer(messengerUser.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(messengerUser)

	return
}

/*
* Return true if given list has item.
 */
func (obj *MessengerUserList) HasItem() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_user_list_has_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return list item.
 */
func (obj *MessengerUserList) Item() *MessengerUser {
	proxyResult := /*pr4*/ C.vssq_messenger_user_list_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserCopy(proxyResult) /* r5 */
}

/*
* Return list item.
 */
func (obj *MessengerUserList) ItemModifiable() *MessengerUser {
	proxyResult := /*pr4*/ C.vssq_messenger_user_list_item_modifiable(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserCopy(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
 */
func (obj *MessengerUserList) HasNext() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_user_list_has_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
 */
func (obj *MessengerUserList) Next() *MessengerUserList {
	proxyResult := /*pr4*/ C.vssq_messenger_user_list_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserListCopy(proxyResult) /* r5 */
}

/*
* Return next list node if exists, or NULL otherwise.
 */
func (obj *MessengerUserList) NextModifiable() *MessengerUserList {
	proxyResult := /*pr4*/ C.vssq_messenger_user_list_next_modifiable(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserListCopy(proxyResult) /* r5 */
}

/*
* Return true if list has previous item.
 */
func (obj *MessengerUserList) HasPrev() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_user_list_has_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
 */
func (obj *MessengerUserList) Prev() *MessengerUserList {
	proxyResult := /*pr4*/ C.vssq_messenger_user_list_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserListCopy(proxyResult) /* r5 */
}

/*
* Return previous list node if exists, or NULL otherwise.
 */
func (obj *MessengerUserList) PrevModifiable() *MessengerUserList {
	proxyResult := /*pr4*/ C.vssq_messenger_user_list_prev_modifiable(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserListCopy(proxyResult) /* r5 */
}

/*
* Remove all items.
 */
func (obj *MessengerUserList) Clear() {
	C.vssq_messenger_user_list_clear(obj.cCtx)

	runtime.KeepAlive(obj)

	return
}

/*
* Find user with a given name.
 */
func (obj *MessengerUserList) FindWithIdentity(userIdentity string) (*MessengerUser, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	userIdentityChar := C.CString(userIdentity)
	defer C.free(unsafe.Pointer(userIdentityChar))
	userIdentityStr := C.vsc_str_from_str(userIdentityChar)

	proxyResult := /*pr4*/ C.vssq_messenger_user_list_find_with_identity(obj.cCtx, userIdentityStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(userIdentity)

	return NewMessengerUserCopy(proxyResult) /* r5 */, nil
}

/*
* Find user with a given name.
 */
func (obj *MessengerUserList) FindWithIdentityModifiable(userIdentity string) (*MessengerUser, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	userIdentityChar := C.CString(userIdentity)
	defer C.free(unsafe.Pointer(userIdentityChar))
	userIdentityStr := C.vsc_str_from_str(userIdentityChar)

	proxyResult := /*pr4*/ C.vssq_messenger_user_list_find_with_identity_modifiable(obj.cCtx, userIdentityStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(userIdentity)

	return NewMessengerUserCopy(proxyResult) /* r5 */, nil
}
