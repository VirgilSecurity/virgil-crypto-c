package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Handles a list of "messenger cloud fs access" class objects.
 */
type MessengerCloudFsAccessList struct {
	cCtx *C.vssq_messenger_cloud_fs_access_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsAccessList) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsAccessList() *MessengerCloudFsAccessList {
	ctx := C.vssq_messenger_cloud_fs_access_list_new()
	obj := &MessengerCloudFsAccessList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsAccessList).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsAccessListWithCtx(anyctx interface{}) *MessengerCloudFsAccessList {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_access_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsAccessList."}
	}
	obj := &MessengerCloudFsAccessList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsAccessList).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsAccessListCopy(anyctx interface{}) *MessengerCloudFsAccessList {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_access_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsAccessList."}
	}
	obj := &MessengerCloudFsAccessList{
		cCtx: C.vssq_messenger_cloud_fs_access_list_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsAccessList).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsAccessList) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsAccessList) delete() {
	C.vssq_messenger_cloud_fs_access_list_delete(obj.cCtx)
}

/*
* Return items count in a list.
 */
func (obj *MessengerCloudFsAccessList) Count() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_access_list_count(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Add new item to the list.
* Note, ownership is transfered.
 */
func (obj *MessengerCloudFsAccessList) AddUser(user *MessengerUser, permission MessengerCloudFsPermission) {
	C.vssq_messenger_cloud_fs_access_list_add_user(obj.cCtx, (*C.vssq_messenger_user_t)(unsafe.Pointer(user.Ctx())), C.vssq_messenger_cloud_fs_permission_t(permission) /*pa7*/)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(user)

	return
}

/*
* Add new item to the list.
* Note, ownership is transfered.
 */
func (obj *MessengerCloudFsAccessList) AddUserWithIdentity(identity string, permission MessengerCloudFsPermission) {
	identityChar := C.CString(identity)
	defer C.free(unsafe.Pointer(identityChar))
	identityStr := C.vsc_str_from_str(identityChar)

	C.vssq_messenger_cloud_fs_access_list_add_user_with_identity(obj.cCtx, identityStr, C.vssq_messenger_cloud_fs_permission_t(permission) /*pa7*/)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(identity)

	return
}

/*
* Add new item to the list.
* Note, ownership is transfered.
 */
func (obj *MessengerCloudFsAccessList) Add(access *MessengerCloudFsAccess) {
	C.vssq_messenger_cloud_fs_access_list_add(obj.cCtx, (*C.vssq_messenger_cloud_fs_access_t)(unsafe.Pointer(access.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(access)

	return
}

/*
* Return true if given list has item.
 */
func (obj *MessengerCloudFsAccessList) HasItem() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_access_list_has_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return list item.
 */
func (obj *MessengerCloudFsAccessList) Item() *MessengerCloudFsAccess {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_access_list_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCloudFsAccessCopy(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
 */
func (obj *MessengerCloudFsAccessList) HasNext() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_access_list_has_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
 */
func (obj *MessengerCloudFsAccessList) Next() *MessengerCloudFsAccessList {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_access_list_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCloudFsAccessListCopy(proxyResult) /* r5 */
}

/*
* Return true if list has previous item.
 */
func (obj *MessengerCloudFsAccessList) HasPrev() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_access_list_has_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
 */
func (obj *MessengerCloudFsAccessList) Prev() *MessengerCloudFsAccessList {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_access_list_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCloudFsAccessListCopy(proxyResult) /* r5 */
}

/*
* Remove all items.
 */
func (obj *MessengerCloudFsAccessList) Clear() {
	C.vssq_messenger_cloud_fs_access_list_clear(obj.cCtx)

	runtime.KeepAlive(obj)

	return
}

/*
* Find user with a given identity.
 */
func (obj *MessengerCloudFsAccessList) FindWithIdentity(userIdentity string) (*MessengerCloudFsAccess, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	userIdentityChar := C.CString(userIdentity)
	defer C.free(unsafe.Pointer(userIdentityChar))
	userIdentityStr := C.vsc_str_from_str(userIdentityChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_access_list_find_with_identity(obj.cCtx, userIdentityStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(userIdentity)

	return NewMessengerCloudFsAccessCopy(proxyResult) /* r5 */, nil
}
