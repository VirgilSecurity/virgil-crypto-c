package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Value object that handles public available folder info.
 */
type MessengerCloudFsFolderInfo struct {
	cCtx *C.vssq_messenger_cloud_fs_folder_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsFolderInfo) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsFolderInfo() *MessengerCloudFsFolderInfo {
	ctx := C.vssq_messenger_cloud_fs_folder_info_new()
	obj := &MessengerCloudFsFolderInfo{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFolderInfo).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsFolderInfoWithCtx(anyctx interface{}) *MessengerCloudFsFolderInfo {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_folder_info_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsFolderInfo."}
	}
	obj := &MessengerCloudFsFolderInfo{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFolderInfo).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsFolderInfoCopy(anyctx interface{}) *MessengerCloudFsFolderInfo {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_folder_info_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsFolderInfo."}
	}
	obj := &MessengerCloudFsFolderInfo{
		cCtx: C.vssq_messenger_cloud_fs_folder_info_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFolderInfo).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsFolderInfo) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsFolderInfo) delete() {
	C.vssq_messenger_cloud_fs_folder_info_delete(obj.cCtx)
}

/*
* Create fully defined object.
 */
func NewMessengerCloudFsFolderInfoWith(id string, name string, createdAt uint, updatedAt uint, updatedBy string, sharedGroupId string) *MessengerCloudFsFolderInfo {
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)
	updatedByChar := C.CString(updatedBy)
	defer C.free(unsafe.Pointer(updatedByChar))
	updatedByStr := C.vsc_str_from_str(updatedByChar)
	sharedGroupIdChar := C.CString(sharedGroupId)
	defer C.free(unsafe.Pointer(sharedGroupIdChar))
	sharedGroupIdStr := C.vsc_str_from_str(sharedGroupIdChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_folder_info_new_with(idStr, nameStr, (C.size_t)(createdAt) /*pa10*/, (C.size_t)(updatedAt) /*pa10*/, updatedByStr, sharedGroupIdStr)

	runtime.KeepAlive(id)

	runtime.KeepAlive(name)

	runtime.KeepAlive(updatedBy)

	runtime.KeepAlive(sharedGroupId)

	obj := &MessengerCloudFsFolderInfo{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFolderInfo).Delete)
	return obj
}

/*
* Return folder id.
 */
func (obj *MessengerCloudFsFolderInfo) Id() string {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_folder_info_id(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return folder name.
 */
func (obj *MessengerCloudFsFolderInfo) Name() string {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_folder_info_name(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return folder "created at" timestamp.
 */
func (obj *MessengerCloudFsFolderInfo) CreatedAt() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_folder_info_created_at(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Return folder "updated at" timestamp.
 */
func (obj *MessengerCloudFsFolderInfo) UpdatedAt() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_folder_info_updated_at(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Return folder "updated by" - user identity that updated a folder.
 */
func (obj *MessengerCloudFsFolderInfo) UpdatedBy() string {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_folder_info_updated_by(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return true if folder is shared.
 */
func (obj *MessengerCloudFsFolderInfo) IsShared() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_folder_info_is_shared(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return shared group identifier if folder is shared or empty string - otherwise.
 */
func (obj *MessengerCloudFsFolderInfo) SharedGroupId() string {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_folder_info_shared_group_id(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}
