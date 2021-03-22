package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Value object that handles public available file info.
 */
type MessengerCloudFsFileInfo struct {
	cCtx *C.vssq_messenger_cloud_fs_file_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsFileInfo) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsFileInfo() *MessengerCloudFsFileInfo {
	ctx := C.vssq_messenger_cloud_fs_file_info_new()
	obj := &MessengerCloudFsFileInfo{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFileInfo).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsFileInfoWithCtx(anyctx interface{}) *MessengerCloudFsFileInfo {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_file_info_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsFileInfo."}
	}
	obj := &MessengerCloudFsFileInfo{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFileInfo).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsFileInfoCopy(anyctx interface{}) *MessengerCloudFsFileInfo {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_file_info_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsFileInfo."}
	}
	obj := &MessengerCloudFsFileInfo{
		cCtx: C.vssq_messenger_cloud_fs_file_info_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFileInfo).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsFileInfo) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsFileInfo) delete() {
	C.vssq_messenger_cloud_fs_file_info_delete(obj.cCtx)
}

/*
* Create fully defined object.
 */
func NewMessengerCloudFsFileInfoWith(id string, name string, mimeTipe string, size uint, createdAt uint, updatedAt uint, updatedBy string) *MessengerCloudFsFileInfo {
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)
	mimeTipeChar := C.CString(mimeTipe)
	defer C.free(unsafe.Pointer(mimeTipeChar))
	mimeTipeStr := C.vsc_str_from_str(mimeTipeChar)
	updatedByChar := C.CString(updatedBy)
	defer C.free(unsafe.Pointer(updatedByChar))
	updatedByStr := C.vsc_str_from_str(updatedByChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_new_with(idStr, nameStr, mimeTipeStr, (C.size_t)(size) /*pa10*/, (C.size_t)(createdAt) /*pa10*/, (C.size_t)(updatedAt) /*pa10*/, updatedByStr)

	runtime.KeepAlive(id)

	runtime.KeepAlive(name)

	runtime.KeepAlive(mimeTipe)

	runtime.KeepAlive(updatedBy)

	obj := &MessengerCloudFsFileInfo{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFileInfo).Delete)
	return obj
}

/*
* Return file id.
 */
func (obj *MessengerCloudFsFileInfo) Id() string {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_id(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return file name.
 */
func (obj *MessengerCloudFsFileInfo) Name() string {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_name(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return mime tipe, aka "text/plain".
 */
func (obj *MessengerCloudFsFileInfo) Type() string {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_type(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return file size.
 */
func (obj *MessengerCloudFsFileInfo) Size() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_size(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Return file "created at" timestamp.
 */
func (obj *MessengerCloudFsFileInfo) CreatedAt() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_created_at(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Return file "updated at" timestamp.
 */
func (obj *MessengerCloudFsFileInfo) UpdatedAt() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_updated_at(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Return file "updated by" - user identity that updated a file.
 */
func (obj *MessengerCloudFsFileInfo) UpdatedBy() string {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_updated_by(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}
