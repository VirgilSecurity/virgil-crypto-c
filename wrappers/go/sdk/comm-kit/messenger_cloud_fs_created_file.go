package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Value object that handles created file info.
 */
type MessengerCloudFsCreatedFile struct {
	cCtx *C.vssq_messenger_cloud_fs_created_file_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsCreatedFile) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsCreatedFile() *MessengerCloudFsCreatedFile {
	ctx := C.vssq_messenger_cloud_fs_created_file_new()
	obj := &MessengerCloudFsCreatedFile{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsCreatedFile).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsCreatedFileWithCtx(anyctx interface{}) *MessengerCloudFsCreatedFile {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_created_file_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsCreatedFile."}
	}
	obj := &MessengerCloudFsCreatedFile{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsCreatedFile).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsCreatedFileCopy(anyctx interface{}) *MessengerCloudFsCreatedFile {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_created_file_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsCreatedFile."}
	}
	obj := &MessengerCloudFsCreatedFile{
		cCtx: C.vssq_messenger_cloud_fs_created_file_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsCreatedFile).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsCreatedFile) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsCreatedFile) delete() {
	C.vssq_messenger_cloud_fs_created_file_delete(obj.cCtx)
}

/*
* Create fully defined object.
 */
func NewMessengerCloudFsCreatedFileWith(uploadLink string, fileInfo *MessengerCloudFsFileInfo) *MessengerCloudFsCreatedFile {
	uploadLinkChar := C.CString(uploadLink)
	defer C.free(unsafe.Pointer(uploadLinkChar))
	uploadLinkStr := C.vsc_str_from_str(uploadLinkChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_created_file_new_with(uploadLinkStr, (*C.vssq_messenger_cloud_fs_file_info_t)(unsafe.Pointer(fileInfo.Ctx())))

	runtime.KeepAlive(uploadLink)

	runtime.KeepAlive(fileInfo)

	obj := &MessengerCloudFsCreatedFile{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsCreatedFile).Delete)
	return obj
}

/*
* Return file upload link.
 */
func (obj *MessengerCloudFsCreatedFile) UploadLink() string {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_created_file_upload_link(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return file info.
 */
func (obj *MessengerCloudFsCreatedFile) Info() *MessengerCloudFsFileInfo {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_created_file_info(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCloudFsFileInfoCopy(proxyResult) /* r5 */
}
