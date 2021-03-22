package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Handles a list of "messenger cloud fs file info" class objects.
 */
type MessengerCloudFsFileInfoList struct {
	cCtx *C.vssq_messenger_cloud_fs_file_info_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsFileInfoList) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsFileInfoList() *MessengerCloudFsFileInfoList {
	ctx := C.vssq_messenger_cloud_fs_file_info_list_new()
	obj := &MessengerCloudFsFileInfoList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFileInfoList).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsFileInfoListWithCtx(anyctx interface{}) *MessengerCloudFsFileInfoList {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_file_info_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsFileInfoList."}
	}
	obj := &MessengerCloudFsFileInfoList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFileInfoList).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsFileInfoListCopy(anyctx interface{}) *MessengerCloudFsFileInfoList {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_file_info_list_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsFileInfoList."}
	}
	obj := &MessengerCloudFsFileInfoList{
		cCtx: C.vssq_messenger_cloud_fs_file_info_list_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsFileInfoList).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsFileInfoList) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsFileInfoList) delete() {
	C.vssq_messenger_cloud_fs_file_info_list_delete(obj.cCtx)
}

/*
* Add new item to the list.
* Note, ownership is transfered.
 */
func (obj *MessengerCloudFsFileInfoList) Add(fileInfo *MessengerCloudFsFileInfo) {
	C.vssq_messenger_cloud_fs_file_info_list_add(obj.cCtx, (*C.vssq_messenger_cloud_fs_file_info_t)(unsafe.Pointer(fileInfo.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(fileInfo)

	return
}

/*
* Return true if given list has item.
 */
func (obj *MessengerCloudFsFileInfoList) HasItem() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_list_has_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return list item.
 */
func (obj *MessengerCloudFsFileInfoList) Item() *MessengerCloudFsFileInfo {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_list_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCloudFsFileInfoCopy(proxyResult) /* r5 */
}

/*
* Return true if list has next item.
 */
func (obj *MessengerCloudFsFileInfoList) HasNext() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_list_has_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
 */
func (obj *MessengerCloudFsFileInfoList) Next() *MessengerCloudFsFileInfoList {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_list_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCloudFsFileInfoListCopy(proxyResult) /* r5 */
}

/*
* Return true if list has previous item.
 */
func (obj *MessengerCloudFsFileInfoList) HasPrev() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_list_has_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
 */
func (obj *MessengerCloudFsFileInfoList) Prev() *MessengerCloudFsFileInfoList {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_file_info_list_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCloudFsFileInfoListCopy(proxyResult) /* r5 */
}

/*
* Remove all items.
 */
func (obj *MessengerCloudFsFileInfoList) Clear() {
	C.vssq_messenger_cloud_fs_file_info_list_clear(obj.cCtx)

	runtime.KeepAlive(obj)

	return
}
