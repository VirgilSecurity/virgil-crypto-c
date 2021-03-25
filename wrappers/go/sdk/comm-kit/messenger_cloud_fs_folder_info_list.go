package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles a list of "messenger cloud fs folder info" class objects.
*/
type MessengerCloudFsFolderInfoList struct {
    cCtx *C.vssq_messenger_cloud_fs_folder_info_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsFolderInfoList) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsFolderInfoList() *MessengerCloudFsFolderInfoList {
    ctx := C.vssq_messenger_cloud_fs_folder_info_list_new()
    obj := &MessengerCloudFsFolderInfoList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsFolderInfoList).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerCloudFsFolderInfoListWithCtx(pointer unsafe.Pointer) *MessengerCloudFsFolderInfoList {
    ctx := (*C.vssq_messenger_cloud_fs_folder_info_list_t /*ct2*/)(pointer)
    obj := &MessengerCloudFsFolderInfoList {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsFolderInfoList).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerCloudFsFolderInfoListCopy(pointer unsafe.Pointer) *MessengerCloudFsFolderInfoList {
    ctx := (*C.vssq_messenger_cloud_fs_folder_info_list_t /*ct2*/)(pointer)
    obj := &MessengerCloudFsFolderInfoList {
        cCtx: C.vssq_messenger_cloud_fs_folder_info_list_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsFolderInfoList).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessengerCloudFsFolderInfoList) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessengerCloudFsFolderInfoList) delete() {
    C.vssq_messenger_cloud_fs_folder_info_list_delete(obj.cCtx)
}

/*
* Add new item to the list.
* Note, ownership is retained.
*/
func (obj *MessengerCloudFsFolderInfoList) Add(folderInfo *MessengerCloudFsFolderInfo) {
    C.vssq_messenger_cloud_fs_folder_info_list_add(obj.cCtx, (*C.vssq_messenger_cloud_fs_folder_info_t)(unsafe.Pointer(folderInfo.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(folderInfo)

    return
}

/*
* Return true if given list has item.
*/
func (obj *MessengerCloudFsFolderInfoList) HasItem() bool {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_info_list_has_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return list item.
*/
func (obj *MessengerCloudFsFolderInfoList) Item() *MessengerCloudFsFolderInfo {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_info_list_item(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessengerCloudFsFolderInfoCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if list has next item.
*/
func (obj *MessengerCloudFsFolderInfoList) HasNext() bool {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_info_list_has_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
*/
func (obj *MessengerCloudFsFolderInfoList) Next() *MessengerCloudFsFolderInfoList {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_info_list_next(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessengerCloudFsFolderInfoListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if list has previous item.
*/
func (obj *MessengerCloudFsFolderInfoList) HasPrev() bool {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_info_list_has_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
*/
func (obj *MessengerCloudFsFolderInfoList) Prev() *MessengerCloudFsFolderInfoList {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_info_list_prev(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessengerCloudFsFolderInfoListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Remove all items.
*/
func (obj *MessengerCloudFsFolderInfoList) Clear() {
    C.vssq_messenger_cloud_fs_folder_info_list_clear(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}
