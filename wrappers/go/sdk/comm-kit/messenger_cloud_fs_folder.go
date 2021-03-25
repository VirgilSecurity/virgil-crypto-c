package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles a list of folder entries
*/
type MessengerCloudFsFolder struct {
    cCtx *C.vssq_messenger_cloud_fs_folder_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsFolder) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsFolder() *MessengerCloudFsFolder {
    ctx := C.vssq_messenger_cloud_fs_folder_new()
    obj := &MessengerCloudFsFolder {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsFolder).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerCloudFsFolderWithCtx(pointer unsafe.Pointer) *MessengerCloudFsFolder {
    ctx := (*C.vssq_messenger_cloud_fs_folder_t /*ct2*/)(pointer)
    obj := &MessengerCloudFsFolder {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsFolder).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerCloudFsFolderCopy(pointer unsafe.Pointer) *MessengerCloudFsFolder {
    ctx := (*C.vssq_messenger_cloud_fs_folder_t /*ct2*/)(pointer)
    obj := &MessengerCloudFsFolder {
        cCtx: C.vssq_messenger_cloud_fs_folder_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsFolder).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessengerCloudFsFolder) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessengerCloudFsFolder) delete() {
    C.vssq_messenger_cloud_fs_folder_delete(obj.cCtx)
}

/*
* Create fully defined object.
*/
func NewMessengerCloudFsFolderWith(totalFolderCount uint, totalFileCount uint, folderEncryptedKey []byte, folderPublicKey []byte, folders *MessengerCloudFsFolderInfoList, files *MessengerCloudFsFileInfoList, info *MessengerCloudFsFolderInfo, usersPermission *MessengerCloudFsAccessList) *MessengerCloudFsFolder {
    folderEncryptedKeyData := helperWrapData (folderEncryptedKey)
    folderPublicKeyData := helperWrapData (folderPublicKey)

    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_new_with((C.size_t)(totalFolderCount)/*pa10*/, (C.size_t)(totalFileCount)/*pa10*/, folderEncryptedKeyData, folderPublicKeyData, (*C.vssq_messenger_cloud_fs_folder_info_list_t)(unsafe.Pointer(folders.Ctx())), (*C.vssq_messenger_cloud_fs_file_info_list_t)(unsafe.Pointer(files.Ctx())), (*C.vssq_messenger_cloud_fs_folder_info_t)(unsafe.Pointer(info.Ctx())), (*C.vssq_messenger_cloud_fs_access_list_t)(unsafe.Pointer(usersPermission.Ctx())))

    runtime.KeepAlive(folders)

    runtime.KeepAlive(files)

    runtime.KeepAlive(info)

    runtime.KeepAlive(usersPermission)

    obj := &MessengerCloudFsFolder {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsFolder).Delete)
    return obj
}

/*
* Create fully defined object.
*/
func NewMessengerCloudFsFolderRootWith(totalFolderCount uint, totalFileCount uint, folders *MessengerCloudFsFolderInfoList, files *MessengerCloudFsFileInfoList, info *MessengerCloudFsFolderInfo) *MessengerCloudFsFolder {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_new_root_with((C.size_t)(totalFolderCount)/*pa10*/, (C.size_t)(totalFileCount)/*pa10*/, (*C.vssq_messenger_cloud_fs_folder_info_list_t)(unsafe.Pointer(folders.Ctx())), (*C.vssq_messenger_cloud_fs_file_info_list_t)(unsafe.Pointer(files.Ctx())), (*C.vssq_messenger_cloud_fs_folder_info_t)(unsafe.Pointer(info.Ctx())))

    runtime.KeepAlive(folders)

    runtime.KeepAlive(files)

    runtime.KeepAlive(info)

    obj := &MessengerCloudFsFolder {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsFolder).Delete)
    return obj
}

/*
* Return true if folder is a root folder.
*/
func (obj *MessengerCloudFsFolder) IsRoot() bool {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_is_root(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return total = folder + file count.
*/
func (obj *MessengerCloudFsFolder) TotalEntryCount() uint {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_total_entry_count(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return total folder count.
*/
func (obj *MessengerCloudFsFolder) TotalFolderCount() uint {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_total_folder_count(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return total file count.
*/
func (obj *MessengerCloudFsFolder) TotalFileCount() uint {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_total_file_count(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return folders.
*/
func (obj *MessengerCloudFsFolder) Folders() *MessengerCloudFsFolderInfoList {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_folders(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessengerCloudFsFolderInfoListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return files.
*/
func (obj *MessengerCloudFsFolder) Files() *MessengerCloudFsFileInfoList {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_files(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessengerCloudFsFileInfoListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return current folder info.
*/
func (obj *MessengerCloudFsFolder) Info() *MessengerCloudFsFolderInfo {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessengerCloudFsFolderInfoCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return encrypted folder private key.
*/
func (obj *MessengerCloudFsFolder) EncryptedKey() []byte {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_encrypted_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return folder public key.
*/
func (obj *MessengerCloudFsFolder) PublicKey() []byte {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return true if folder has shared users.
*/
func (obj *MessengerCloudFsFolder) HasSharedUsersPermission() bool {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_has_shared_users_permission(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return users that have permissions to this folder.
*/
func (obj *MessengerCloudFsFolder) SharedUsersPermission() *MessengerCloudFsAccessList {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_folder_shared_users_permission(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessengerCloudFsAccessListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}
