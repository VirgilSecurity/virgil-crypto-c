package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"

/*
* This class provides access to the messenger Cloud File System service.
 */
type MessengerCloudFsClient struct {
	cCtx *C.vssq_messenger_cloud_fs_client_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsClient) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsClient() *MessengerCloudFsClient {
	ctx := C.vssq_messenger_cloud_fs_client_new()
	obj := &MessengerCloudFsClient{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsClient).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsClientWithCtx(anyctx interface{}) *MessengerCloudFsClient {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_client_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsClient."}
	}
	obj := &MessengerCloudFsClient{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsClient).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsClientCopy(anyctx interface{}) *MessengerCloudFsClient {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_client_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsClient."}
	}
	obj := &MessengerCloudFsClient{
		cCtx: C.vssq_messenger_cloud_fs_client_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsClient).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsClient) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsClient) delete() {
	C.vssq_messenger_cloud_fs_client_delete(obj.cCtx)
}

func (obj *MessengerCloudFsClient) SetAuth(auth *MessengerAuth) {
	C.vssq_messenger_cloud_fs_client_release_auth(obj.cCtx)
	C.vssq_messenger_cloud_fs_client_use_auth(obj.cCtx, (*C.vssq_messenger_auth_t)(unsafe.Pointer(auth.Ctx())))

	runtime.KeepAlive(auth)
	runtime.KeepAlive(obj)
}

/*
* Create a new file within the Cloud FS.
* Note, if folder id is empty then file created in a root folder.
 */
func (obj *MessengerCloudFsClient) CreateFile(name string, mimeTipe string, size uint, folderId string, fileEncryptedKey []byte) (*MessengerCloudFsCreatedFile, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)
	mimeTipeChar := C.CString(mimeTipe)
	defer C.free(unsafe.Pointer(mimeTipeChar))
	mimeTipeStr := C.vsc_str_from_str(mimeTipeChar)
	folderIdChar := C.CString(folderId)
	defer C.free(unsafe.Pointer(folderIdChar))
	folderIdStr := C.vsc_str_from_str(folderIdChar)
	fileEncryptedKeyData := helperWrapData(fileEncryptedKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_create_file(obj.cCtx, nameStr, mimeTipeStr, (C.size_t)(size) /*pa10*/, folderIdStr, fileEncryptedKeyData, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(name)

	runtime.KeepAlive(mimeTipe)

	runtime.KeepAlive(folderId)

	return NewMessengerCloudFsCreatedFileWithCtx(proxyResult) /* r6 */, nil
}

/*
* Get a file download link.
 */
func (obj *MessengerCloudFsClient) GetDownloadLink(id string) (*MessengerCloudFsFileDownloadInfo, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_get_download_link(obj.cCtx, idStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(id)

	return NewMessengerCloudFsFileDownloadInfoWithCtx(proxyResult) /* r6 */, nil
}

/*
* Delete existing file.
 */
func (obj *MessengerCloudFsClient) DeleteFile(id string) error {
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_delete_file(obj.cCtx, idStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(id)

	return nil
}

/*
* Create a new folder within the Cloud FS.
* Note, if parent folder id is empty then folder created in a root folder.
 */
func (obj *MessengerCloudFsClient) CreateFolder(name string, folderEncryptedKey []byte, folderPublicKey []byte, parentFolderId string) (*MessengerCloudFsFolderInfo, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)
	parentFolderIdChar := C.CString(parentFolderId)
	defer C.free(unsafe.Pointer(parentFolderIdChar))
	parentFolderIdStr := C.vsc_str_from_str(parentFolderIdChar)
	folderEncryptedKeyData := helperWrapData(folderEncryptedKey)
	folderPublicKeyData := helperWrapData(folderPublicKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_create_folder(obj.cCtx, nameStr, folderEncryptedKeyData, folderPublicKeyData, parentFolderIdStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(name)

	runtime.KeepAlive(parentFolderId)

	return NewMessengerCloudFsFolderInfoWithCtx(proxyResult) /* r6 */, nil
}

/*
* Create a new folder within the Cloud FS that is shared with other users.
* Note, if parent folder id is empty then folder created in a root folder.
 */
func (obj *MessengerCloudFsClient) CreateSharedFolder(name string, folderEncryptedKey []byte, folderPublicKey []byte, parentFolderId string, users *MessengerCloudFsAccessList) (*MessengerCloudFsFolderInfo, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)
	parentFolderIdChar := C.CString(parentFolderId)
	defer C.free(unsafe.Pointer(parentFolderIdChar))
	parentFolderIdStr := C.vsc_str_from_str(parentFolderIdChar)
	folderEncryptedKeyData := helperWrapData(folderEncryptedKey)
	folderPublicKeyData := helperWrapData(folderPublicKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_create_shared_folder(obj.cCtx, nameStr, folderEncryptedKeyData, folderPublicKeyData, parentFolderIdStr, (*C.vssq_messenger_cloud_fs_access_list_t)(unsafe.Pointer(users.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(name)

	runtime.KeepAlive(parentFolderId)

	runtime.KeepAlive(users)

	return NewMessengerCloudFsFolderInfoWithCtx(proxyResult) /* r6 */, nil
}

/*
* List content of requested folder.
* Note, if folder id is empty then a root folder will be listed.
 */
func (obj *MessengerCloudFsClient) ListFolder(id string) (*MessengerCloudFsFolder, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_list_folder(obj.cCtx, idStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(id)

	return NewMessengerCloudFsFolderWithCtx(proxyResult) /* r6 */, nil
}

/*
* Delete existing folder.
 */
func (obj *MessengerCloudFsClient) DeleteFolder(id string) error {
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_delete_folder(obj.cCtx, idStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(id)

	return nil
}

/*
* Get shared group of users.
 */
func (obj *MessengerCloudFsClient) GetSharedGroupUsers(id string) (*MessengerCloudFsAccessList, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_get_shared_group_users(obj.cCtx, idStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(id)

	return NewMessengerCloudFsAccessListWithCtx(proxyResult) /* r6 */, nil
}

/*
* Set shared group of users.
 */
func (obj *MessengerCloudFsClient) SetSharedGroupUsers(id string, entryEncryptedKey []byte, users *MessengerCloudFsAccessList) error {
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)
	entryEncryptedKeyData := helperWrapData(entryEncryptedKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_set_shared_group_users(obj.cCtx, idStr, entryEncryptedKeyData, (*C.vssq_messenger_cloud_fs_access_list_t)(unsafe.Pointer(users.Ctx())))

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(id)

	runtime.KeepAlive(users)

	return nil
}

/*
* Return true if a user is authenticated.
 */
func (obj *MessengerCloudFsClient) IsAuthenticated() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_is_authenticated(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return information about current user.
*
* Prerequisites: user should be authenticated.
 */
func (obj *MessengerCloudFsClient) User() *MessengerUser {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_user(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserCopy(proxyResult) /* r5 */
}

/*
* Return a private key of current user.
*
* Prerequisites: user should be authenticated.
 */
func (obj *MessengerCloudFsClient) UserPrivateKey() (foundation.PrivateKey, error) {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client_user_private_key(obj.cCtx)

	runtime.KeepAlive(obj)

	return foundation.ImplementationWrapPrivateKeyCopy(proxyResult) /* r4.1 */
}
