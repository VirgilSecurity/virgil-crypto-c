package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"

/*
* This class provides access to the messenger Cloud File System, that can be used to store and share files.
 */
type MessengerCloudFs struct {
	cCtx *C.vssq_messenger_cloud_fs_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFs) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFs() *MessengerCloudFs {
	ctx := C.vssq_messenger_cloud_fs_new()
	obj := &MessengerCloudFs{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFs).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsWithCtx(anyctx interface{}) *MessengerCloudFs {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFs."}
	}
	obj := &MessengerCloudFs{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFs).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsCopy(anyctx interface{}) *MessengerCloudFs {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFs."}
	}
	obj := &MessengerCloudFs{
		cCtx: C.vssq_messenger_cloud_fs_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFs).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFs) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFs) delete() {
	C.vssq_messenger_cloud_fs_delete(obj.cCtx)
}

func (obj *MessengerCloudFs) SetClient(client *MessengerCloudFsClient) {
	C.vssq_messenger_cloud_fs_release_client(obj.cCtx)
	C.vssq_messenger_cloud_fs_use_client(obj.cCtx, (*C.vssq_messenger_cloud_fs_client_t)(unsafe.Pointer(client.Ctx())))

	runtime.KeepAlive(client)
	runtime.KeepAlive(obj)
}

func (obj *MessengerCloudFs) SetRandom(random foundation.Random) {
	C.vssq_messenger_cloud_fs_release_random(obj.cCtx)
	C.vssq_messenger_cloud_fs_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

	runtime.KeepAlive(random)
	runtime.KeepAlive(obj)
}

/*
* Return the Cloud FS client.
 */
func (obj *MessengerCloudFs) Client() *MessengerCloudFsClient {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_client(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCloudFsClientCopy(proxyResult) /* r5 */
}

/*
* Create a new file within the Cloud FS.
* Note, if folder id is empty then file created in a root folder.
 */
func (obj *MessengerCloudFs) CreateFile(name string, mimeTipe string, size uint, fileKey []byte, parentFolderId string, parentFolderPublicKey []byte) (*MessengerCloudFsCreatedFile, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)
	mimeTipeChar := C.CString(mimeTipe)
	defer C.free(unsafe.Pointer(mimeTipeChar))
	mimeTipeStr := C.vsc_str_from_str(mimeTipeChar)
	parentFolderIdChar := C.CString(parentFolderId)
	defer C.free(unsafe.Pointer(parentFolderIdChar))
	parentFolderIdStr := C.vsc_str_from_str(parentFolderIdChar)
	fileKeyData := helperWrapData(fileKey)
	parentFolderPublicKeyData := helperWrapData(parentFolderPublicKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_create_file(obj.cCtx, nameStr, mimeTipeStr, (C.size_t)(size) /*pa10*/, fileKeyData, parentFolderIdStr, parentFolderPublicKeyData, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(name)

	runtime.KeepAlive(mimeTipe)

	runtime.KeepAlive(parentFolderId)

	return NewMessengerCloudFsCreatedFileWithCtx(proxyResult) /* r6 */, nil
}

/*
* Get a file download link.
 */
func (obj *MessengerCloudFs) GetDownloadLink(id string) (*MessengerCloudFsFileDownloadInfo, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_get_download_link(obj.cCtx, idStr, &error)

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
func (obj *MessengerCloudFs) DeleteFile(id string) error {
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_delete_file(obj.cCtx, idStr)

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
func (obj *MessengerCloudFs) CreateFolder(name string, parentFolderId string, parentFolderPublicKey []byte) (*MessengerCloudFsFolderInfo, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)
	parentFolderIdChar := C.CString(parentFolderId)
	defer C.free(unsafe.Pointer(parentFolderIdChar))
	parentFolderIdStr := C.vsc_str_from_str(parentFolderIdChar)
	parentFolderPublicKeyData := helperWrapData(parentFolderPublicKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_create_folder(obj.cCtx, nameStr, parentFolderIdStr, parentFolderPublicKeyData, &error)

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
func (obj *MessengerCloudFs) CreateSharedFolder(name string, parentFolderId string, parentFolderPublicKey []byte, usersAccess *MessengerCloudFsAccessList) (*MessengerCloudFsFolderInfo, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)
	parentFolderIdChar := C.CString(parentFolderId)
	defer C.free(unsafe.Pointer(parentFolderIdChar))
	parentFolderIdStr := C.vsc_str_from_str(parentFolderIdChar)
	parentFolderPublicKeyData := helperWrapData(parentFolderPublicKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_create_shared_folder(obj.cCtx, nameStr, parentFolderIdStr, parentFolderPublicKeyData, (*C.vssq_messenger_cloud_fs_access_list_t)(unsafe.Pointer(usersAccess.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(name)

	runtime.KeepAlive(parentFolderId)

	runtime.KeepAlive(usersAccess)

	return NewMessengerCloudFsFolderInfoWithCtx(proxyResult) /* r6 */, nil
}

/*
* List content of requested folder.
* Note, if folder id is empty then a root folder will be listed.
 */
func (obj *MessengerCloudFs) ListFolder(id string) (*MessengerCloudFsFolder, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_list_folder(obj.cCtx, idStr, &error)

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
func (obj *MessengerCloudFs) DeleteFolder(id string) error {
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_delete_folder(obj.cCtx, idStr)

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
func (obj *MessengerCloudFs) GetSharedGroupUsers(id string) (*MessengerCloudFsAccessList, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_get_shared_group_users(obj.cCtx, idStr, &error)

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
func (obj *MessengerCloudFs) SetSharedGroupUsers(id string, encryptedGroupKey []byte, keyIssuer *MessengerUser, usersAccess *MessengerCloudFsAccessList) error {
	idChar := C.CString(id)
	defer C.free(unsafe.Pointer(idChar))
	idStr := C.vsc_str_from_str(idChar)
	encryptedGroupKeyData := helperWrapData(encryptedGroupKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_set_shared_group_users(obj.cCtx, idStr, encryptedGroupKeyData, (*C.vssq_messenger_user_t)(unsafe.Pointer(keyIssuer.Ctx())), (*C.vssq_messenger_cloud_fs_access_list_t)(unsafe.Pointer(usersAccess.Ctx())))

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(id)

	runtime.KeepAlive(keyIssuer)

	runtime.KeepAlive(usersAccess)

	return nil
}

/*
* Return true if a user is authenticated.
 */
func (obj *MessengerCloudFs) IsAuthenticated() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_is_authenticated(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return information about current user.
*
* Prerequisites: user should be authenticated.
 */
func (obj *MessengerCloudFs) User() *MessengerUser {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_user(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserCopy(proxyResult) /* r5 */
}

/*
* Return a private key of current user.
*
* Prerequisites: user should be authenticated.
 */
func (obj *MessengerCloudFs) UserPrivateKey() (foundation.PrivateKey, error) {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_user_private_key(obj.cCtx)

	runtime.KeepAlive(obj)

	return foundation.ImplementationWrapPrivateKeyCopy(proxyResult) /* r4.1 */
}

/*
* Return buffer length required to hold "decrypted key" written by the "decrypt key" method.
 */
func (obj *MessengerCloudFs) DecryptedKeyLen(encryptedKey []byte) uint {
	encryptedKeyData := helperWrapData(encryptedKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_decrypted_key_len(obj.cCtx, encryptedKeyData)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Decrypt file/folder key with current user key:
* Note, issuer is a person who produced an encrypted key.
 */
func (obj *MessengerCloudFs) DecryptKey(encryptedKey []byte, issuer *MessengerUser) ([]byte, error) {
	decryptedKeyBuf, decryptedKeyBufErr := newBuffer(int(obj.DecryptedKeyLen(encryptedKey) /* lg2 */))
	if decryptedKeyBufErr != nil {
		return nil, decryptedKeyBufErr
	}
	defer decryptedKeyBuf.delete()
	encryptedKeyData := helperWrapData(encryptedKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_decrypt_key(obj.cCtx, encryptedKeyData, (*C.vssq_messenger_user_t)(unsafe.Pointer(issuer.Ctx())), decryptedKeyBuf.ctx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(issuer)

	return decryptedKeyBuf.getData() /* r7 */, nil
}

/*
* Decrypt file/folder key with a given parent folder key:
* Note, issuer is a person who produced an encrypted key.
 */
func (obj *MessengerCloudFs) DecryptKeyWithParentFolderKey(encryptedKey []byte, issuer *MessengerUser, parentFolderId string, parentFolderKey []byte) ([]byte, error) {
	parentFolderIdChar := C.CString(parentFolderId)
	defer C.free(unsafe.Pointer(parentFolderIdChar))
	parentFolderIdStr := C.vsc_str_from_str(parentFolderIdChar)

	decryptedKeyBuf, decryptedKeyBufErr := newBuffer(int(obj.DecryptedKeyLen(encryptedKey) /* lg2 */))
	if decryptedKeyBufErr != nil {
		return nil, decryptedKeyBufErr
	}
	defer decryptedKeyBuf.delete()
	encryptedKeyData := helperWrapData(encryptedKey)
	parentFolderKeyData := helperWrapData(parentFolderKey)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_decrypt_key_with_parent_folder_key(obj.cCtx, encryptedKeyData, (*C.vssq_messenger_user_t)(unsafe.Pointer(issuer.Ctx())), parentFolderIdStr, parentFolderKeyData, decryptedKeyBuf.ctx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(issuer)

	runtime.KeepAlive(parentFolderId)

	return decryptedKeyBuf.getData() /* r7 */, nil
}
