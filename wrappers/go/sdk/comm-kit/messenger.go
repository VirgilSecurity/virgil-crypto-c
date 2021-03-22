package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"
import sdk_core "virgil/sdk/core"

/*
* Entrypoint to the messenger user management, authentication and encryption.
 */
type Messenger struct {
	cCtx *C.vssq_messenger_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *Messenger) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessenger() *Messenger {
	ctx := C.vssq_messenger_new()
	obj := &Messenger{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*Messenger).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerWithCtx(anyctx interface{}) *Messenger {
	ctx, ok := anyctx.(*C.vssq_messenger_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct Messenger."}
	}
	obj := &Messenger{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*Messenger).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCopy(anyctx interface{}) *Messenger {
	ctx, ok := anyctx.(*C.vssq_messenger_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct Messenger."}
	}
	obj := &Messenger{
		cCtx: C.vssq_messenger_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*Messenger).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *Messenger) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *Messenger) delete() {
	C.vssq_messenger_delete(obj.cCtx)
}

/*
* Initialize messenger with a custom configuration.
 */
func NewMessengerWithConfig(config *MessengerConfig) *Messenger {
	proxyResult := /*pr4*/ C.vssq_messenger_new_with_config((*C.vssq_messenger_config_t)(unsafe.Pointer(config.Ctx())))

	runtime.KeepAlive(config)

	obj := &Messenger{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*Messenger).Delete)
	return obj
}

func (obj *Messenger) SetRandom(random foundation.Random) {
	C.vssq_messenger_release_random(obj.cCtx)
	C.vssq_messenger_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

	runtime.KeepAlive(random)
	runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
 */
func (obj *Messenger) SetupDefaults() error {
	proxyResult := /*pr4*/ C.vssq_messenger_setup_defaults(obj.cCtx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	return nil
}

/*
* Register a new user with a given name.
 */
func (obj *Messenger) Register(username string) error {
	usernameChar := C.CString(username)
	defer C.free(unsafe.Pointer(usernameChar))
	usernameStr := C.vsc_str_from_str(usernameChar)

	proxyResult := /*pr4*/ C.vssq_messenger_register(obj.cCtx, usernameStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(username)

	return nil
}

/*
* Authenticate a user with a given credentials.
 */
func (obj *Messenger) Authenticate(creds *MessengerCreds) error {
	proxyResult := /*pr4*/ C.vssq_messenger_authenticate(obj.cCtx, (*C.vssq_messenger_creds_t)(unsafe.Pointer(creds.Ctx())))

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(creds)

	return nil
}

/*
* Return true if a user is authenticated.
 */
func (obj *Messenger) IsAuthenticated() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_is_authenticated(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return information about current user.
*
* Prerequisites: user should be authenticated.
 */
func (obj *Messenger) User() *MessengerUser {
	proxyResult := /*pr4*/ C.vssq_messenger_user(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserCopy(proxyResult) /* r5 */
}

/*
* Return information about current user.
*
* Prerequisites: user should be authenticated.
 */
func (obj *Messenger) UserModifiable() *MessengerUser {
	proxyResult := /*pr4*/ C.vssq_messenger_user_modifiable(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserCopy(proxyResult) /* r5 */
}

/*
* Return name of the current user.
*
* Prerequisites: user should be authenticated.
 */
func (obj *Messenger) Username() string {
	proxyResult := /*pr4*/ C.vssq_messenger_username(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return user credentials.
 */
func (obj *Messenger) Creds() *MessengerCreds {
	proxyResult := /*pr4*/ C.vssq_messenger_creds(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCredsCopy(proxyResult) /* r5 */
}

/*
* Check whether current credentials were backed up.
*
* Prerequisites: user should be authenticated.
 */
func (obj *Messenger) HasBackupCreds() (bool, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_has_backup_creds(obj.cCtx, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return false, err
	}

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */, nil
}

/*
* Encrypt the user credentials and push them to the secure cloud storage (Keyknox).
*
* Prerequisites: user should be authenticated.
 */
func (obj *Messenger) BackupCreds(pwd string) error {
	pwdChar := C.CString(pwd)
	defer C.free(unsafe.Pointer(pwdChar))
	pwdStr := C.vsc_str_from_str(pwdChar)

	proxyResult := /*pr4*/ C.vssq_messenger_backup_creds(obj.cCtx, pwdStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(pwd)

	return nil
}

/*
* Authenticate user by using backup credentials.
 */
func (obj *Messenger) AuthenticateWithBackupCreds(username string, pwd string) error {
	usernameChar := C.CString(username)
	defer C.free(unsafe.Pointer(usernameChar))
	usernameStr := C.vsc_str_from_str(usernameChar)
	pwdChar := C.CString(pwd)
	defer C.free(unsafe.Pointer(pwdChar))
	pwdStr := C.vsc_str_from_str(pwdChar)

	proxyResult := /*pr4*/ C.vssq_messenger_authenticate_with_backup_creds(obj.cCtx, usernameStr, pwdStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(username)

	runtime.KeepAlive(pwd)

	return nil
}

/*
* Remove credentials backup from the secure cloud storage (Keyknox).
*
* Prerequisites: user should be authenticated.
 */
func (obj *Messenger) RemoveCredsBackup() error {
	proxyResult := /*pr4*/ C.vssq_messenger_remove_creds_backup(obj.cCtx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	return nil
}

/*
* Return authentication module.
*
* It should be used with great carefulness and responsibility.
 */
func (obj *Messenger) Auth() *MessengerAuth {
	proxyResult := /*pr4*/ C.vssq_messenger_auth(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerAuthCopy(proxyResult) /* r5 */
}

/*
* Return founded user or error.
 */
func (obj *Messenger) FindUserWithIdentity(identity string) (*MessengerUser, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	identityChar := C.CString(identity)
	defer C.free(unsafe.Pointer(identityChar))
	identityStr := C.vsc_str_from_str(identityChar)

	proxyResult := /*pr4*/ C.vssq_messenger_find_user_with_identity(obj.cCtx, identityStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(identity)

	return NewMessengerUserWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return founded users or error.
 */
func (obj *Messenger) FindUsersWithIdentities(identities *sdk_core.StringList) (*MessengerUserList, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_find_users_with_identities(obj.cCtx, (*C.vssc_string_list_t)(unsafe.Pointer(identities.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(identities)

	return NewMessengerUserListWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return founded user or error.
 */
func (obj *Messenger) FindUserWithUsername(username string) (*MessengerUser, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	usernameChar := C.CString(username)
	defer C.free(unsafe.Pointer(usernameChar))
	usernameStr := C.vsc_str_from_str(usernameChar)

	proxyResult := /*pr4*/ C.vssq_messenger_find_user_with_username(obj.cCtx, usernameStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(username)

	return NewMessengerUserWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return founded users.
 */
func (obj *Messenger) FindUsersByPhones(phones *sdk_core.StringList) (*MessengerUserList, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_find_users_by_phones(obj.cCtx, (*C.vssc_string_list_t)(unsafe.Pointer(phones.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(phones)

	return NewMessengerUserListWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return founded users.
 */
func (obj *Messenger) FindUsersByEmails(emails *sdk_core.StringList) (*MessengerUserList, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_find_users_by_emails(obj.cCtx, (*C.vssc_string_list_t)(unsafe.Pointer(emails.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(emails)

	return NewMessengerUserListWithCtx(proxyResult) /* r6 */, nil
}

/*
* Register user's phone number.
*
* Prerequisites: phone numbers are formatted according to E.164 standard.
 */
func (obj *Messenger) AddPhoneNumber(phoneNumber string) error {
	phoneNumberChar := C.CString(phoneNumber)
	defer C.free(unsafe.Pointer(phoneNumberChar))
	phoneNumberStr := C.vsc_str_from_str(phoneNumberChar)

	proxyResult := /*pr4*/ C.vssq_messenger_add_phone_number(obj.cCtx, phoneNumberStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(phoneNumber)

	return nil
}

/*
* Confirm user's phone number.
*
* Prerequisites: phone numbers are formatted according to E.164 standard.
 */
func (obj *Messenger) ConfirmPhoneNumber(phoneNumber string, confirmationCode string) error {
	phoneNumberChar := C.CString(phoneNumber)
	defer C.free(unsafe.Pointer(phoneNumberChar))
	phoneNumberStr := C.vsc_str_from_str(phoneNumberChar)
	confirmationCodeChar := C.CString(confirmationCode)
	defer C.free(unsafe.Pointer(confirmationCodeChar))
	confirmationCodeStr := C.vsc_str_from_str(confirmationCodeChar)

	proxyResult := /*pr4*/ C.vssq_messenger_confirm_phone_number(obj.cCtx, phoneNumberStr, confirmationCodeStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(phoneNumber)

	runtime.KeepAlive(confirmationCode)

	return nil
}

/*
* Delete user's phone number.
*
* Prerequisites: phone numbers are formatted according to E.164 standard.
 */
func (obj *Messenger) DeletePhoneNumber(phoneNumber string) error {
	phoneNumberChar := C.CString(phoneNumber)
	defer C.free(unsafe.Pointer(phoneNumberChar))
	phoneNumberStr := C.vsc_str_from_str(phoneNumberChar)

	proxyResult := /*pr4*/ C.vssq_messenger_delete_phone_number(obj.cCtx, phoneNumberStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(phoneNumber)

	return nil
}

/*
* Register user's email.
 */
func (obj *Messenger) AddEmail(email string) error {
	emailChar := C.CString(email)
	defer C.free(unsafe.Pointer(emailChar))
	emailStr := C.vsc_str_from_str(emailChar)

	proxyResult := /*pr4*/ C.vssq_messenger_add_email(obj.cCtx, emailStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(email)

	return nil
}

/*
* Confirm user's email.
 */
func (obj *Messenger) ConfirmEmail(email string, confirmationCode string) error {
	emailChar := C.CString(email)
	defer C.free(unsafe.Pointer(emailChar))
	emailStr := C.vsc_str_from_str(emailChar)
	confirmationCodeChar := C.CString(confirmationCode)
	defer C.free(unsafe.Pointer(confirmationCodeChar))
	confirmationCodeStr := C.vsc_str_from_str(confirmationCodeChar)

	proxyResult := /*pr4*/ C.vssq_messenger_confirm_email(obj.cCtx, emailStr, confirmationCodeStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(email)

	runtime.KeepAlive(confirmationCode)

	return nil
}

/*
* Delete user's email.
 */
func (obj *Messenger) DeleteEmail(email string) error {
	emailChar := C.CString(email)
	defer C.free(unsafe.Pointer(emailChar))
	emailStr := C.vsc_str_from_str(emailChar)

	proxyResult := /*pr4*/ C.vssq_messenger_delete_email(obj.cCtx, emailStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(email)

	return nil
}

/*
* Return a buffer length enough to hold an encrypted message.
 */
func (obj *Messenger) EncryptedMessageLen(messageLen uint, recipient *MessengerUser) uint {
	proxyResult := /*pr4*/ C.vssq_messenger_encrypted_message_len(obj.cCtx, (C.size_t)(messageLen) /*pa10*/, (*C.vssq_messenger_user_t)(unsafe.Pointer(recipient.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(recipient)

	return uint(proxyResult) /* r9 */
}

/*
* Encrypt a text message.
 */
func (obj *Messenger) EncryptText(text string, recipient *MessengerUser) ([]byte, error) {
	textChar := C.CString(text)
	defer C.free(unsafe.Pointer(textChar))
	textStr := C.vsc_str_from_str(textChar)

	outBuf, outBufErr := newBuffer(int(obj.EncryptedMessageLen(uint(len(text)), recipient) /* lg2 */))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()

	proxyResult := /*pr4*/ C.vssq_messenger_encrypt_text(obj.cCtx, textStr, (*C.vssq_messenger_user_t)(unsafe.Pointer(recipient.Ctx())), outBuf.ctx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(text)

	runtime.KeepAlive(recipient)

	return outBuf.getData() /* r7 */, nil
}

/*
* Encrypt a binary message.
 */
func (obj *Messenger) EncryptData(data []byte, recipient *MessengerUser) ([]byte, error) {
	outBuf, outBufErr := newBuffer(int(obj.EncryptedMessageLen(uint(len(data)), recipient) /* lg2 */))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()
	dataData := helperWrapData(data)

	proxyResult := /*pr4*/ C.vssq_messenger_encrypt_data(obj.cCtx, dataData, (*C.vssq_messenger_user_t)(unsafe.Pointer(recipient.Ctx())), outBuf.ctx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(recipient)

	return outBuf.getData() /* r7 */, nil
}

/*
* Return a buffer length enough to hold a decrypted message.
 */
func (obj *Messenger) DecryptedMessageLen(encryptedMessageLen uint) uint {
	proxyResult := /*pr4*/ C.vssq_messenger_decrypted_message_len(obj.cCtx, (C.size_t)(encryptedMessageLen) /*pa10*/)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Decrypt a text message.
 */
func (obj *Messenger) DecryptText(encryptedText []byte, sender *MessengerUser) (string, error) {
	outBuf := C.vsc_str_buffer_new_with_capacity((C.size_t)(obj.DecryptedMessageLen(uint(len(encryptedText))) /* lg2 */))
	defer C.vsc_str_buffer_delete(outBuf)
	encryptedTextData := helperWrapData(encryptedText)

	proxyResult := /*pr4*/ C.vssq_messenger_decrypt_text(obj.cCtx, encryptedTextData, (*C.vssq_messenger_user_t)(unsafe.Pointer(sender.Ctx())), outBuf)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(sender)

	return C.GoString(C.vsc_str_buffer_chars(outBuf)) /* r7.1 */, nil
}

/*
* Decrypt a binary message.
 */
func (obj *Messenger) DecryptData(encryptedData []byte, sender *MessengerUser) ([]byte, error) {
	outBuf, outBufErr := newBuffer(int(obj.DecryptedMessageLen(uint(len(encryptedData))) /* lg2 */))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()
	encryptedDataData := helperWrapData(encryptedData)

	proxyResult := /*pr4*/ C.vssq_messenger_decrypt_data(obj.cCtx, encryptedDataData, (*C.vssq_messenger_user_t)(unsafe.Pointer(sender.Ctx())), outBuf.ctx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(sender)

	return outBuf.getData() /* r7 */, nil
}

/*
* Create a new group for a group messaging.
*
* Prerequisites: user should be authenticated.
* Note, group owner is added to the participants automatically.
 */
func (obj *Messenger) CreateGroup(groupId string, participants *MessengerUserList) (*MessengerGroup, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	groupIdChar := C.CString(groupId)
	defer C.free(unsafe.Pointer(groupIdChar))
	groupIdStr := C.vsc_str_from_str(groupIdChar)

	proxyResult := /*pr4*/ C.vssq_messenger_create_group(obj.cCtx, groupIdStr, (*C.vssq_messenger_user_list_t)(unsafe.Pointer(participants.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(groupId)

	runtime.KeepAlive(participants)

	return NewMessengerGroupWithCtx(proxyResult) /* r6 */, nil
}

/*
* Load an existing group for a group messaging.
*
* Prerequisites: user should be authenticated.
 */
func (obj *Messenger) LoadGroup(groupId string, owner *MessengerUser) (*MessengerGroup, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	groupIdChar := C.CString(groupId)
	defer C.free(unsafe.Pointer(groupIdChar))
	groupIdStr := C.vsc_str_from_str(groupIdChar)

	proxyResult := /*pr4*/ C.vssq_messenger_load_group(obj.cCtx, groupIdStr, (*C.vssq_messenger_user_t)(unsafe.Pointer(owner.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(groupId)

	runtime.KeepAlive(owner)

	return NewMessengerGroupWithCtx(proxyResult) /* r6 */, nil
}

/*
* Returns module for working with the CLoud FS.
 */
func (obj *Messenger) CloudFs() *MessengerCloudFs {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCloudFsCopy(proxyResult) /* r5 */
}
