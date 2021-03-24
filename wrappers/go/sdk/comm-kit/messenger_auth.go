package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"
import sdk_core "virgil/sdk/core"

/*
* Provides access to the messenger authentication endpoints.
 */
type MessengerAuth struct {
	cCtx *C.vssq_messenger_auth_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerAuth) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerAuth() *MessengerAuth {
	ctx := C.vssq_messenger_auth_new()
	obj := &MessengerAuth{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerAuth).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerAuthWithCtx(pointer unsafe.Pointer) *MessengerAuth {
	ctx := (*C.vssq_messenger_auth_t /*ct2*/)(pointer)
	obj := &MessengerAuth{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerAuth).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerAuthCopy(pointer unsafe.Pointer) *MessengerAuth {
	ctx := (*C.vssq_messenger_auth_t /*ct2*/)(pointer)
	obj := &MessengerAuth{
		cCtx: C.vssq_messenger_auth_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerAuth).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerAuth) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerAuth) delete() {
	C.vssq_messenger_auth_delete(obj.cCtx)
}

/*
* Initialize with a custom configuration.
 */
func NewMessengerAuthWithConfig(config *MessengerConfig) *MessengerAuth {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_new_with_config((*C.vssq_messenger_config_t)(unsafe.Pointer(config.Ctx())))

	runtime.KeepAlive(config)

	obj := &MessengerAuth{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*MessengerAuth).Delete)
	return obj
}

func (obj *MessengerAuth) SetRandom(random foundation.Random) {
	C.vssq_messenger_auth_release_random(obj.cCtx)
	C.vssq_messenger_auth_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

	runtime.KeepAlive(random)
	runtime.KeepAlive(obj)
}

/*
* Return configuration.
 */
func (obj *MessengerAuth) Config() *MessengerConfig {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_config(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerConfigCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Register a new user with a given name.
 */
func (obj *MessengerAuth) Register(username string) error {
	usernameChar := C.CString(username)
	defer C.free(unsafe.Pointer(usernameChar))
	usernameStr := C.vsc_str_from_str(usernameChar)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_register(obj.cCtx, usernameStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(username)

	return nil
}

/*
* Authenticate existing user with a given credentials.
 */
func (obj *MessengerAuth) Authenticate(creds *MessengerCreds) error {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_authenticate(obj.cCtx, (*C.vssq_messenger_creds_t)(unsafe.Pointer(creds.Ctx())))

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
func (obj *MessengerAuth) IsAuthenticated() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_is_authenticated(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return information about current user.
*
* Prerequisites: user should be authenticated.
 */
func (obj *MessengerAuth) User() *MessengerUser {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_user(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return information about current user.
*
* Prerequisites: user should be authenticated.
 */
func (obj *MessengerAuth) UserModifiable() *MessengerUser {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_user_modifiable(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerUserCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if user credentials are defined.
 */
func (obj *MessengerAuth) HasCreds() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_has_creds(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return user credentials.
 */
func (obj *MessengerAuth) Creds() *MessengerCreds {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_creds(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewMessengerCredsCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return user's private key from credentials.
*
* Prerequisites: credentials are defined.
 */
func (obj *MessengerAuth) PrivateKey() (foundation.PrivateKey, error) {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_private_key(obj.cCtx)

	runtime.KeepAlive(obj)

	return foundation.ImplementationWrapPrivateKeyCopy(proxyResult) /* r4.1 */
}

/*
* Check whether current credentials were backed up.
*
* Prerequisites: user should be authenticated.
 */
func (obj *MessengerAuth) HasBackupCreds() (bool, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_has_backup_creds(obj.cCtx, &error)

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
func (obj *MessengerAuth) BackupCreds(pwd string) error {
	pwdChar := C.CString(pwd)
	defer C.free(unsafe.Pointer(pwdChar))
	pwdStr := C.vsc_str_from_str(pwdChar)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_backup_creds(obj.cCtx, pwdStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(pwd)

	return nil
}

/*
* Restore credentials from the backup and authenticate user.
*
* Perform next steps:
* 1. Get base JWT using part of pwd.
* 2. Pull encrypted credentials from the Keyknox.
* 3. Decrypt credentials using another part of pwd.
* 4. Use credentials to authenticate within XMPP server (Ejabberd).
 */
func (obj *MessengerAuth) RestoreCreds(username string, pwd string) error {
	usernameChar := C.CString(username)
	defer C.free(unsafe.Pointer(usernameChar))
	usernameStr := C.vsc_str_from_str(usernameChar)
	pwdChar := C.CString(pwd)
	defer C.free(unsafe.Pointer(pwdChar))
	pwdStr := C.vsc_str_from_str(pwdChar)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_restore_creds(obj.cCtx, usernameStr, pwdStr)

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
func (obj *MessengerAuth) RemoveCredsBackup() error {
	proxyResult := /*pr4*/ C.vssq_messenger_auth_remove_creds_backup(obj.cCtx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	return nil
}

/*
* Get JWT to use with Virgil services based on the credentials.
*
* Prerequisites: user should be authenticated.
*
* Note, the cached token is returned if it is exist and not expired.
 */
func (obj *MessengerAuth) VirgilJwt() (*sdk_core.Jwt, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_virgil_jwt(obj.cCtx, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return sdk_core.NewJwtCopy(unsafe.Pointer(proxyResult)) /* r5 */, nil
}

/*
* Get JWT to use with Virgil Contact Discovery service based on the credentials.
*
* Prerequisites: user should be authenticated.
*
* Note, the cached token is returned if it is exist and not expired.
 */
func (obj *MessengerAuth) ContactDiscoveryJwt() (*sdk_core.Jwt, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_contact_discovery_jwt(obj.cCtx, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return sdk_core.NewJwtCopy(unsafe.Pointer(proxyResult)) /* r5 */, nil
}

/*
* Return JWT to access ejabberd server.
*
* Format: https://docs.ejabberd.im/admin/configuration/authentication/#jwt-authentication
*
* Prerequisites: user should be authenticated.
*
* Note, the cached token is returned if it is exist and not expired.
 */
func (obj *MessengerAuth) EjabberdJwt() (*EjabberdJwt, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_ejabberd_jwt(obj.cCtx, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return NewEjabberdJwtCopy(unsafe.Pointer(proxyResult)) /* r5 */, nil
}

/*
* Generate authorization header for a Virgil Messenger Backend.
*
* Header-Name : Authorization
* Header-Value: Bearer JWT
*
* Prerequisites: credentials are defined.
 */
func (obj *MessengerAuth) GenerateMessengerAuthHeader() (*sdk_core.HttpHeader, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_generate_messenger_auth_header(obj.cCtx, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return sdk_core.NewHttpHeaderWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Send HTTP request to the a Virgil Messenger Backend.
*
* Note, Authorization is added if "with auth" option is true.
 */
func (obj *MessengerAuth) SendMessengerRequest(httpRequest *sdk_core.HttpRequest, withAuth bool) (*sdk_core.HttpResponse, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_send_messenger_request(obj.cCtx, (*C.vssc_http_request_t)(unsafe.Pointer(httpRequest.Ctx())), (C.bool)(withAuth) /*pa10*/, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(httpRequest)

	return sdk_core.NewHttpResponseWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Send HTTP request to the a Virgil Service, aka Cards, Keyknox etc.
*
* Note, Virgil JWT is updated automatically.
 */
func (obj *MessengerAuth) SendVirgilRequest(httpRequest *sdk_core.HttpRequest) (*sdk_core.HttpResponse, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_send_virgil_request(obj.cCtx, (*C.vssc_http_request_t)(unsafe.Pointer(httpRequest.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(httpRequest)

	return sdk_core.NewHttpResponseWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Send HTTP request to the a Virgil Contact Discovery Service.
*
* Note, Contact Discovery JWT is updated automatically.
 */
func (obj *MessengerAuth) SendContactDiscoveryRequest(httpRequest *sdk_core.HttpRequest) (*sdk_core.HttpResponse, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_auth_send_contact_discovery_request(obj.cCtx, (*C.vssc_http_request_t)(unsafe.Pointer(httpRequest.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(httpRequest)

	return sdk_core.NewHttpResponseWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}
