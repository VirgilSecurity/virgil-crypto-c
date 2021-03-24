package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import sdk_core "virgil/sdk/core"
import foundation "virgil/foundation"

/*
* Information about a messenger user, i.e. username, Virgil Card, etc.
 */
type MessengerUser struct {
	cCtx *C.vssq_messenger_user_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerUser) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerUser() *MessengerUser {
	ctx := C.vssq_messenger_user_new()
	obj := &MessengerUser{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerUser).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerUserWithCtx(pointer unsafe.Pointer) *MessengerUser {
	ctx := (*C.vssq_messenger_user_t /*ct2*/)(pointer)
	obj := &MessengerUser{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerUser).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerUserCopy(pointer unsafe.Pointer) *MessengerUser {
	ctx := (*C.vssq_messenger_user_t /*ct2*/)(pointer)
	obj := &MessengerUser{
		cCtx: C.vssq_messenger_user_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerUser).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerUser) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerUser) delete() {
	C.vssq_messenger_user_delete(obj.cCtx)
}

/*
* Create an object with required fields.
 */
func NewMessengerUserWithCard(card *sdk_core.Card) *MessengerUser {
	proxyResult := /*pr4*/ C.vssq_messenger_user_new_with_card((*C.vssc_card_t)(unsafe.Pointer(card.Ctx())))

	runtime.KeepAlive(card)

	obj := &MessengerUser{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*MessengerUser).Delete)
	return obj
}

/*
* Return a user's Card.
 */
func (obj *MessengerUser) Card() *sdk_core.Card {
	proxyResult := /*pr4*/ C.vssq_messenger_user_card(obj.cCtx)

	runtime.KeepAlive(obj)

	return sdk_core.NewCardCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return a user's identity (Card's identity).
 */
func (obj *MessengerUser) Identity() string {
	proxyResult := /*pr4*/ C.vssq_messenger_user_identity(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return a user's public key (Card's public key).
 */
func (obj *MessengerUser) PublicKey() (foundation.PublicKey, error) {
	proxyResult := /*pr4*/ C.vssq_messenger_user_public_key(obj.cCtx)

	runtime.KeepAlive(obj)

	return foundation.ImplementationWrapPublicKeyCopy(proxyResult) /* r4.1 */
}

/*
* Return a user's public key identifier (Card's public key identifier).
 */
func (obj *MessengerUser) PublicKeyId() []byte {
	proxyResult := /*pr4*/ C.vssq_messenger_user_public_key_id(obj.cCtx)

	runtime.KeepAlive(obj)

	return helperExtractData(proxyResult) /* r1 */
}

/*
* Return true if a username defined.
 */
func (obj *MessengerUser) HasUsername() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_user_has_username(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return username, or an empty string if username not defined.
 */
func (obj *MessengerUser) Username() string {
	proxyResult := /*pr4*/ C.vssq_messenger_user_username(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Set an optional username.
 */
func (obj *MessengerUser) SetUsername(username string) {
	usernameChar := C.CString(username)
	defer C.free(unsafe.Pointer(usernameChar))
	usernameStr := C.vsc_str_from_str(usernameChar)

	C.vssq_messenger_user_set_username(obj.cCtx, usernameStr)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(username)

	return
}

/*
* Return true if a phone number defined.
 */
func (obj *MessengerUser) HasPhoneNumber() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_user_has_phone_number(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return phone number, or an empty string if phone number not defined.
 */
func (obj *MessengerUser) PhoneNumber() string {
	proxyResult := /*pr4*/ C.vssq_messenger_user_phone_number(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Set an optional phone number.
 */
func (obj *MessengerUser) SetPhoneNumber(phoneNumber string) {
	phoneNumberChar := C.CString(phoneNumber)
	defer C.free(unsafe.Pointer(phoneNumberChar))
	phoneNumberStr := C.vsc_str_from_str(phoneNumberChar)

	C.vssq_messenger_user_set_phone_number(obj.cCtx, phoneNumberStr)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(phoneNumber)

	return
}

/*
* Return true if a email defined.
 */
func (obj *MessengerUser) HasEmail() bool {
	proxyResult := /*pr4*/ C.vssq_messenger_user_has_email(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return email, or an empty string if email not defined.
 */
func (obj *MessengerUser) Email() string {
	proxyResult := /*pr4*/ C.vssq_messenger_user_email(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Set an optional email.
 */
func (obj *MessengerUser) SetEmail(email string) {
	emailChar := C.CString(email)
	defer C.free(unsafe.Pointer(emailChar))
	emailStr := C.vsc_str_from_str(emailChar)

	C.vssq_messenger_user_set_email(obj.cCtx, emailStr)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(email)

	return
}

/*
* Return user as JSON object.
 */
func (obj *MessengerUser) ToJson() (*sdk_core.JsonObject, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_user_to_json(obj.cCtx, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return sdk_core.NewJsonObjectWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Parse user from JSON.
 */
func MessengerUserFromJson(jsonObj *sdk_core.JsonObject, random foundation.Random) (*MessengerUser, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_messenger_user_from_json((*C.vssc_json_object_t)(unsafe.Pointer(jsonObj.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(jsonObj)

	runtime.KeepAlive(random)

	return NewMessengerUserWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Parse user from JSON string.
 */
func MessengerUserFromJsonStr(jsonStr string, random foundation.Random) (*MessengerUser, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	jsonStrChar := C.CString(jsonStr)
	defer C.free(unsafe.Pointer(jsonStrChar))
	jsonStrStr := C.vsc_str_from_str(jsonStrChar)

	proxyResult := /*pr4*/ C.vssq_messenger_user_from_json_str(jsonStrStr, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(jsonStr)

	runtime.KeepAlive(random)

	return NewMessengerUserWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}
