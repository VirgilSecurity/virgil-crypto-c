package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import sdk_core "virgil/sdk/core"

/*
* Helps to normalize and hash user contacts: username, email, phone, etc.
 */
type ContactUtils struct {
}

const (
	ContactUtilsDigestHexLen   uint = 64
	ContactUtilsUsernameLenMax uint = 20
)

/*
* Validate and normalize username.
*
* Validation rules:
* 1. Length in the range: [1..20]
* 2. Do not start or end with an underscore
* 3. Do not start with a number
* 4. Match regex: ^[a-zA-Z0-9_]+$
*
* Normalization rules:
* 1. To lowercase
 */
func ContactUtilsNormalizeUsername(username string) (string, error) {
	usernameChar := C.CString(username)
	defer C.free(unsafe.Pointer(usernameChar))
	usernameStr := C.vsc_str_from_str(usernameChar)

	normalizedBuf := C.vsc_str_buffer_new_with_capacity((C.size_t)(len(username)))
	defer C.vsc_str_buffer_delete(normalizedBuf)

	proxyResult := /*pr4*/ C.vssq_contact_utils_normalize_username(usernameStr, normalizedBuf)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(username)

	return C.GoString(C.vsc_str_buffer_chars(normalizedBuf)) /* r7.1 */, nil
}

/*
* Validate, normalize, and hash username.
 */
func ContactUtilsHashUsername(username string) (string, error) {
	usernameChar := C.CString(username)
	defer C.free(unsafe.Pointer(usernameChar))
	usernameStr := C.vsc_str_from_str(usernameChar)

	digestHexBuf := C.vsc_str_buffer_new_with_capacity((C.size_t)(ContactUtilsDigestHexLen /* lg4 */))
	defer C.vsc_str_buffer_delete(digestHexBuf)

	proxyResult := /*pr4*/ C.vssq_contact_utils_hash_username(usernameStr, digestHexBuf)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(username)

	return C.GoString(C.vsc_str_buffer_chars(digestHexBuf)) /* r7.1 */, nil
}

/*
* Validate, normalize, and hash each username.
*
* Return a map "username->hash".
*
* Note, usernames in the returned map equals to the given.
 */
func ContactUtilsHashUsernames(usernames *sdk_core.StringList) (*sdk_core.StringMap, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_contact_utils_hash_usernames((*C.vssc_string_list_t)(unsafe.Pointer(usernames.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(usernames)

	return sdk_core.NewStringMapWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Validate phone number.
*
* Validation rules:
* 1. Start with plus (+) sign.
* 2. Contains only digits after plus sign.
* 3. Phone number max 15 digits.
 */
func ContactUtilsValidatePhoneNumber(phoneNumber string) error {
	phoneNumberChar := C.CString(phoneNumber)
	defer C.free(unsafe.Pointer(phoneNumberChar))
	phoneNumberStr := C.vsc_str_from_str(phoneNumberChar)

	proxyResult := /*pr4*/ C.vssq_contact_utils_validate_phone_number(phoneNumberStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(phoneNumber)

	return nil
}

/*
* Validate, and hash phone number.
*
* Validation rules:
* 1. Start with plus (+) sign.
* 2. Contains only digits after plus sign.
* 3. Phone number max 15 digits.
*
* Note, for now given phone number is not formatted.
 */
func ContactUtilsHashPhoneNumber(phoneNumber string) (string, error) {
	phoneNumberChar := C.CString(phoneNumber)
	defer C.free(unsafe.Pointer(phoneNumberChar))
	phoneNumberStr := C.vsc_str_from_str(phoneNumberChar)

	digestHexBuf := C.vsc_str_buffer_new_with_capacity((C.size_t)(ContactUtilsDigestHexLen /* lg4 */))
	defer C.vsc_str_buffer_delete(digestHexBuf)

	proxyResult := /*pr4*/ C.vssq_contact_utils_hash_phone_number(phoneNumberStr, digestHexBuf)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(phoneNumber)

	return C.GoString(C.vsc_str_buffer_chars(digestHexBuf)) /* r7.1 */, nil
}

/*
* Validate, and hash each phone number.
*
* Return a map "phone-number->hash".
*
* Note, phone numbers in the returned map equals to the given.
 */
func ContactUtilsHashPhoneNumbers(phoneNumbers *sdk_core.StringList) (*sdk_core.StringMap, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_contact_utils_hash_phone_numbers((*C.vssc_string_list_t)(unsafe.Pointer(phoneNumbers.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(phoneNumbers)

	return sdk_core.NewStringMapWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Validate email.
*
* Validation rules:
* 1. Check email regex: "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+$)".
 */
func ContactUtilsValidateEmail(email string) error {
	emailChar := C.CString(email)
	defer C.free(unsafe.Pointer(emailChar))
	emailStr := C.vsc_str_from_str(emailChar)

	proxyResult := /*pr4*/ C.vssq_contact_utils_validate_email(emailStr)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(email)

	return nil
}

/*
* Validate, normalize and hash email.
*
* Validation rules:
* 1. Check email regex: "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+$)".
*
* Normalization rules:
* 1. To lowercase
* 2. Remove dots.
* 3. Remove suffix that starts with a plus sign.
 */
func ContactUtilsHashEmail(email string) (string, error) {
	emailChar := C.CString(email)
	defer C.free(unsafe.Pointer(emailChar))
	emailStr := C.vsc_str_from_str(emailChar)

	digestHexBuf := C.vsc_str_buffer_new_with_capacity((C.size_t)(ContactUtilsDigestHexLen /* lg4 */))
	defer C.vsc_str_buffer_delete(digestHexBuf)

	proxyResult := /*pr4*/ C.vssq_contact_utils_hash_email(emailStr, digestHexBuf)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(email)

	return C.GoString(C.vsc_str_buffer_chars(digestHexBuf)) /* r7.1 */, nil
}

/*
* Validate, normalize, and hash each email.
*
* Return a map "email->hash".
*
* Note, emails in the returned map equals to the given.
 */
func ContactUtilsHashEmails(emails *sdk_core.StringList) (*sdk_core.StringMap, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)

	proxyResult := /*pr4*/ C.vssq_contact_utils_hash_emails((*C.vssc_string_list_t)(unsafe.Pointer(emails.Ctx())), &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(emails)

	return sdk_core.NewStringMapWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Merge "contact request map" with "contact response map".
*
* Contact request map : username | email | phone-number -> hash
* Contact response map: hash -> identity
* Final map : username | email | phone-number -> identity
 */
func ContactUtilsMergeContactDiscoveryMaps(contactRequestMap *sdk_core.StringMap, contactResponseMap *sdk_core.StringMap) *sdk_core.StringMap {
	proxyResult := /*pr4*/ C.vssq_contact_utils_merge_contact_discovery_maps((*C.vssc_string_map_t)(unsafe.Pointer(contactRequestMap.Ctx())), (*C.vssc_string_map_t)(unsafe.Pointer(contactResponseMap.Ctx())))

	runtime.KeepAlive(contactRequestMap)

	runtime.KeepAlive(contactResponseMap)

	return sdk_core.NewStringMapWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}
