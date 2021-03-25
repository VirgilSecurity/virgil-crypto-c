package sdk_keyknox

// #include <virgil/sdk/keyknox/vssk_keyknox_sdk_public.h>
import "C"
import "fmt"


/*
* Defines the library status codes.
*/
type KeyknoxSdkError struct {
    Code int
    Message string
}
const (
    /*
    * Met internal inconsistency.
    */
    KeyknoxSdkErrorInternalError int = -1
    /*
    * Response processing failed because given HTTP response contains Virgil Service error.
    */
    KeyknoxSdkErrorHttpResponseContainsServiceError int = -401
    /*
    * Given HTTP response body can not be parsed in an expected way.
    */
    KeyknoxSdkErrorHttpResponseBodyParseFailed int = -402
    /*
    * Failed to parse Keyknox entry from the service response.
    */
    KeyknoxSdkErrorKeyknoxEntryParseFailed int = -403
)

func (obj *KeyknoxSdkError) Error() string {
    return fmt.Sprintf("KeyknoxSdkError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func KeyknoxSdkErrorHandleStatus(status C.vssk_status_t) error {
    if status != C.vssk_status_SUCCESS {
        switch (status) {
        case C.vssk_status_INTERNAL_ERROR:
            return &KeyknoxSdkError {int(status), "Met internal inconsistency."}
        case C.vssk_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR:
            return &KeyknoxSdkError {int(status), "Response processing failed because given HTTP response contains Virgil Service error."}
        case C.vssk_status_HTTP_RESPONSE_BODY_PARSE_FAILED:
            return &KeyknoxSdkError {int(status), "Given HTTP response body can not be parsed in an expected way."}
        case C.vssk_status_KEYKNOX_ENTRY_PARSE_FAILED:
            return &KeyknoxSdkError {int(status), "Failed to parse Keyknox entry from the service response."}
        }
    }
    return nil
}

type wrapError struct {
    err error
    msg string
}

func (obj *wrapError) Error() string {
    return fmt.Sprintf("%s: %v", obj.msg, obj.err)
}

func (obj *wrapError) Unwrap() error {
    return obj.err
}
