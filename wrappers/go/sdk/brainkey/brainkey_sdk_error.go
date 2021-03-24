package sdk_brainkey

// #include <virgil/sdk/brainkey/vssb_brainkey_sdk_public.h>
import "C"
import "fmt"

/*
* Defines the library status codes.
 */
type BrainkeySdkError struct {
	Code    int
	Message string
}

const (
	/*
	 * Met internal inconsistency.
	 */
	BrainkeySdkErrorInternalError int = -1
	/*
	 * Given HTTP response body can not be parsed in an expected way.
	 */
	BrainkeySdkErrorHttpResponseParseFailed int = -401
	/*
	 * Given HTTP response handles unexpected status code.
	 */
	BrainkeySdkErrorHttpResponseError int = -402
	/*
	 * Got HTTP response with a service error - internal server error - status code 500.
	 */
	BrainkeySdkErrorHttpServiceErrorServerInternalError int = 1000
	/*
	 * Got HTTP response with a service error - bad blinded point data - status code 400.
	 */
	BrainkeySdkErrorHttpServiceErrorBadBlindedPointData int = 1001
	/*
	 * Got HTTP response with a service error - invalid json - status code 400.
	 */
	BrainkeySdkErrorHttpServiceErrorInvalidJson int = 1002
	/*
	 * Got HTTP response with a service error - undefined error - status code 400.
	 */
	BrainkeySdkErrorHttpServiceErrorUndefined int = 1999
)

func (obj *BrainkeySdkError) Error() string {
	return fmt.Sprintf("BrainkeySdkError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func BrainkeySdkErrorHandleStatus(status C.vssb_status_t) error {
	if status != C.vssb_status_SUCCESS {
		switch status {
		case C.vssb_status_INTERNAL_ERROR:
			return &BrainkeySdkError{int(status), "Met internal inconsistency."}
		case C.vssb_status_HTTP_RESPONSE_PARSE_FAILED:
			return &BrainkeySdkError{int(status), "Given HTTP response body can not be parsed in an expected way."}
		case C.vssb_status_HTTP_RESPONSE_ERROR:
			return &BrainkeySdkError{int(status), "Given HTTP response handles unexpected status code."}
		case C.vssb_status_HTTP_SERVICE_ERROR_SERVER_INTERNAL_ERROR:
			return &BrainkeySdkError{int(status), "Got HTTP response with a service error - internal server error - status code 500."}
		case C.vssb_status_HTTP_SERVICE_ERROR_BAD_BLINDED_POINT_DATA:
			return &BrainkeySdkError{int(status), "Got HTTP response with a service error - bad blinded point data - status code 400."}
		case C.vssb_status_HTTP_SERVICE_ERROR_INVALID_JSON:
			return &BrainkeySdkError{int(status), "Got HTTP response with a service error - invalid json - status code 400."}
		case C.vssb_status_HTTP_SERVICE_ERROR_UNDEFINED:
			return &BrainkeySdkError{int(status), "Got HTTP response with a service error - undefined error - status code 400."}
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
