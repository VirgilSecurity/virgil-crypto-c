package core.sdk

// #include <virgil/crypto/core sdk/vscs_core_core_sdk_public.h>
import "C"
import "fmt"


/*
* Defines the library status codes.
*/
type CoreSdkError struct {
    Code int
    Message string
}
const (
    /*
    * Met internal inconsistency.
    */
    CoreSdkErrorInternalError int = -1
)

func (obj *CoreSdkError) Error() string {
    return fmt.Sprintf("CoreSdkError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func CoreSdkErrorHandleStatus(status C.vscs_core_status_t) error {
    if status != C.vscs_core_status_SUCCESS {
        switch (status) {
        case C.vscs_core_status_INTERNAL_ERROR:
            return &CoreSdkError {int(status), "Met internal inconsistency."}
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
