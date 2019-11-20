package pythia

// #include <virgil/crypto/pythia/vscp_pythia_public.h>
import "C"
import "fmt"


/*
* Defines the library status codes.
*/
type PythiaError struct {
    Code int
    Message string
}
const (
    /*
    * This error should not be returned if assertions is enabled.
    */
    PythiaErrorErrorBadArguments int = -1
    /*
    * Underlying pythia library returns -1.
    */
    PythiaErrorErrorPythiaInnerFail int = -200
    /*
    * Underlying random number generator failed.
    */
    PythiaErrorErrorRngFailed int = -202
)

func (obj *PythiaError) Error() string {
    return fmt.Sprintf("PythiaError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func PythiaErrorHandleStatus(status C.vscp_status_t) error {
    if status != C.vscp_status_SUCCESS {
        switch (status) {
        case C.vscp_status_ERROR_BAD_ARGUMENTS:
            return &PythiaError {int(status), "This error should not be returned if assertions is enabled."}
        case C.vscp_status_ERROR_PYTHIA_INNER_FAIL:
            return &PythiaError {int(status), "Underlying pythia library returns -1."}
        case C.vscp_status_ERROR_RNG_FAILED:
            return &PythiaError {int(status), "Underlying random number generator failed."}
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
