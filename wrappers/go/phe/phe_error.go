package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"
import "fmt"


/*
* Defines the library status codes.
*/
type PheError struct {
    Code int
    Message string
}
const (
    /*
    * Success proof check failed.
    */
    PheErrorErrorInvalidSuccessProof int = -1
    /*
    * Failure proof check failed.
    */
    PheErrorErrorInvalidFailProof int = -2
    /*
    * RNG returned error.
    */
    PheErrorErrorRNGFailed int = -3
    /*
    * Protobuf decode failed.
    */
    PheErrorErrorProtobufDecodeFailed int = -4
    /*
    * Invalid public key.
    */
    PheErrorErrorInvalidPublicKey int = -5
    /*
    * Invalid private key.
    */
    PheErrorErrorInvalidPrivateKey int = -6
    /*
    * AES error occurred.
    */
    PheErrorErrorAESFailed int = -7
)

func (obj *PheError) Error() string {
    return fmt.Sprintf("PheError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func PheErrorHandleStatus(status C.vsce_status_t) error {
    if status != C.vsce_status_SUCCESS {
        switch (status) {
        case C.vsce_status_ERROR_INVALID_SUCCESS_PROOF:
            return &PheError {int(status), "Success proof check failed."}
        case C.vsce_status_ERROR_INVALID_FAIL_PROOF:
            return &PheError {int(status), "Failure proof check failed."}
        case C.vsce_status_ERROR_RNG_FAILED:
            return &PheError {int(status), "RNG returned error."}
        case C.vsce_status_ERROR_PROTOBUF_DECODE_FAILED:
            return &PheError {int(status), "Protobuf decode failed."}
        case C.vsce_status_ERROR_INVALID_PUBLIC_KEY:
            return &PheError {int(status), "Invalid public key."}
        case C.vsce_status_ERROR_INVALID_PRIVATE_KEY:
            return &PheError {int(status), "Invalid private key."}
        case C.vsce_status_ERROR_AES_FAILED:
            return &PheError {int(status), "AES error occurred."}
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
