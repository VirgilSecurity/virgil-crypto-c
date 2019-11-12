package phe

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_phe -lvsc_phe_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
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
    PHE_ERROR_ERROR_INVALID_SUCCESS_PROOF int = -1
    /*
    * Failure proof check failed.
    */
    PHE_ERROR_ERROR_INVALID_FAIL_PROOF int = -2
    /*
    * RNG returned error.
    */
    PHE_ERROR_ERROR_RNG_FAILED int = -3
    /*
    * Protobuf decode failed.
    */
    PHE_ERROR_ERROR_PROTOBUF_DECODE_FAILED int = -4
    /*
    * Invalid public key.
    */
    PHE_ERROR_ERROR_INVALID_PUBLIC_KEY int = -5
    /*
    * Invalid private key.
    */
    PHE_ERROR_ERROR_INVALID_PRIVATE_KEY int = -6
    /*
    * AES error occurred.
    */
    PHE_ERROR_ERROR_AES_FAILED int = -7
)

func (obj *PheError) Error () string {
    return fmt.Sprintf("PheError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func PheErrorHandleStatus (status C.vsce_status_t) error {
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

func (obj *wrapError) Error () string {
    return fmt.Sprintf("%s: %v", obj.msg, obj.err)
}

func (obj *wrapError) Unwrap () error {
    return obj.err
}
