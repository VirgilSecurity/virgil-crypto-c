package ratchet

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_ratchet -lvsc_ratchet_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"
import "fmt"


/*
* Defines the library status codes.
*/
type RatchetError struct {
    Code int
    Message string
}
const (
    /*
    * Error during protobuf deserialization.
    */
    RATCHET_ERROR_ERROR_PROTOBUF_DECODE int = -1
    /*
    * Bad message type.
    */
    RATCHET_ERROR_ERROR_BAD_MESSAGE_TYPE int = -2
    /*
    * AES error.
    */
    RATCHET_ERROR_ERROR_AES int = -3
    /*
    * RNG failed.
    */
    RATCHET_ERROR_ERROR_RNG_FAILED int = -4
    /*
    * Curve25519 error.
    */
    RATCHET_ERROR_ERROR_CURVE25519 int = -5
    /*
    * Curve25519 error.
    */
    RATCHET_ERROR_ERROR_ED25519 int = -6
    /*
    * Key deserialization failed.
    */
    RATCHET_ERROR_ERROR_KEY_DESERIALIZATION_FAILED int = -7
    /*
    * Invalid key type.
    */
    RATCHET_ERROR_ERROR_INVALID_KEY_TYPE int = -8
    /*
    * Identity key doesn't match.
    */
    RATCHET_ERROR_ERROR_IDENTITY_KEY_DOESNT_MATCH int = -9
    /*
    * Message already decrypted.
    */
    RATCHET_ERROR_ERROR_MESSAGE_ALREADY_DECRYPTED int = -10
    /*
    * Too many lost messages.
    */
    RATCHET_ERROR_ERROR_TOO_MANY_LOST_MESSAGES int = -11
    /*
    * Sender chain missing.
    */
    RATCHET_ERROR_ERROR_SENDER_CHAIN_MISSING int = -12
    /*
    * Skipped message missing.
    */
    RATCHET_ERROR_ERROR_SKIPPED_MESSAGE_MISSING int = -13
    /*
    * Session is not initialized.
    */
    RATCHET_ERROR_ERROR_SESSION_IS_NOT_INITIALIZED int = -14
    /*
    * Exceeded max plain text len.
    */
    RATCHET_ERROR_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN int = -15
    /*
    * Too many messages for sender chain.
    */
    RATCHET_ERROR_ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN int = -16
    /*
    * Too many messages for receiver chain.
    */
    RATCHET_ERROR_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN int = -17
    /*
    * Invalid padding.
    */
    RATCHET_ERROR_ERROR_INVALID_PADDING int = -18
    /*
    * Too many participants.
    */
    RATCHET_ERROR_ERROR_TOO_MANY_PARTICIPANTS int = -19
    /*
    * Too few participants.
    */
    RATCHET_ERROR_ERROR_TOO_FEW_PARTICIPANTS int = -20
    /*
    * Sender not found.
    */
    RATCHET_ERROR_ERROR_SENDER_NOT_FOUND int = -21
    /*
    * Cannot decrypt own messages.
    */
    RATCHET_ERROR_ERROR_CANNOT_DECRYPT_OWN_MESSAGES int = -22
    /*
    * Invalid signature.
    */
    RATCHET_ERROR_ERROR_INVALID_SIGNATURE int = -23
    /*
    * Cannot remove myself.
    */
    RATCHET_ERROR_ERROR_CANNOT_REMOVE_MYSELF int = -24
    /*
    * Epoch mismatch.
    */
    RATCHET_ERROR_ERROR_EPOCH_MISMATCH int = -25
    /*
    * Epoch not found.
    */
    RATCHET_ERROR_ERROR_EPOCH_NOT_FOUND int = -26
    /*
    * Session id mismatch.
    */
    RATCHET_ERROR_ERROR_SESSION_ID_MISMATCH int = -27
    /*
    * Simultaneous group user operation.
    */
    RATCHET_ERROR_ERROR_SIMULTANEOUS_GROUP_USER_OPERATION int = -28
    /*
    * Myself is included in info.
    */
    RATCHET_ERROR_ERROR_MYSELF_IS_INCLUDED_IN_INFO int = -29
)

func (obj *RatchetError) Error () string {
    return fmt.Sprintf("RatchetError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func RatchetErrorHandleStatus (status C.vscr_status_t) error {
    if status != C.vscr_status_SUCCESS {
        switch (status) {
        case C.vscr_status_ERROR_PROTOBUF_DECODE:
            return &RatchetError {int(status), "Error during protobuf deserialization."}
        case C.vscr_status_ERROR_BAD_MESSAGE_TYPE:
            return &RatchetError {int(status), "Bad message type."}
        case C.vscr_status_ERROR_AES:
            return &RatchetError {int(status), "AES error."}
        case C.vscr_status_ERROR_RNG_FAILED:
            return &RatchetError {int(status), "RNG failed."}
        case C.vscr_status_ERROR_CURVE25519:
            return &RatchetError {int(status), "Curve25519 error."}
        case C.vscr_status_ERROR_ED25519:
            return &RatchetError {int(status), "Curve25519 error."}
        case C.vscr_status_ERROR_KEY_DESERIALIZATION_FAILED:
            return &RatchetError {int(status), "Key deserialization failed."}
        case C.vscr_status_ERROR_INVALID_KEY_TYPE:
            return &RatchetError {int(status), "Invalid key type."}
        case C.vscr_status_ERROR_IDENTITY_KEY_DOESNT_MATCH:
            return &RatchetError {int(status), "Identity key doesn't match."}
        case C.vscr_status_ERROR_MESSAGE_ALREADY_DECRYPTED:
            return &RatchetError {int(status), "Message already decrypted."}
        case C.vscr_status_ERROR_TOO_MANY_LOST_MESSAGES:
            return &RatchetError {int(status), "Too many lost messages."}
        case C.vscr_status_ERROR_SENDER_CHAIN_MISSING:
            return &RatchetError {int(status), "Sender chain missing."}
        case C.vscr_status_ERROR_SKIPPED_MESSAGE_MISSING:
            return &RatchetError {int(status), "Skipped message missing."}
        case C.vscr_status_ERROR_SESSION_IS_NOT_INITIALIZED:
            return &RatchetError {int(status), "Session is not initialized."}
        case C.vscr_status_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN:
            return &RatchetError {int(status), "Exceeded max plain text len."}
        case C.vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_SENDER_CHAIN:
            return &RatchetError {int(status), "Too many messages for sender chain."}
        case C.vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN:
            return &RatchetError {int(status), "Too many messages for receiver chain."}
        case C.vscr_status_ERROR_INVALID_PADDING:
            return &RatchetError {int(status), "Invalid padding."}
        case C.vscr_status_ERROR_TOO_MANY_PARTICIPANTS:
            return &RatchetError {int(status), "Too many participants."}
        case C.vscr_status_ERROR_TOO_FEW_PARTICIPANTS:
            return &RatchetError {int(status), "Too few participants."}
        case C.vscr_status_ERROR_SENDER_NOT_FOUND:
            return &RatchetError {int(status), "Sender not found."}
        case C.vscr_status_ERROR_CANNOT_DECRYPT_OWN_MESSAGES:
            return &RatchetError {int(status), "Cannot decrypt own messages."}
        case C.vscr_status_ERROR_INVALID_SIGNATURE:
            return &RatchetError {int(status), "Invalid signature."}
        case C.vscr_status_ERROR_CANNOT_REMOVE_MYSELF:
            return &RatchetError {int(status), "Cannot remove myself."}
        case C.vscr_status_ERROR_EPOCH_MISMATCH:
            return &RatchetError {int(status), "Epoch mismatch."}
        case C.vscr_status_ERROR_EPOCH_NOT_FOUND:
            return &RatchetError {int(status), "Epoch not found."}
        case C.vscr_status_ERROR_SESSION_ID_MISMATCH:
            return &RatchetError {int(status), "Session id mismatch."}
        case C.vscr_status_ERROR_SIMULTANEOUS_GROUP_USER_OPERATION:
            return &RatchetError {int(status), "Simultaneous group user operation."}
        case C.vscr_status_ERROR_MYSELF_IS_INCLUDED_IN_INFO:
            return &RatchetError {int(status), "Myself is included in info."}
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
