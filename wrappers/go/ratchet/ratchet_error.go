package ratchet

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
    RatchetErrorErrorProtobufDecode int = -1
    /*
    * Bad message type.
    */
    RatchetErrorErrorBadMessageType int = -2
    /*
    * AES error.
    */
    RatchetErrorErrorAes int = -3
    /*
    * RNG failed.
    */
    RatchetErrorErrorRngFailed int = -4
    /*
    * Curve25519 error.
    */
    RatchetErrorErrorCurve25519 int = -5
    /*
    * Curve25519 error.
    */
    RatchetErrorErrorEd25519 int = -6
    /*
    * Key deserialization failed.
    */
    RatchetErrorErrorKeyDeserializationFailed int = -7
    /*
    * Invalid key type.
    */
    RatchetErrorErrorInvalidKeyType int = -8
    /*
    * Identity key doesn't match.
    */
    RatchetErrorErrorIdentityKeyDoesntMatch int = -9
    /*
    * Message already decrypted.
    */
    RatchetErrorErrorMessageAlreadyDecrypted int = -10
    /*
    * Too many lost messages.
    */
    RatchetErrorErrorTooManyLostMessages int = -11
    /*
    * Sender chain missing.
    */
    RatchetErrorErrorSenderChainMissing int = -12
    /*
    * Skipped message missing.
    */
    RatchetErrorErrorSkippedMessageMissing int = -13
    /*
    * Session is not initialized.
    */
    RatchetErrorErrorSessionIsNotInitialized int = -14
    /*
    * Exceeded max plain text len.
    */
    RatchetErrorErrorExceededMaxPlainTextLen int = -15
    /*
    * Too many messages for sender chain.
    */
    RatchetErrorErrorTooManyMessagesForSenderChain int = -16
    /*
    * Too many messages for receiver chain.
    */
    RatchetErrorErrorTooManyMessagesForReceiverChain int = -17
    /*
    * Invalid padding.
    */
    RatchetErrorErrorInvalidPadding int = -18
    /*
    * Too many participants.
    */
    RatchetErrorErrorTooManyParticipants int = -19
    /*
    * Too few participants.
    */
    RatchetErrorErrorTooFewParticipants int = -20
    /*
    * Sender not found.
    */
    RatchetErrorErrorSenderNotFound int = -21
    /*
    * Cannot decrypt own messages.
    */
    RatchetErrorErrorCannotDecryptOwnMessages int = -22
    /*
    * Invalid signature.
    */
    RatchetErrorErrorInvalidSignature int = -23
    /*
    * Cannot remove myself.
    */
    RatchetErrorErrorCannotRemoveMyself int = -24
    /*
    * Epoch mismatch.
    */
    RatchetErrorErrorEpochMismatch int = -25
    /*
    * Epoch not found.
    */
    RatchetErrorErrorEpochNotFound int = -26
    /*
    * Session id mismatch.
    */
    RatchetErrorErrorSessionIdMismatch int = -27
    /*
    * Simultaneous group user operation.
    */
    RatchetErrorErrorSimultaneousGroupUserOperation int = -28
    /*
    * Myself is included in info.
    */
    RatchetErrorErrorMyselfIsIncludedInInfo int = -29
    /*
    * Round5 error.
    */
    RatchetErrorErrorRound5 int = -30
    /*
    * Falcon error.
    */
    RatchetErrorErrorFalcon int = -31
    /*
    * Decaps signature is invalid.
    */
    RatchetErrorErrorDecapsSignatureInvalid int = -32
    /*
    * Error importing round5 key.
    */
    RatchetErrorErrorRound5ImportKey int = -33
)

func (obj *RatchetError) Error() string {
    return fmt.Sprintf("RatchetError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func RatchetErrorHandleStatus(status C.vscr_status_t) error {
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
        case C.vscr_status_ERROR_ROUND5:
            return &RatchetError {int(status), "Round5 error."}
        case C.vscr_status_ERROR_FALCON:
            return &RatchetError {int(status), "Falcon error."}
        case C.vscr_status_ERROR_DECAPS_SIGNATURE_INVALID:
            return &RatchetError {int(status), "Decaps signature is invalid."}
        case C.vscr_status_ERROR_ROUND5_IMPORT_KEY:
            return &RatchetError {int(status), "Error importing round5 key."}
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
