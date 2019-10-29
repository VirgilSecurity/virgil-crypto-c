package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "fmt"

/*
* Defines the library status codes.
*/
type FoundationError struct {
    Code int
    Message string
}
const (
    /*
    * This error should not be returned if assertions is enabled.
    */
    FOUNDATION_ERROR_ERROR_BAD_ARGUMENTS int = -1
    /*
    * Can be used to define that not all context prerequisites are satisfied.
    * Note, this error should not be returned if assertions is enabled.
    */
    FOUNDATION_ERROR_ERROR_UNINITIALIZED int = -2
    /*
    * Define that error code from one of third-party module was not handled.
    * Note, this error should not be returned if assertions is enabled.
    */
    FOUNDATION_ERROR_ERROR_UNHANDLED_THIRDPARTY_ERROR int = -3
    /*
    * Buffer capacity is not enough to hold result.
    */
    FOUNDATION_ERROR_ERROR_SMALL_BUFFER int = -101
    /*
    * Unsupported algorithm.
    */
    FOUNDATION_ERROR_ERROR_UNSUPPORTED_ALGORITHM int = -200
    /*
    * Authentication failed during decryption.
    */
    FOUNDATION_ERROR_ERROR_AUTH_FAILED int = -201
    /*
    * Attempt to read data out of buffer bounds.
    */
    FOUNDATION_ERROR_ERROR_OUT_OF_DATA int = -202
    /*
    * ASN.1 encoded data is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_ASN1 int = -203
    /*
    * Attempt to read ASN.1 type that is bigger then requested C type.
    */
    FOUNDATION_ERROR_ERROR_ASN1_LOSSY_TYPE_NARROWING int = -204
    /*
    * ASN.1 representation of PKCS#1 public key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_PKCS1_PUBLIC_KEY int = -205
    /*
    * ASN.1 representation of PKCS#1 private key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_PKCS1_PRIVATE_KEY int = -206
    /*
    * ASN.1 representation of PKCS#8 public key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_PKCS8_PUBLIC_KEY int = -207
    /*
    * ASN.1 representation of PKCS#8 private key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_PKCS8_PRIVATE_KEY int = -208
    /*
    * Encrypted data is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_ENCRYPTED_DATA int = -209
    /*
    * Underlying random operation returns error.
    */
    FOUNDATION_ERROR_ERROR_RANDOM_FAILED int = -210
    /*
    * Generation of the private or secret key failed.
    */
    FOUNDATION_ERROR_ERROR_KEY_GENERATION_FAILED int = -211
    /*
    * One of the entropy sources failed.
    */
    FOUNDATION_ERROR_ERROR_ENTROPY_SOURCE_FAILED int = -212
    /*
    * Requested data to be generated is too big.
    */
    FOUNDATION_ERROR_ERROR_RNG_REQUESTED_DATA_TOO_BIG int = -213
    /*
    * Base64 encoded string contains invalid characters.
    */
    FOUNDATION_ERROR_ERROR_BAD_BASE64 int = -214
    /*
    * PEM data is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_PEM int = -215
    /*
    * Exchange key return zero.
    */
    FOUNDATION_ERROR_ERROR_SHARED_KEY_EXCHANGE_FAILED int = -216
    /*
    * Ed25519 public key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_ED25519_PUBLIC_KEY int = -217
    /*
    * Ed25519 private key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_ED25519_PRIVATE_KEY int = -218
    /*
    * CURVE25519 public key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_CURVE25519_PUBLIC_KEY int = -219
    /*
    * CURVE25519 private key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_CURVE25519_PRIVATE_KEY int = -220
    /*
    * Elliptic curve public key format is corrupted see RFC 5480.
    */
    FOUNDATION_ERROR_ERROR_BAD_SEC1_PUBLIC_KEY int = -221
    /*
    * Elliptic curve public key format is corrupted see RFC 5915.
    */
    FOUNDATION_ERROR_ERROR_BAD_SEC1_PRIVATE_KEY int = -222
    /*
    * ASN.1 representation of a public key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_DER_PUBLIC_KEY int = -223
    /*
    * ASN.1 representation of a private key is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_DER_PRIVATE_KEY int = -224
    /*
    * Key algorithm does not accept given type of public key.
    */
    FOUNDATION_ERROR_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM int = -225
    /*
    * Key algorithm does not accept given type of private key.
    */
    FOUNDATION_ERROR_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM int = -226
    /*
    * Decryption failed, because message info was not given explicitly,
    * and was not part of an encrypted message.
    */
    FOUNDATION_ERROR_ERROR_NO_MESSAGE_INFO int = -301
    /*
    * Message Info is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_MESSAGE_INFO int = -302
    /*
    * Recipient defined with id is not found within message info
    * during data decryption.
    */
    FOUNDATION_ERROR_ERROR_KEY_RECIPIENT_IS_NOT_FOUND int = -303
    /*
    * Content encryption key can not be decrypted with a given private key.
    */
    FOUNDATION_ERROR_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG int = -304
    /*
    * Content encryption key can not be decrypted with a given password.
    */
    FOUNDATION_ERROR_ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG int = -305
    /*
    * Custom parameter with a given key is not found within message info.
    */
    FOUNDATION_ERROR_ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND int = -306
    /*
    * A custom parameter with a given key is found, but the requested value
    * type does not correspond to the actual type.
    */
    FOUNDATION_ERROR_ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH int = -307
    /*
    * Signature format is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_SIGNATURE int = -308
    /*
    * Message Info footer is corrupted.
    */
    FOUNDATION_ERROR_ERROR_BAD_MESSAGE_INFO_FOOTER int = -309
    /*
    * Brainkey password length is out of range.
    */
    FOUNDATION_ERROR_ERROR_INVALID_BRAINKEY_PASSWORD_LEN int = -401
    /*
    * Brainkey number length should be 32 byte.
    */
    FOUNDATION_ERROR_ERROR_INVALID_BRAINKEY_FACTOR_LEN int = -402
    /*
    * Brainkey point length should be 65 bytes.
    */
    FOUNDATION_ERROR_ERROR_INVALID_BRAINKEY_POINT_LEN int = -403
    /*
    * Brainkey name is out of range.
    */
    FOUNDATION_ERROR_ERROR_INVALID_BRAINKEY_KEY_NAME_LEN int = -404
    /*
    * Brainkey internal error.
    */
    FOUNDATION_ERROR_ERROR_BRAINKEY_INTERNAL int = -405
    /*
    * Brainkey point is invalid.
    */
    FOUNDATION_ERROR_ERROR_BRAINKEY_INVALID_POINT int = -406
    /*
    * Brainkey number buffer length capacity should be >= 32 byte.
    */
    FOUNDATION_ERROR_ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN int = -407
    /*
    * Brainkey point buffer length capacity should be >= 32 byte.
    */
    FOUNDATION_ERROR_ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN int = -408
    /*
    * Brainkey seed buffer length capacity should be >= 32 byte.
    */
    FOUNDATION_ERROR_ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN int = -409
    /*
    * Brainkey identity secret is invalid.
    */
    FOUNDATION_ERROR_ERROR_INVALID_IDENTITY_SECRET int = -410
    /*
    * Invalid padding.
    */
    FOUNDATION_ERROR_ERROR_INVALID_PADDING int = -501
    /*
    * Protobuf error.
    */
    FOUNDATION_ERROR_ERROR_PROTOBUF int = -601
    /*
    * Session id doesnt match.
    */
    FOUNDATION_ERROR_ERROR_SESSION_ID_DOESNT_MATCH int = -701
    /*
    * Epoch not found.
    */
    FOUNDATION_ERROR_ERROR_EPOCH_NOT_FOUND int = -702
    /*
    * Wrong key type.
    */
    FOUNDATION_ERROR_ERROR_WRONG_KEY_TYPE int = -703
    /*
    * Invalid signature.
    */
    FOUNDATION_ERROR_ERROR_INVALID_SIGNATURE int = -704
    /*
    * Ed25519 error.
    */
    FOUNDATION_ERROR_ERROR_ED25519 int = -705
    /*
    * Duplicate epoch.
    */
    FOUNDATION_ERROR_ERROR_DUPLICATE_EPOCH int = -706
    /*
    * Plain text too long.
    */
    FOUNDATION_ERROR_ERROR_PLAIN_TEXT_TOO_LONG int = -707
)

func (this FoundationError) Error () string {
    return fmt.Sprintf("FoundationError{code: %v message: %s}", this.Code, this.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func FoundationErrorHandleStatus (status C.vscf_status_t) error {
    if status != C.vscf_status_SUCCESS {
        switch (status) {
        case C.vscf_status_ERROR_BAD_ARGUMENTS:
            return &FoundationError {int(status), "This error should not be returned if assertions is enabled."}
        case C.vscf_status_ERROR_UNINITIALIZED:
            return &FoundationError {int(status), "Can be used to define that not all context prerequisites are satisfied. Note, this error should not be returned if assertions is enabled."}
        case C.vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR:
            return &FoundationError {int(status), "Define that error code from one of third-party module was not handled. Note, this error should not be returned if assertions is enabled."}
        case C.vscf_status_ERROR_SMALL_BUFFER:
            return &FoundationError {int(status), "Buffer capacity is not enough to hold result."}
        case C.vscf_status_ERROR_UNSUPPORTED_ALGORITHM:
            return &FoundationError {int(status), "Unsupported algorithm."}
        case C.vscf_status_ERROR_AUTH_FAILED:
            return &FoundationError {int(status), "Authentication failed during decryption."}
        case C.vscf_status_ERROR_OUT_OF_DATA:
            return &FoundationError {int(status), "Attempt to read data out of buffer bounds."}
        case C.vscf_status_ERROR_BAD_ASN1:
            return &FoundationError {int(status), "ASN.1 encoded data is corrupted."}
        case C.vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING:
            return &FoundationError {int(status), "Attempt to read ASN.1 type that is bigger then requested C type."}
        case C.vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY:
            return &FoundationError {int(status), "ASN.1 representation of PKCS#1 public key is corrupted."}
        case C.vscf_status_ERROR_BAD_PKCS1_PRIVATE_KEY:
            return &FoundationError {int(status), "ASN.1 representation of PKCS#1 private key is corrupted."}
        case C.vscf_status_ERROR_BAD_PKCS8_PUBLIC_KEY:
            return &FoundationError {int(status), "ASN.1 representation of PKCS#8 public key is corrupted."}
        case C.vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY:
            return &FoundationError {int(status), "ASN.1 representation of PKCS#8 private key is corrupted."}
        case C.vscf_status_ERROR_BAD_ENCRYPTED_DATA:
            return &FoundationError {int(status), "Encrypted data is corrupted."}
        case C.vscf_status_ERROR_RANDOM_FAILED:
            return &FoundationError {int(status), "Underlying random operation returns error."}
        case C.vscf_status_ERROR_KEY_GENERATION_FAILED:
            return &FoundationError {int(status), "Generation of the private or secret key failed."}
        case C.vscf_status_ERROR_ENTROPY_SOURCE_FAILED:
            return &FoundationError {int(status), "One of the entropy sources failed."}
        case C.vscf_status_ERROR_RNG_REQUESTED_DATA_TOO_BIG:
            return &FoundationError {int(status), "Requested data to be generated is too big."}
        case C.vscf_status_ERROR_BAD_BASE64:
            return &FoundationError {int(status), "Base64 encoded string contains invalid characters."}
        case C.vscf_status_ERROR_BAD_PEM:
            return &FoundationError {int(status), "PEM data is corrupted."}
        case C.vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED:
            return &FoundationError {int(status), "Exchange key return zero."}
        case C.vscf_status_ERROR_BAD_ED25519_PUBLIC_KEY:
            return &FoundationError {int(status), "Ed25519 public key is corrupted."}
        case C.vscf_status_ERROR_BAD_ED25519_PRIVATE_KEY:
            return &FoundationError {int(status), "Ed25519 private key is corrupted."}
        case C.vscf_status_ERROR_BAD_CURVE25519_PUBLIC_KEY:
            return &FoundationError {int(status), "CURVE25519 public key is corrupted."}
        case C.vscf_status_ERROR_BAD_CURVE25519_PRIVATE_KEY:
            return &FoundationError {int(status), "CURVE25519 private key is corrupted."}
        case C.vscf_status_ERROR_BAD_SEC1_PUBLIC_KEY:
            return &FoundationError {int(status), "Elliptic curve public key format is corrupted see RFC 5480."}
        case C.vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY:
            return &FoundationError {int(status), "Elliptic curve public key format is corrupted see RFC 5915."}
        case C.vscf_status_ERROR_BAD_DER_PUBLIC_KEY:
            return &FoundationError {int(status), "ASN.1 representation of a public key is corrupted."}
        case C.vscf_status_ERROR_BAD_DER_PRIVATE_KEY:
            return &FoundationError {int(status), "ASN.1 representation of a private key is corrupted."}
        case C.vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM:
            return &FoundationError {int(status), "Key algorithm does not accept given type of public key."}
        case C.vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM:
            return &FoundationError {int(status), "Key algorithm does not accept given type of private key."}
        case C.vscf_status_ERROR_NO_MESSAGE_INFO:
            return &FoundationError {int(status), "Decryption failed, because message info was not given explicitly, and was not part of an encrypted message."}
        case C.vscf_status_ERROR_BAD_MESSAGE_INFO:
            return &FoundationError {int(status), "Message Info is corrupted."}
        case C.vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND:
            return &FoundationError {int(status), "Recipient defined with id is not found within message info during data decryption."}
        case C.vscf_status_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG:
            return &FoundationError {int(status), "Content encryption key can not be decrypted with a given private key."}
        case C.vscf_status_ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG:
            return &FoundationError {int(status), "Content encryption key can not be decrypted with a given password."}
        case C.vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND:
            return &FoundationError {int(status), "Custom parameter with a given key is not found within message info."}
        case C.vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH:
            return &FoundationError {int(status), "A custom parameter with a given key is found, but the requested value type does not correspond to the actual type."}
        case C.vscf_status_ERROR_BAD_SIGNATURE:
            return &FoundationError {int(status), "Signature format is corrupted."}
        case C.vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER:
            return &FoundationError {int(status), "Message Info footer is corrupted."}
        case C.vscf_status_ERROR_INVALID_BRAINKEY_PASSWORD_LEN:
            return &FoundationError {int(status), "Brainkey password length is out of range."}
        case C.vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_LEN:
            return &FoundationError {int(status), "Brainkey number length should be 32 byte."}
        case C.vscf_status_ERROR_INVALID_BRAINKEY_POINT_LEN:
            return &FoundationError {int(status), "Brainkey point length should be 65 bytes."}
        case C.vscf_status_ERROR_INVALID_BRAINKEY_KEY_NAME_LEN:
            return &FoundationError {int(status), "Brainkey name is out of range."}
        case C.vscf_status_ERROR_BRAINKEY_INTERNAL:
            return &FoundationError {int(status), "Brainkey internal error."}
        case C.vscf_status_ERROR_BRAINKEY_INVALID_POINT:
            return &FoundationError {int(status), "Brainkey point is invalid."}
        case C.vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN:
            return &FoundationError {int(status), "Brainkey number buffer length capacity should be >= 32 byte."}
        case C.vscf_status_ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN:
            return &FoundationError {int(status), "Brainkey point buffer length capacity should be >= 32 byte."}
        case C.vscf_status_ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN:
            return &FoundationError {int(status), "Brainkey seed buffer length capacity should be >= 32 byte."}
        case C.vscf_status_ERROR_INVALID_IDENTITY_SECRET:
            return &FoundationError {int(status), "Brainkey identity secret is invalid."}
        case C.vscf_status_ERROR_INVALID_PADDING:
            return &FoundationError {int(status), "Invalid padding."}
        case C.vscf_status_ERROR_PROTOBUF:
            return &FoundationError {int(status), "Protobuf error."}
        case C.vscf_status_ERROR_SESSION_ID_DOESNT_MATCH:
            return &FoundationError {int(status), "Session id doesnt match."}
        case C.vscf_status_ERROR_EPOCH_NOT_FOUND:
            return &FoundationError {int(status), "Epoch not found."}
        case C.vscf_status_ERROR_WRONG_KEY_TYPE:
            return &FoundationError {int(status), "Wrong key type."}
        case C.vscf_status_ERROR_INVALID_SIGNATURE:
            return &FoundationError {int(status), "Invalid signature."}
        case C.vscf_status_ERROR_ED25519:
            return &FoundationError {int(status), "Ed25519 error."}
        case C.vscf_status_ERROR_DUPLICATE_EPOCH:
            return &FoundationError {int(status), "Duplicate epoch."}
        case C.vscf_status_ERROR_PLAIN_TEXT_TOO_LONG:
            return &FoundationError {int(status), "Plain text too long."}
        }
    }
    return nil
}
type wrapError struct {
    err error
    msg string
}

func (this wrapError) Error () string {
    return fmt.Sprintf("%s: %v", this.msg, this.err)
}

func (this wrapError) Unwrap () error {
    return this.err
}
