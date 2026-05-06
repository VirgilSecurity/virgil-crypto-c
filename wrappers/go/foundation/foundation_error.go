package foundation

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
    FoundationErrorErrorBadArguments int = -1
    /*
    * Can be used to define that not all context prerequisites are satisfied.
    * Note, this error should not be returned if assertions is enabled.
    */
    FoundationErrorErrorUninitialized int = -2
    /*
    * Define that error code from one of third-party module was not handled.
    * Note, this error should not be returned if assertions is enabled.
    */
    FoundationErrorErrorUnhandledThirdpartyError int = -3
    /*
    * Buffer capacity is not enough to hold result.
    */
    FoundationErrorErrorSmallBuffer int = -101
    /*
    * Unsupported algorithm.
    */
    FoundationErrorErrorUnsupportedAlgorithm int = -200
    /*
    * Authentication failed during decryption.
    */
    FoundationErrorErrorAuthFailed int = -201
    /*
    * Attempt to read data out of buffer bounds.
    */
    FoundationErrorErrorOutOfData int = -202
    /*
    * ASN.1 encoded data is corrupted.
    */
    FoundationErrorErrorBadAsn1 int = -203
    /*
    * Attempt to read ASN.1 type that is bigger then requested C type.
    */
    FoundationErrorErrorAsn1LossyTypeNarrowing int = -204
    /*
    * ASN.1 representation of PKCS#1 public key is corrupted.
    */
    FoundationErrorErrorBadPkcs1PublicKey int = -205
    /*
    * ASN.1 representation of PKCS#1 private key is corrupted.
    */
    FoundationErrorErrorBadPkcs1PrivateKey int = -206
    /*
    * ASN.1 representation of PKCS#8 public key is corrupted.
    */
    FoundationErrorErrorBadPkcs8PublicKey int = -207
    /*
    * ASN.1 representation of PKCS#8 private key is corrupted.
    */
    FoundationErrorErrorBadPkcs8PrivateKey int = -208
    /*
    * Encrypted data is corrupted.
    */
    FoundationErrorErrorBadEncryptedData int = -209
    /*
    * Underlying random operation returns error.
    */
    FoundationErrorErrorRandomFailed int = -210
    /*
    * Generation of the private or secret key failed.
    */
    FoundationErrorErrorKeyGenerationFailed int = -211
    /*
    * One of the entropy sources failed.
    */
    FoundationErrorErrorEntropySourceFailed int = -212
    /*
    * Requested data to be generated is too big.
    */
    FoundationErrorErrorRngRequestedDataTooBig int = -213
    /*
    * Base64 encoded string contains invalid characters.
    */
    FoundationErrorErrorBadBase64 int = -214
    /*
    * PEM data is corrupted.
    */
    FoundationErrorErrorBadPem int = -215
    /*
    * Exchange key return zero.
    */
    FoundationErrorErrorSharedKeyExchangeFailed int = -216
    /*
    * Ed25519 public key is corrupted.
    */
    FoundationErrorErrorBadEd25519PublicKey int = -217
    /*
    * Ed25519 private key is corrupted.
    */
    FoundationErrorErrorBadEd25519PrivateKey int = -218
    /*
    * CURVE25519 public key is corrupted.
    */
    FoundationErrorErrorBadCurve25519PublicKey int = -219
    /*
    * CURVE25519 private key is corrupted.
    */
    FoundationErrorErrorBadCurve25519PrivateKey int = -220
    /*
    * Elliptic curve public key format is corrupted see RFC 5480.
    */
    FoundationErrorErrorBadSec1PublicKey int = -221
    /*
    * Elliptic curve public key format is corrupted see RFC 5915.
    */
    FoundationErrorErrorBadSec1PrivateKey int = -222
    /*
    * ASN.1 representation of a public key is corrupted.
    */
    FoundationErrorErrorBadDerPublicKey int = -223
    /*
    * ASN.1 representation of a private key is corrupted.
    */
    FoundationErrorErrorBadDerPrivateKey int = -224
    /*
    * Key algorithm does not accept given type of public key.
    */
    FoundationErrorErrorMismatchPublicKeyAndAlgorithm int = -225
    /*
    * Key algorithm does not accept given type of private key.
    */
    FoundationErrorErrorMismatchPrivateKeyAndAlgorithm int = -226
    /*
    * Post-quantum Falcon-Sign public key is corrupted.
    */
    FoundationErrorErrorBadFalconPublicKey int = -227
    /*
    * Post-quantum Falcon-Sign private key is corrupted.
    */
    FoundationErrorErrorBadFalconPrivateKey int = -228
    /*
    * Generic Round5 library error.
    */
    FoundationErrorErrorRound5 int = -229
    /*
    * Post-quantum NIST Round5 public key is corrupted.
    */
    FoundationErrorErrorBadRound5PublicKey int = -230
    /*
    * Post-quantum NIST Round5 private key is corrupted.
    */
    FoundationErrorErrorBadRound5PrivateKey int = -231
    /*
    * Compound public key is corrupted.
    */
    FoundationErrorErrorBadCompoundPublicKey int = -232
    /*
    * Compound private key is corrupted.
    */
    FoundationErrorErrorBadCompoundPrivateKey int = -233
    /*
    * Compound public hybrid key is corrupted.
    */
    FoundationErrorErrorBadHybridPublicKey int = -234
    /*
    * Compound private hybrid key is corrupted.
    */
    FoundationErrorErrorBadHybridPrivateKey int = -235
    /*
    * ASN.1 AlgorithmIdentifer is corrupted.
    */
    FoundationErrorErrorBadAsn1Algorithm int = -236
    /*
    * ASN.1 AlgorithmIdentifer with ECParameters is corrupted.
    */
    FoundationErrorErrorBadAsn1AlgorithmEcc int = -237
    /*
    * ASN.1 AlgorithmIdentifer with CompoundKeyParams is corrupted.
    */
    FoundationErrorErrorBadAsn1AlgorithmCompoundKey int = -238
    /*
    * ASN.1 AlgorithmIdentifer with HybridKeyParams is corrupted.
    */
    FoundationErrorErrorBadAsn1AlgorithmHybridKey int = -239
    /*
    * Decryption failed, because message info was not given explicitly,
    * and was not part of an encrypted message.
    */
    FoundationErrorErrorNoMessageInfo int = -301
    /*
    * Message Info is corrupted.
    */
    FoundationErrorErrorBadMessageInfo int = -302
    /*
    * Recipient defined with id is not found within message info
    * during data decryption.
    */
    FoundationErrorErrorKeyRecipientIsNotFound int = -303
    /*
    * Content encryption key can not be decrypted with a given private key.
    */
    FoundationErrorErrorKeyRecipientPrivateKeyIsWrong int = -304
    /*
    * Content encryption key can not be decrypted with a given password.
    */
    FoundationErrorErrorPasswordRecipientPasswordIsWrong int = -305
    /*
    * Custom parameter with a given key is not found within message info.
    */
    FoundationErrorErrorMessageInfoCustomParamNotFound int = -306
    /*
    * A custom parameter with a given key is found, but the requested value
    * type does not correspond to the actual type.
    */
    FoundationErrorErrorMessageInfoCustomParamTypeMismatch int = -307
    /*
    * Signature format is corrupted.
    */
    FoundationErrorErrorBadSignature int = -308
    /*
    * Message Info footer is corrupted.
    */
    FoundationErrorErrorBadMessageInfoFooter int = -309
    /*
    * Brainkey password length is out of range.
    */
    FoundationErrorErrorInvalidBrainkeyPasswordLen int = -401
    /*
    * Brainkey number length should be 32 byte.
    */
    FoundationErrorErrorInvalidBrainkeyFactorLen int = -402
    /*
    * Brainkey point length should be 65 bytes.
    */
    FoundationErrorErrorInvalidBrainkeyPointLen int = -403
    /*
    * Brainkey name is out of range.
    */
    FoundationErrorErrorInvalidBrainkeyKeyNameLen int = -404
    /*
    * Brainkey internal error.
    */
    FoundationErrorErrorBrainkeyInternal int = -405
    /*
    * Brainkey point is invalid.
    */
    FoundationErrorErrorBrainkeyInvalidPoint int = -406
    /*
    * Brainkey number buffer length capacity should be >= 32 byte.
    */
    FoundationErrorErrorInvalidBrainkeyFactorBufferLen int = -407
    /*
    * Brainkey point buffer length capacity should be >= 32 byte.
    */
    FoundationErrorErrorInvalidBrainkeyPointBufferLen int = -408
    /*
    * Brainkey seed buffer length capacity should be >= 32 byte.
    */
    FoundationErrorErrorInvalidBrainkeySeedBufferLen int = -409
    /*
    * Brainkey identity secret is invalid.
    */
    FoundationErrorErrorInvalidIdentitySecret int = -410
    /*
    * KEM encapsulated key is invalid or does not correspond to the private key.
    */
    FoundationErrorErrorInvalidKemEncapsulatedKey int = -411
    /*
    * Invalid padding.
    */
    FoundationErrorErrorInvalidPadding int = -501
    /*
    * Protobuf error.
    */
    FoundationErrorErrorProtobuf int = -601
    /*
    * Session id doesnt match.
    */
    FoundationErrorErrorSessionIdDoesntMatch int = -701
    /*
    * Epoch not found.
    */
    FoundationErrorErrorEpochNotFound int = -702
    /*
    * Wrong key type.
    */
    FoundationErrorErrorWrongKeyType int = -703
    /*
    * Invalid signature.
    */
    FoundationErrorErrorInvalidSignature int = -704
    /*
    * Ed25519 error.
    */
    FoundationErrorErrorEd25519 int = -705
    /*
    * Duplicate epoch.
    */
    FoundationErrorErrorDuplicateEpoch int = -706
    /*
    * Plain text too long.
    */
    FoundationErrorErrorPlainTextTooLong int = -707
)

func (obj *FoundationError) Error() string {
    return fmt.Sprintf("FoundationError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func FoundationErrorHandleStatus(status C.vscf_status_t) error {
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
        case C.vscf_status_ERROR_BAD_FALCON_PUBLIC_KEY:
            return &FoundationError {int(status), "Post-quantum Falcon-Sign public key is corrupted."}
        case C.vscf_status_ERROR_BAD_FALCON_PRIVATE_KEY:
            return &FoundationError {int(status), "Post-quantum Falcon-Sign private key is corrupted."}
        case C.vscf_status_ERROR_ROUND5:
            return &FoundationError {int(status), "Generic Round5 library error."}
        case C.vscf_status_ERROR_BAD_ROUND5_PUBLIC_KEY:
            return &FoundationError {int(status), "Post-quantum NIST Round5 public key is corrupted."}
        case C.vscf_status_ERROR_BAD_ROUND5_PRIVATE_KEY:
            return &FoundationError {int(status), "Post-quantum NIST Round5 private key is corrupted."}
        case C.vscf_status_ERROR_BAD_COMPOUND_PUBLIC_KEY:
            return &FoundationError {int(status), "Compound public key is corrupted."}
        case C.vscf_status_ERROR_BAD_COMPOUND_PRIVATE_KEY:
            return &FoundationError {int(status), "Compound private key is corrupted."}
        case C.vscf_status_ERROR_BAD_HYBRID_PUBLIC_KEY:
            return &FoundationError {int(status), "Compound public hybrid key is corrupted."}
        case C.vscf_status_ERROR_BAD_HYBRID_PRIVATE_KEY:
            return &FoundationError {int(status), "Compound private hybrid key is corrupted."}
        case C.vscf_status_ERROR_BAD_ASN1_ALGORITHM:
            return &FoundationError {int(status), "ASN.1 AlgorithmIdentifer is corrupted."}
        case C.vscf_status_ERROR_BAD_ASN1_ALGORITHM_ECC:
            return &FoundationError {int(status), "ASN.1 AlgorithmIdentifer with ECParameters is corrupted."}
        case C.vscf_status_ERROR_BAD_ASN1_ALGORITHM_COMPOUND_KEY:
            return &FoundationError {int(status), "ASN.1 AlgorithmIdentifer with CompoundKeyParams is corrupted."}
        case C.vscf_status_ERROR_BAD_ASN1_ALGORITHM_HYBRID_KEY:
            return &FoundationError {int(status), "ASN.1 AlgorithmIdentifer with HybridKeyParams is corrupted."}
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
        case C.vscf_status_ERROR_INVALID_KEM_ENCAPSULATED_KEY:
            return &FoundationError {int(status), "KEM encapsulated key is invalid or does not correspond to the private key."}
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

func (obj *wrapError) Error() string {
    return fmt.Sprintf("%s: %v", obj.msg, obj.err)
}

func (obj *wrapError) Unwrap() error {
    return obj.err
}
